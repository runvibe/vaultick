use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::{Command as ProcessCommand, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::{
    Cli, Command, RsaSubcommand, SecretSubcommand, VAULTICK_HOME_ENV_VAR, VAULTICK_REMOTE_ENV_VAR,
    VAULTICK_WORKSPACE_ENV_VAR, read_env_var,
};
use vaultick::{Vaultick, compression};

const REMOTE_PROTOCOL_VERSION: u32 = 1;
const FILE_PLACEHOLDER_PREFIX: &str = "__vaultick_remote_file_";
const VAULTICK_REMOTE_BIN_ENV_VAR: &str = "VAULTICK_REMOTE_BIN";
const VAULTICK_REMOTE_SSH_COMMAND_ENV_VAR: &str = "VAULTICK_REMOTE_SSH_COMMAND";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RemoteTarget {
    pub(crate) ssh_destination: String,
    pub(crate) vaultick_home: Option<String>,
}

impl RemoteTarget {
    pub(crate) fn parse(input: &str) -> Result<Self, io::Error> {
        let input = input.trim();
        if input.is_empty() {
            return Err(io::Error::other("missing remote host"));
        }

        let (ssh_destination, vaultick_home) = input
            .split_once(':')
            .map_or((input, None), |(destination, home)| {
                (destination, Some(home.to_string()))
            });

        if ssh_destination.trim().is_empty() {
            return Err(io::Error::other("missing remote host"));
        }

        let vaultick_home = vaultick_home.filter(|home| !home.trim().is_empty());

        Ok(Self {
            ssh_destination: ssh_destination.to_string(),
            vaultick_home,
        })
    }
}

pub(crate) fn resolve_remote(cli_remote: Option<&str>) -> Result<Option<RemoteTarget>, io::Error> {
    if let Some(remote) = cli_remote {
        return Ok(Some(RemoteTarget::parse(remote)?));
    }

    read_env_var(VAULTICK_REMOTE_ENV_VAR)
        .map(|remote| RemoteTarget::parse(&remote))
        .transpose()
}

pub(crate) fn validate_remote_mode(cli: &Cli) -> Result<(), io::Error> {
    if cli.db.is_some() {
        return Err(io::Error::other(
            "--db cannot be combined with --remote or VAULTICK_REMOTE",
        ));
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RemoteRequest {
    pub(crate) protocol_version: u32,
    pub(crate) args: Vec<String>,
    pub(crate) vaultick_home: Option<String>,
    pub(crate) workspace: Option<String>,
    pub(crate) stdin: Vec<u8>,
    pub(crate) files: Vec<RemoteFilePayload>,
    pub(crate) secret_operation: Option<RemoteSecretOperation>,
    #[serde(skip)]
    pub(crate) local_output: Option<RemoteLocalOutput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RemoteFilePayload {
    pub(crate) placeholder: String,
    pub(crate) contents: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RemoteResponse {
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) exit_code: i32,
    pub(crate) secret_payload: Option<RemoteSecretPayload>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum RemoteSecretOperation {
    SetPreparedFile {
        key: String,
        payload: Vec<u8>,
        compression: String,
        original_size: Option<u64>,
        overwrite: bool,
    },
    GetRawFile {
        key: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RemoteLocalOutput {
    pub(crate) path: String,
    pub(crate) no_uncompress: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RemoteSecretPayload {
    pub(crate) payload: Vec<u8>,
    pub(crate) compression: String,
    pub(crate) original_size: Option<u64>,
}

pub(crate) fn prepare_remote_request(
    target: &RemoteTarget,
    cli: &Cli,
    raw_args: &[String],
    reader: &mut impl Read,
) -> Result<RemoteRequest, Box<dyn std::error::Error>> {
    validate_remote_mode(cli)?;
    let mut args = strip_remote_args(raw_args)?;
    let mut stdin = Vec::new();
    let mut files = Vec::new();
    let mut secret_operation = None;
    let mut local_output = None;

    match &cli.command {
        Command::Workspace(_) => {}
        Command::Secret(command) => match &command.command {
            SecretSubcommand::Set {
                stdin: read_stdin,
                file,
                env_file,
                key,
                overwrite,
                compress,
                compress_level,
                no_compress,
                ..
            } => {
                if *read_stdin || env_file.as_deref() == Some("-") {
                    reader.read_to_end(&mut stdin)?;
                }

                if let Some(path) = file {
                    let key = key
                        .clone()
                        .ok_or_else(|| io::Error::other("missing secret key or use --env-file"))?;
                    let file_contents = fs::read(path)?;
                    let prepared = compression::prepare_secret_payload(
                        &file_contents,
                        super::resolve_compression_mode(*compress, *compress_level, *no_compress)?,
                    )?;
                    args.clear();
                    secret_operation = Some(RemoteSecretOperation::SetPreparedFile {
                        key,
                        payload: prepared.payload,
                        compression: prepared.compression.as_str().to_string(),
                        original_size: prepared.original_size,
                        overwrite: *overwrite,
                    });
                }

                if let Some(path) = env_file
                    && path != "-"
                {
                    capture_file_option(&mut args, "--env-file", path, &mut files)?;
                }
            }
            SecretSubcommand::Get {
                key,
                output,
                no_uncompress,
                ..
            } => {
                if let Some(output) = output {
                    args.clear();
                    secret_operation = Some(RemoteSecretOperation::GetRawFile { key: key.clone() });
                    local_output = Some(RemoteLocalOutput {
                        path: output.clone(),
                        no_uncompress: *no_uncompress,
                    });
                }
            }
            SecretSubcommand::List { .. } | SecretSubcommand::Delete { .. } => {}
        },
        Command::Rsa(command) => match &command.command {
            RsaSubcommand::Add {
                cert,
                rewrap_from_key,
                ..
            } => {
                if let Some(path) = cert {
                    capture_file_option(&mut args, "--cert", &path.to_string_lossy(), &mut files)?;
                }
                if let Some(path) = rewrap_from_key {
                    capture_file_option(
                        &mut args,
                        "--rewrap-from-key",
                        &path.to_string_lossy(),
                        &mut files,
                    )?;
                }
            }
            RsaSubcommand::List | RsaSubcommand::Delete { .. } => {}
        },
        Command::Exec(_) | Command::Request(_) => {
            return Err(io::Error::other(
                "remote mode currently supports workspace, rsa, and secret commands",
            )
            .into());
        }
        Command::RemoteStdio => {
            return Err(io::Error::other("remote-stdio cannot be dispatched remotely").into());
        }
    }

    Ok(RemoteRequest {
        protocol_version: REMOTE_PROTOCOL_VERSION,
        args,
        vaultick_home: target.vaultick_home.clone(),
        workspace: read_env_var(VAULTICK_WORKSPACE_ENV_VAR),
        stdin,
        files,
        secret_operation,
        local_output,
    })
}

pub(crate) fn dispatch_remote(
    target: &RemoteTarget,
    cli: &Cli,
    raw_args: &[String],
) -> Result<i32, Box<dyn std::error::Error>> {
    let mut stdin = io::stdin().lock();
    let request = prepare_remote_request(target, cli, raw_args, &mut stdin)?;
    dispatch_remote_request(
        target,
        &request,
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    )
}

pub(crate) fn handle_remote_stdio() -> Result<i32, Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().lock().read_to_end(&mut input)?;
    let request: RemoteRequest = serde_json::from_slice(&input)?;
    let response = execute_remote_request(request);
    serde_json::to_writer(io::stdout().lock(), &response)?;
    Ok(0)
}

fn dispatch_remote_request(
    target: &RemoteTarget,
    request: &RemoteRequest,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<i32, Box<dyn std::error::Error>> {
    let ssh_command =
        read_env_var(VAULTICK_REMOTE_SSH_COMMAND_ENV_VAR).unwrap_or_else(|| "ssh".to_string());
    let remote_bin =
        read_env_var(VAULTICK_REMOTE_BIN_ENV_VAR).unwrap_or_else(|| "vaultick".to_string());
    let mut child = ProcessCommand::new(&ssh_command)
        .arg(&target.ssh_destination)
        .arg(remote_bin)
        .arg("remote-stdio")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| {
            io::Error::other(format!(
                "failed to start SSH command for {}: {err}",
                target.ssh_destination
            ))
        })?;

    {
        let mut child_stdin = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("failed to open SSH stdin"))?;
        serde_json::to_writer(&mut child_stdin, request)?;
    }

    let output = child.wait_with_output()?;
    if !output.status.success() {
        stderr.write_all(&output.stderr)?;
        return Err(io::Error::other(format!(
            "remote SSH command failed for {} with status {}",
            target.ssh_destination, output.status
        ))
        .into());
    }

    let response: RemoteResponse = serde_json::from_slice(&output.stdout).map_err(|err| {
        io::Error::other(format!(
            "remote command did not return a valid Vaultick response: {err}"
        ))
    })?;
    if let Some(secret_payload) = response.secret_payload {
        let local_output = request.local_output.as_ref().ok_or_else(|| {
            io::Error::other("remote returned a secret payload without a local output target")
        })?;
        let compression = secret_payload
            .compression
            .parse::<compression::Compression>()
            .map_err(|err| io::Error::other(err.to_string()))?;
        let payload = if local_output.no_uncompress {
            secret_payload.payload
        } else {
            compression::decompress_secret_payload(
                &secret_payload.payload,
                compression,
                secret_payload.original_size,
            )
            .map_err(|err| io::Error::other(err.to_string()))?
        };
        fs::write(&local_output.path, payload)?;
    }
    stdout.write_all(&response.stdout)?;
    stderr.write_all(&response.stderr)?;
    Ok(response.exit_code)
}

fn execute_remote_request(request: RemoteRequest) -> RemoteResponse {
    match execute_remote_request_inner(request) {
        Ok(response) => response,
        Err(err) => RemoteResponse {
            stdout: Vec::new(),
            stderr: format!("{err}\n").into_bytes(),
            exit_code: 1,
            secret_payload: None,
        },
    }
}

fn execute_remote_request_inner(
    request: RemoteRequest,
) -> Result<RemoteResponse, Box<dyn std::error::Error>> {
    if request.protocol_version != REMOTE_PROTOCOL_VERSION {
        return Err(io::Error::other(format!(
            "unsupported remote protocol version: {}",
            request.protocol_version
        ))
        .into());
    }

    if let Some(operation) = request.secret_operation.clone() {
        return execute_remote_secret_operation(request, operation);
    }

    let mut temp_files = Vec::new();
    for file in &request.files {
        temp_files.push(TempFileGuard::write(&file.placeholder, &file.contents)?);
    }

    let mut args = request.args.clone();
    for temp_file in &temp_files {
        for arg in &mut args {
            if arg.contains(&temp_file.placeholder) {
                *arg = arg.replace(&temp_file.placeholder, &temp_file.path.to_string_lossy());
            }
        }
    }

    let current_exe = std::env::current_exe()?;
    let mut child = ProcessCommand::new(current_exe);
    child.args(&args);
    child.stdin(Stdio::piped());
    child.stdout(Stdio::piped());
    child.stderr(Stdio::piped());
    child.env_remove(super::VAULTICK_REMOTE_ENV_VAR);
    if let Some(home) = request.vaultick_home {
        child.env(super::VAULTICK_HOME_ENV_VAR, home);
    }
    if let Some(workspace) = request.workspace {
        child.env(super::VAULTICK_WORKSPACE_ENV_VAR, workspace);
    }

    let mut child = child.spawn()?;
    {
        let mut child_stdin = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("failed to open remote child stdin"))?;
        child_stdin.write_all(&request.stdin)?;
    }
    let output = child.wait_with_output()?;

    Ok(RemoteResponse {
        stdout: output.stdout,
        stderr: output.stderr,
        exit_code: output.status.code().unwrap_or(1),
        secret_payload: None,
    })
}

fn execute_remote_secret_operation(
    request: RemoteRequest,
    operation: RemoteSecretOperation,
) -> Result<RemoteResponse, Box<dyn std::error::Error>> {
    let db_path = resolve_remote_db_path(request.vaultick_home.as_deref())?;
    let vaultick = Vaultick::open(db_path)?;
    let workspace_ref = request
        .workspace
        .as_deref()
        .unwrap_or(super::DEFAULT_WORKSPACE_NAME);

    match operation {
        RemoteSecretOperation::SetPreparedFile {
            key,
            payload,
            compression,
            original_size,
            overwrite,
        } => {
            let compression = compression.parse::<compression::Compression>()?;
            vaultick.set_secret_prepared_bytes(
                workspace_ref,
                &key,
                &payload,
                compression,
                original_size,
                overwrite,
            )?;
            Ok(RemoteResponse {
                stdout: Vec::new(),
                stderr: Vec::new(),
                exit_code: 0,
                secret_payload: None,
            })
        }
        RemoteSecretOperation::GetRawFile { key } => {
            let ssh_dir = super::resolve_ssh_dir()?;
            let raw = vaultick.get_secret_raw_bytes_auto(workspace_ref, &key, ssh_dir)?;
            Ok(RemoteResponse {
                stdout: Vec::new(),
                stderr: Vec::new(),
                exit_code: 0,
                secret_payload: Some(RemoteSecretPayload {
                    payload: raw.payload,
                    compression: raw.compression.as_str().to_string(),
                    original_size: raw.original_size,
                }),
            })
        }
    }
}

fn resolve_remote_db_path(vaultick_home: Option<&str>) -> Result<PathBuf, io::Error> {
    let vaultick_home = match vaultick_home {
        Some(home) => home.to_string(),
        None => read_env_var(VAULTICK_HOME_ENV_VAR).ok_or_else(|| {
            io::Error::other(
                "missing VAULTICK_HOME. Configure VAULTICK_HOME on the remote host or include :VAULTICK_HOME in --remote",
            )
        })?,
    };
    let db_directory = PathBuf::from(vaultick_home).join(super::DEFAULT_DB_DIRECTORY);
    fs::create_dir_all(&db_directory)?;
    Ok(db_directory.join(super::DEFAULT_DB_FILENAME))
}

struct TempFileGuard {
    placeholder: String,
    path: PathBuf,
}

impl TempFileGuard {
    fn write(placeholder: &str, contents: &[u8]) -> Result<Self, io::Error> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| io::Error::other(format!("system time error: {err}")))?
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("vaultick-remote-{}-{nonce}", std::process::id()));
        fs::write(&path, contents)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&path)?.permissions();
            permissions.set_mode(0o600);
            fs::set_permissions(&path, permissions)?;
        }

        Ok(Self {
            placeholder: placeholder.to_string(),
            path,
        })
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn capture_file_option(
    args: &mut [String],
    option: &str,
    path: &str,
    files: &mut Vec<RemoteFilePayload>,
) -> Result<(), io::Error> {
    let placeholder = format!("{FILE_PLACEHOLDER_PREFIX}{}__", files.len());
    replace_option_value(args, option, &placeholder)?;
    files.push(RemoteFilePayload {
        placeholder,
        contents: fs::read(path)?,
    });
    Ok(())
}

fn strip_remote_args(raw_args: &[String]) -> Result<Vec<String>, io::Error> {
    let mut stripped = Vec::with_capacity(raw_args.len());
    let mut index = 0;

    while let Some(arg) = raw_args.get(index) {
        if arg == "-r" || arg == "--remote" {
            if raw_args.get(index + 1).is_none() {
                return Err(io::Error::other(format!("{arg} requires an address")));
            }
            index += 2;
            continue;
        }

        if arg.starts_with("--remote=") || (arg.starts_with("-r") && arg.len() > 2) {
            index += 1;
            continue;
        }

        stripped.push(arg.clone());
        index += 1;
    }

    Ok(stripped)
}

fn replace_option_value(
    args: &mut [String],
    option: &str,
    replacement: &str,
) -> Result<(), io::Error> {
    let prefix = format!("{option}=");

    for index in 0..args.len() {
        if args[index] == option {
            let Some(value) = args.get_mut(index + 1) else {
                return Err(io::Error::other(format!("{option} requires a value")));
            };
            *value = replacement.to_string();
            return Ok(());
        }

        if args[index].starts_with(&prefix) {
            args[index] = format!("{option}={replacement}");
            return Ok(());
        }
    }

    Err(io::Error::other(format!(
        "missing {option} option in remote arguments"
    )))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use clap::Parser;
    use tempfile::tempdir;

    use super::*;
    use crate::commands::Cli;

    fn target() -> RemoteTarget {
        RemoteTarget::parse("assis@192.168.88.240:/mnt/hd/vaultick").unwrap()
    }

    #[test]
    fn strip_remote_args_removes_short_and_long_remote_flags() {
        assert_eq!(
            strip_remote_args(&[
                "-r".to_string(),
                "host:/vault".to_string(),
                "secret".to_string(),
                "list".to_string()
            ])
            .unwrap(),
            vec!["secret", "list"]
        );
        assert_eq!(
            strip_remote_args(&[
                "--remote=host:/vault".to_string(),
                "workspace".to_string(),
                "list".to_string()
            ])
            .unwrap(),
            vec!["workspace", "list"]
        );
    }

    #[test]
    fn prepare_remote_request_prepares_secret_file_payload_on_client() {
        let dir = tempdir().unwrap();
        let secret_file = dir.path().join("secret.bin");
        fs::write(&secret_file, b"secret-bytes".repeat(256)).unwrap();
        let raw_args = vec![
            "-r".to_string(),
            "host:/vault".to_string(),
            "secret".to_string(),
            "set".to_string(),
            "PAYLOAD".to_string(),
            "--file".to_string(),
            secret_file.to_string_lossy().to_string(),
            "--compress".to_string(),
        ];
        let cli =
            Cli::parse_from(std::iter::once("vaultick").chain(raw_args.iter().map(String::as_str)));

        let request =
            prepare_remote_request(&target(), &cli, &raw_args, &mut Cursor::new(Vec::new()))
                .unwrap();

        assert!(request.args.is_empty());
        assert!(request.files.is_empty());
        let Some(RemoteSecretOperation::SetPreparedFile {
            key,
            payload,
            compression,
            original_size,
            overwrite,
        }) = request.secret_operation
        else {
            panic!("expected prepared file operation");
        };
        assert_eq!(key, "PAYLOAD");
        assert_eq!(compression, "zstd");
        assert_eq!(
            original_size,
            Some(b"secret-bytes".repeat(256).len() as u64)
        );
        assert!(!overwrite);
        assert!(payload.len() < b"secret-bytes".repeat(256).len());
    }

    #[test]
    fn prepare_remote_request_captures_get_output_for_local_write() {
        let raw_args = vec![
            "-r".to_string(),
            "host:/vault".to_string(),
            "secret".to_string(),
            "get".to_string(),
            "PAYLOAD".to_string(),
            "--output".to_string(),
            "payload.bin".to_string(),
            "--no-uncompress".to_string(),
        ];
        let cli =
            Cli::parse_from(std::iter::once("vaultick").chain(raw_args.iter().map(String::as_str)));

        let request =
            prepare_remote_request(&target(), &cli, &raw_args, &mut Cursor::new(Vec::new()))
                .unwrap();

        assert!(request.args.is_empty());
        assert_eq!(
            request.secret_operation,
            Some(RemoteSecretOperation::GetRawFile {
                key: "PAYLOAD".to_string()
            })
        );
        let local_output = request.local_output.unwrap();
        assert_eq!(local_output.path, "payload.bin");
        assert!(local_output.no_uncompress);
    }

    #[test]
    fn prepare_remote_request_captures_env_file_payload() {
        let dir = tempdir().unwrap();
        let env_file = dir.path().join(".env");
        fs::write(&env_file, "API_KEY=abc\n").unwrap();
        let raw_args = vec![
            "--remote".to_string(),
            "host:/vault".to_string(),
            "secret".to_string(),
            "set".to_string(),
            "--env-file".to_string(),
            env_file.to_string_lossy().to_string(),
        ];
        let cli =
            Cli::parse_from(std::iter::once("vaultick").chain(raw_args.iter().map(String::as_str)));

        let request =
            prepare_remote_request(&target(), &cli, &raw_args, &mut Cursor::new(Vec::new()))
                .unwrap();

        assert_eq!(
            request.args,
            vec!["secret", "set", "--env-file", "__vaultick_remote_file_0__"]
        );
        assert_eq!(request.files[0].contents, b"API_KEY=abc\n");
    }

    #[test]
    fn prepare_remote_request_forwards_stdin_when_needed() {
        let raw_args = vec![
            "-r".to_string(),
            "host:/vault".to_string(),
            "secret".to_string(),
            "set".to_string(),
            "TOKEN".to_string(),
            "--stdin".to_string(),
        ];
        let cli =
            Cli::parse_from(std::iter::once("vaultick").chain(raw_args.iter().map(String::as_str)));

        let request = prepare_remote_request(
            &target(),
            &cli,
            &raw_args,
            &mut Cursor::new(b"from-stdin".to_vec()),
        )
        .unwrap();

        assert_eq!(request.args, vec!["secret", "set", "TOKEN", "--stdin"]);
        assert_eq!(request.stdin, b"from-stdin");
    }

    #[test]
    fn prepare_remote_request_rejects_exec_and_request_commands() {
        let exec_args = vec![
            "-r".to_string(),
            "host:/vault".to_string(),
            "exec".to_string(),
            "--".to_string(),
            "env".to_string(),
        ];
        let cli = Cli::parse_from(
            std::iter::once("vaultick").chain(exec_args.iter().map(String::as_str)),
        );

        let err = prepare_remote_request(&target(), &cli, &exec_args, &mut Cursor::new(Vec::new()))
            .unwrap_err();

        assert!(err.to_string().contains("workspace, rsa, and secret"));
    }
}
