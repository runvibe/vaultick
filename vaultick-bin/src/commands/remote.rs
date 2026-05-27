use std::fs;
use std::io::{self, Read};

use serde::{Deserialize, Serialize};

use super::{
    Cli, Command, RsaSubcommand, SecretSubcommand, VAULTICK_REMOTE_ENV_VAR,
    VAULTICK_WORKSPACE_ENV_VAR, read_env_var,
};

const REMOTE_PROTOCOL_VERSION: u32 = 1;
const FILE_PLACEHOLDER_PREFIX: &str = "__vaultick_remote_file_";

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

        let (ssh_destination, vaultick_home) =
            input
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

    match &cli.command {
        Command::Workspace(_) => {}
        Command::Secret(command) => match &command.command {
            SecretSubcommand::Set {
                stdin: read_stdin,
                file,
                env_file,
                ..
            } => {
                if *read_stdin {
                    reader.read_to_end(&mut stdin)?;
                } else if env_file.as_deref() == Some("-") {
                    reader.read_to_end(&mut stdin)?;
                }

                if let Some(path) = file {
                    capture_file_option(&mut args, "--file", path, &mut files)?;
                }

                if let Some(path) = env_file
                    && path != "-"
                {
                    capture_file_option(&mut args, "--env-file", path, &mut files)?;
                }
            }
            SecretSubcommand::Get { .. }
            | SecretSubcommand::List { .. }
            | SecretSubcommand::Delete { .. } => {}
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
    })
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

fn replace_option_value(args: &mut [String], option: &str, replacement: &str) -> Result<(), io::Error> {
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

    Err(io::Error::other(format!("missing {option} option in remote arguments")))
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
    fn prepare_remote_request_captures_secret_file_payload() {
        let dir = tempdir().unwrap();
        let secret_file = dir.path().join("secret.bin");
        fs::write(&secret_file, b"secret-bytes").unwrap();
        let raw_args = vec![
            "-r".to_string(),
            "host:/vault".to_string(),
            "secret".to_string(),
            "set".to_string(),
            "PAYLOAD".to_string(),
            "--file".to_string(),
            secret_file.to_string_lossy().to_string(),
        ];
        let cli = Cli::parse_from(std::iter::once("vaultick").chain(raw_args.iter().map(String::as_str)));

        let request = prepare_remote_request(&target(), &cli, &raw_args, &mut Cursor::new(Vec::new())).unwrap();

        assert_eq!(request.args, vec!["secret", "set", "PAYLOAD", "--file", "__vaultick_remote_file_0__"]);
        assert_eq!(request.files[0].contents, b"secret-bytes");
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
        let cli = Cli::parse_from(std::iter::once("vaultick").chain(raw_args.iter().map(String::as_str)));

        let request = prepare_remote_request(&target(), &cli, &raw_args, &mut Cursor::new(Vec::new())).unwrap();

        assert_eq!(request.args, vec!["secret", "set", "--env-file", "__vaultick_remote_file_0__"]);
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
        let cli = Cli::parse_from(std::iter::once("vaultick").chain(raw_args.iter().map(String::as_str)));

        let request = prepare_remote_request(&target(), &cli, &raw_args, &mut Cursor::new(b"from-stdin".to_vec())).unwrap();

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
        let cli = Cli::parse_from(std::iter::once("vaultick").chain(exec_args.iter().map(String::as_str)));

        let err = prepare_remote_request(&target(), &cli, &exec_args, &mut Cursor::new(Vec::new())).unwrap_err();

        assert!(err.to_string().contains("workspace, rsa, and secret"));
    }
}
