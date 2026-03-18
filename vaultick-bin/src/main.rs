use std::collections::HashMap;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};
use std::thread;

use clap::{Args, Parser, Subcommand};
use dialoguer::{Select, theme::ColorfulTheme};
use rsa::BigUint;
use rsa::pkcs8::{EncodePublicKey, LineEnding};
use serde::Deserialize;
use serde_json::json;
use ssh_key::{HashAlg, PrivateKey as SshPrivateKey, PublicKey as SshPublicKey};
use vaultick::{Result as VaultickResult, RsaCertificate, SecretMetadata, Vaultick, Workspace};
use vaultick_request::{
    RequestBody, RequestSpec, RequestTemplateIndex, ResolvedRequest, execute_blocking,
    parse_request_headers, replace_secret_placeholders, stream_redacted_output,
};

const DEFAULT_WORKSPACE_NAME: &str = "default";
const DEFAULT_DB_DIRECTORY: &str = "databases";
const DEFAULT_DB_FILENAME: &str = "database.db";
#[cfg(test)]
const DEFAULT_SSH_PRIVATE_KEY_NAME: &str = "id_rsa";
const VAULTICK_HOME_ENV_VAR: &str = "VAULTICK_HOME";
const VAULTICK_WORKSPACE_ENV_VAR: &str = "VAULTICK_WORKSPACE";

#[derive(Debug, Clone)]
struct AutoRsaCandidate {
    label: String,
    public_path: PathBuf,
    private_path: PathBuf,
    public_key_pem: String,
    fingerprint: String,
}

#[derive(Parser, Debug)]
#[command(name = "vaultick")]
#[command(about = "Secure secret storage backed by SQLite and RSA certificates")]
struct Cli {
    #[arg(long, value_name = "PATH")]
    db: Option<PathBuf>,
    #[arg(long, value_name = "WORKSPACE")]
    workspace: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    #[command(about = "Manage workspaces for grouping secrets and certificates")]
    Workspace(WorkspaceCommand),
    #[command(about = "Manage RSA certificates used to wrap secrets")]
    Rsa(RsaCommand),
    #[command(about = "Store, read, list, and delete secrets")]
    Secret(SecretCommand),
    #[command(about = "Run a process with secrets injected as environment variables")]
    Exec(ExecCommand),
    #[command(about = "Send HTTP requests with vault-backed secret interpolation")]
    Request(RequestCommand),
}

#[derive(Subcommand, Debug)]
enum WorkspaceSubcommand {
    #[command(about = "Create a new workspace")]
    Create { name: String },
    #[command(about = "List all workspaces")]
    List,
    #[command(about = "Show details for a workspace")]
    Get { workspace_ref: String },
    #[command(about = "Delete a workspace")]
    Delete { workspace_ref: String },
}

#[derive(Args, Debug)]
#[command(about = "Manage workspaces for grouping secrets and certificates")]
struct WorkspaceCommand {
    #[command(subcommand)]
    command: WorkspaceSubcommand,
}

#[derive(Subcommand, Debug)]
enum RsaSubcommand {
    #[command(about = "Add an RSA certificate to the active workspace")]
    Add {
        #[arg(long)]
        label: Option<String>,
        #[arg(long, value_name = "PEM_PATH")]
        cert: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        auto: bool,
        #[arg(long = "rewrap-from-key", value_name = "PEM_PATH")]
        rewrap_from_key: Option<PathBuf>,
    },
    #[command(about = "List RSA certificates in the active workspace")]
    List,
    #[command(about = "Delete an RSA certificate from the active workspace")]
    Delete {
        cert_ref: String,
    },
}

#[derive(Args, Debug)]
#[command(about = "Manage RSA certificates used to wrap secrets")]
struct RsaCommand {
    #[command(subcommand)]
    command: RsaSubcommand,
}

#[derive(Subcommand, Debug)]
enum SecretSubcommand {
    #[command(about = "Create or update a secret")]
    Set {
        key: Option<String>,
        value: Option<String>,
        #[arg(long, default_value_t = false)]
        stdin: bool,
        #[arg(long = "file", value_name = "PATH")]
        file: Option<String>,
        #[arg(short = 'o', long = "overwrite", default_value_t = false)]
        overwrite: bool,
        #[arg(long = "skip-existing", default_value_t = false)]
        skip_existing: bool,
        #[arg(long = "env-file", value_name = "PATH")]
        env_file: Option<String>,
    },
    #[command(about = "Read a secret value")]
    Get {
        key: String,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    #[command(about = "List secrets in the active workspace")]
    List {
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    #[command(about = "Delete a secret")]
    Delete {
        key: String,
    },
}

#[derive(Args, Debug)]
#[command(about = "Store, read, list, and delete secrets")]
struct SecretCommand {
    #[command(subcommand)]
    command: SecretSubcommand,
}

#[derive(Args, Debug)]
#[command(about = "Run a process with secrets injected as environment variables")]
struct ExecCommand {
    #[arg(long = "private-key", value_name = "PEM_PATH")]
    private_key: Option<PathBuf>,
    #[arg(long = "env", value_name = "KEY", conflicts_with = "all")]
    env: Vec<String>,
    #[arg(long = "all", default_value_t = false, conflicts_with = "env")]
    all: bool,
    #[arg(
        required = true,
        num_args = 1..,
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    argv: Vec<String>,
}

#[derive(Args, Debug)]
#[command(about = "Send HTTP requests with vault-backed secret interpolation")]
struct RequestCommand {
    #[arg(long = "private-key", value_name = "PEM_PATH")]
    private_key: Option<PathBuf>,
    #[arg(long, value_name = "URL")]
    url: Option<String>,
    #[arg(long, value_name = "METHOD")]
    method: Option<String>,
    #[arg(long = "header", value_name = "NAME: VALUE")]
    header: Vec<String>,
    #[arg(long, value_name = "TEXT")]
    body: Option<String>,
    #[arg(long, value_name = "JSON")]
    data: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedSecretSetInput {
    value: Vec<u8>,
    print_output: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ResolvedSecretSetRequest {
    Single {
        key: String,
        input: ResolvedSecretSetInput,
    },
    EnvFile {
        entries: Vec<(String, String)>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedRequestInvocation {
    request: ResolvedRequest,
    redacted_values: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RequestDataInput {
    url: String,
    method: Option<String>,
    headers: Option<HashMap<String, String>>,
    body: Option<String>,
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<i32, Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let db_path = resolve_db_path(cli.db)?;
    let vaultick = Vaultick::open(&db_path)?;

    match cli.command {
        Command::Workspace(command) => handle_workspace(&vaultick, command.command)?,
        Command::Rsa(command) => {
            let workspace_ref = resolve_workspace_ref(&vaultick, cli.workspace.as_deref())?;
            handle_rsa(&vaultick, &workspace_ref, command.command)?;
        }
        Command::Secret(command) => {
            let workspace_ref = resolve_workspace_ref(&vaultick, cli.workspace.as_deref())?;
            handle_secret(&vaultick, &workspace_ref, command.command)?;
        }
        Command::Exec(command) => {
            let workspace_ref = resolve_workspace_ref(&vaultick, cli.workspace.as_deref())?;
            return handle_exec(&vaultick, &workspace_ref, command);
        }
        Command::Request(command) => {
            let workspace_ref = resolve_workspace_ref(&vaultick, cli.workspace.as_deref())?;
            return handle_request(&vaultick, &workspace_ref, command);
        }
    }

    Ok(0)
}

fn resolve_db_path(cli_db: Option<PathBuf>) -> Result<PathBuf, io::Error> {
    if let Some(path) = cli_db {
        return Ok(path);
    }

    let vaultick_home = read_env_var(VAULTICK_HOME_ENV_VAR).ok_or_else(|| {
        io::Error::other(
            "missing VAULTICK_HOME. Configure something like VAULTICK_HOME=\"$HOME/.vaultick\" or pass --db <path>",
        )
    })?;

    let home_path = PathBuf::from(vaultick_home);
    let db_directory = home_path.join(DEFAULT_DB_DIRECTORY);
    fs::create_dir_all(&db_directory)?;
    Ok(db_directory.join(DEFAULT_DB_FILENAME))
}

fn handle_workspace(
    vaultick: &Vaultick,
    command: WorkspaceSubcommand,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        WorkspaceSubcommand::Create { name } => {
            let workspace = vaultick.create_workspace(&name)?;
            print_workspace(&workspace);
        }
        WorkspaceSubcommand::List => {
            let workspaces = vaultick.list_workspaces()?;
            for workspace in workspaces {
                print_workspace(&workspace);
            }
        }
        WorkspaceSubcommand::Get { workspace_ref } => {
            let workspace = vaultick.get_workspace(&workspace_ref)?;
            print_workspace(&workspace);
        }
        WorkspaceSubcommand::Delete { workspace_ref } => {
            vaultick.delete_workspace(&workspace_ref)?;
            println!("deleted workspace {workspace_ref}");
        }
    }

    Ok(())
}

fn handle_rsa(
    vaultick: &Vaultick,
    workspace_ref: &str,
    command: RsaSubcommand,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        RsaSubcommand::Add {
            label,
            cert,
            auto,
            rewrap_from_key,
        } => {
            let add_input = resolve_rsa_add_input(label, cert, auto)?;
            let rewrap_pem = rewrap_from_key.map(fs::read_to_string).transpose()?;
            let certificate = vaultick.add_certificate(
                workspace_ref,
                &add_input.label,
                &add_input.public_key_pem,
                rewrap_pem.as_deref(),
            )?;
            print_certificate(&certificate);
        }
        RsaSubcommand::List => {
            let certificates = vaultick.list_certificates(workspace_ref)?;
            for certificate in certificates {
                print_certificate(&certificate);
            }
        }
        RsaSubcommand::Delete { cert_ref } => {
            vaultick.delete_certificate(workspace_ref, &cert_ref)?;
            println!("deleted certificate {cert_ref}");
        }
    }

    Ok(())
}

fn handle_secret(
    vaultick: &Vaultick,
    workspace_ref: &str,
    command: SecretSubcommand,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        SecretSubcommand::Set {
            key,
            value,
            stdin,
            file,
            overwrite,
            skip_existing,
            env_file,
        } => {
            let mut stdin_reader = io::stdin().lock();
            let request = resolve_secret_set_request(
                key,
                value,
                stdin,
                file.as_deref(),
                env_file.as_deref(),
                &mut stdin_reader,
            )?;
            match request {
                ResolvedSecretSetRequest::Single { key, input } => {
                    if skip_existing {
                        return Err(io::Error::other(
                            "--skip-existing can only be used with --env-file",
                        )
                        .into());
                    }
                    let secret =
                        vaultick.set_secret_bytes(workspace_ref, &key, &input.value, overwrite)?;
                    if input.print_output {
                        print_secret_metadata(&secret);
                    }
                }
                ResolvedSecretSetRequest::EnvFile { entries } => {
                    if overwrite && skip_existing {
                        return Err(io::Error::other(
                            "--overwrite and --skip-existing cannot be used together",
                        )
                        .into());
                    }

                    let existing_keys = vaultick
                        .list_secrets(workspace_ref)?
                        .into_iter()
                        .map(|secret| secret.key)
                        .collect::<std::collections::HashSet<_>>();

                    if !overwrite
                        && !skip_existing
                        && let Some((existing_key, _)) =
                            entries.iter().find(|(key, _)| existing_keys.contains(key))
                    {
                        return Err(io::Error::other(format!(
                            "secret already exists in workspace: {existing_key}; use --overwrite to update it"
                        ))
                        .into());
                    }

                    for (key, value) in entries {
                        if skip_existing && existing_keys.contains(&key) {
                            println!("skipped existing secret {key}");
                            continue;
                        }
                        let secret = vaultick.set_secret(workspace_ref, &key, &value, overwrite)?;
                        print_secret_metadata(&secret);
                    }
                }
            }
        }
        SecretSubcommand::Get { key, json } => {
            let secret = vaultick.get_secret_metadata(workspace_ref, &key)?;
            if json {
                print_secret_metadata_json(&secret)?;
            } else {
                print_secret_metadata(&secret);
            }
        }
        SecretSubcommand::List { json } => {
            let secrets = vaultick.list_secrets(workspace_ref)?;
            if json {
                print_secret_metadata_list_json(&secrets)?;
            } else {
                for secret in secrets {
                    print_secret_metadata(&secret);
                }
            }
        }
        SecretSubcommand::Delete { key } => {
            vaultick.delete_secret(workspace_ref, &key)?;
            println!("deleted secret {key}");
        }
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedExecInvocation {
    program: String,
    args: Vec<String>,
    env_vars: Vec<(String, String)>,
    redacted_values: Vec<String>,
}

fn handle_exec(
    vaultick: &Vaultick,
    workspace_ref: &str,
    command: ExecCommand,
) -> Result<i32, Box<dyn std::error::Error>> {
    let invocation = resolve_exec_invocation(
        vaultick,
        workspace_ref,
        &command.env,
        command.all,
        &command.argv,
        command.private_key.as_deref(),
    )?;

    let mut child = ProcessCommand::new(&invocation.program);
    child.args(&invocation.args);
    child.envs(invocation.env_vars.iter().map(|(key, value)| (key, value)));
    child.stdout(Stdio::piped());
    child.stderr(Stdio::piped());

    let mut child = child.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("failed to capture child stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("failed to capture child stderr"))?;

    let stdout_redactions = invocation.redacted_values.clone();
    let stderr_redactions = invocation.redacted_values.clone();

    let stdout_handle = thread::spawn(move || -> io::Result<()> {
        let mut writer = io::stdout().lock();
        stream_redacted_output(stdout, &mut writer, &stdout_redactions)
    });
    let stderr_handle = thread::spawn(move || -> io::Result<()> {
        let mut writer = io::stderr().lock();
        stream_redacted_output(stderr, &mut writer, &stderr_redactions)
    });

    let status = child.wait()?;
    stdout_handle
        .join()
        .map_err(|_| io::Error::other("failed to join child stdout reader"))??;
    stderr_handle
        .join()
        .map_err(|_| io::Error::other("failed to join child stderr reader"))??;
    Ok(status.code().unwrap_or(1))
}

fn handle_request(
    vaultick: &Vaultick,
    workspace_ref: &str,
    command: RequestCommand,
) -> Result<i32, Box<dyn std::error::Error>> {
    let invocation = resolve_request_invocation(vaultick, workspace_ref, &command)?;
    let response = execute_blocking(&invocation.request)?;
    let is_success = response.status().is_success();
    let mut writer = io::stdout().lock();
    response.copy_redacted_to_writer(&mut writer, &invocation.redacted_values)?;

    Ok(if is_success { 0 } else { 1 })
}

fn resolve_secret_set_input(
    value: Option<String>,
    stdin: bool,
    reader: &mut impl Read,
) -> Result<ResolvedSecretSetInput, io::Error> {
    match (value, stdin) {
        (Some(_), true) => Err(io::Error::other(
            "value and --stdin cannot be used together",
        )),
        (Some(value), false) => Ok(ResolvedSecretSetInput {
            value: value.into_bytes(),
            print_output: false,
        }),
        (None, false) => Err(io::Error::other("missing secret value or use --stdin")),
        (None, true) => {
            let mut value = Vec::new();
            reader.read_to_end(&mut value)?;
            Ok(ResolvedSecretSetInput {
                value,
                print_output: true,
            })
        }
    }
}

fn resolve_secret_set_request(
    key: Option<String>,
    value: Option<String>,
    stdin: bool,
    file: Option<&str>,
    env_file: Option<&str>,
    reader: &mut impl Read,
) -> Result<ResolvedSecretSetRequest, Box<dyn std::error::Error>> {
    if let Some(env_file) = env_file {
        if key.is_some() || value.is_some() || stdin || file.is_some() {
            return Err(io::Error::other(
                "--env-file cannot be combined with key, value, --stdin, or --file",
            )
            .into());
        }

        let contents = read_env_file_source(env_file, reader)?;
        let entries = parse_env_file(&contents)?;
        return Ok(ResolvedSecretSetRequest::EnvFile { entries });
    }

    let key = key.ok_or_else(|| io::Error::other("missing secret key or use --env-file"))?;
    let key = normalize_secret_key(&key)?;
    if let Some(file) = file {
        if value.is_some() || stdin {
            return Err(io::Error::other("--file cannot be combined with value or --stdin").into());
        }

        let value = fs::read(file)?;
        return Ok(ResolvedSecretSetRequest::Single {
            key,
            input: ResolvedSecretSetInput {
                value,
                print_output: false,
            },
        });
    }

    let input = resolve_secret_set_input(value, stdin, reader)?;
    Ok(ResolvedSecretSetRequest::Single { key, input })
}

fn read_env_file_source(path: &str, reader: &mut impl Read) -> Result<String, io::Error> {
    if path == "-" {
        let mut contents = String::new();
        reader.read_to_string(&mut contents)?;
        return Ok(contents);
    }

    fs::read_to_string(path)
}

fn parse_env_file(input: &str) -> Result<Vec<(String, String)>, io::Error> {
    let mut entries = Vec::<(String, String)>::new();
    let mut index_by_key = HashMap::<String, usize>::new();

    for (line_number, raw_line) in input.lines().enumerate() {
        let line_number = line_number + 1;
        let line = raw_line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let line = line.strip_prefix("export ").unwrap_or(line).trim();
        let (raw_key, raw_value) = line.split_once('=').ok_or_else(|| {
            io::Error::other(format!(
                "invalid env file entry at line {line_number}: expected KEY=VALUE"
            ))
        })?;

        let key = normalize_secret_key(raw_key.trim())?;
        if key.is_empty() {
            return Err(io::Error::other(format!(
                "invalid env file entry at line {line_number}: missing key"
            )));
        }

        if !is_valid_env_var_name(&key) {
            return Err(io::Error::other(format!(
                "invalid env file entry at line {line_number}: invalid key {key}"
            )));
        }

        let value = parse_env_value(raw_value.trim());
        if let Some(index) = index_by_key.get(&key).copied() {
            entries[index].1 = value;
        } else {
            index_by_key.insert(key.clone(), entries.len());
            entries.push((key, value));
        }
    }

    Ok(entries)
}

fn parse_env_value(value: &str) -> String {
    if value.len() >= 2 {
        let first = value.as_bytes()[0];
        let last = value.as_bytes()[value.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return value[1..value.len() - 1].to_string();
        }
    }

    value.to_string()
}

fn normalize_secret_key(key: &str) -> Result<String, io::Error> {
    let normalized = key.trim().to_ascii_uppercase();
    if normalized.is_empty() {
        return Err(io::Error::other("secret key cannot be empty"));
    }

    Ok(normalized)
}

fn resolve_and_get_secret(
    vaultick: &Vaultick,
    workspace_ref: &str,
    key: &str,
    private_key: Option<&Path>,
) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(private_key_path) = private_key {
        let private_key_pem = fs::read_to_string(private_key_path)?;
        return Ok(vaultick.get_secret(workspace_ref, key, &private_key_pem)?);
    }

    let ssh_dir = resolve_ssh_dir().map_err(|_| {
        io::Error::other("no private key candidate was found automatically; define --private-key")
    })?;
    Ok(vaultick.get_secret_auto(workspace_ref, key, &ssh_dir)?)
}

fn resolve_request_invocation(
    vaultick: &Vaultick,
    workspace_ref: &str,
    command: &RequestCommand,
) -> Result<ResolvedRequestInvocation, Box<dyn std::error::Error>> {
    if command.data.is_some()
        && (command.url.is_some()
            || command.method.is_some()
            || !command.header.is_empty()
            || command.body.is_some())
    {
        return Err(io::Error::other(
            "--data cannot be combined with --url, --method, --header, or --body",
        )
        .into());
    }

    let parsed = if let Some(data) = command.data.as_deref() {
        let input: RequestDataInput = serde_json::from_str(data)?;
        ParsedRequestInput {
            url: input.url,
            method: input.method,
            headers: input
                .headers
                .unwrap_or_default()
                .into_iter()
                .collect::<Vec<_>>(),
            body: input.body,
        }
    } else {
        ParsedRequestInput {
            url: command
                .url
                .clone()
                .ok_or_else(|| io::Error::other("missing --url or --data"))?,
            method: command.method.clone(),
            headers: parse_request_headers(&command.header)?,
            body: command.body.clone(),
        }
    };

    let mut resolver =
        ExecTemplateResolver::new(vaultick, workspace_ref, command.private_key.as_deref())?;
    let request = ResolvedRequest::from_spec(
        &RequestSpec {
            url: parsed.url,
            method: parsed.method,
            headers: parsed.headers,
            body: parsed.body.map(RequestBody::Text),
            timeout: None,
        },
        |secret_key| resolver.resolve_secret_value_by_placeholder(secret_key),
    )?;

    Ok(ResolvedRequestInvocation {
        request,
        redacted_values: resolver.into_redacted_values(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedRequestInput {
    url: String,
    method: Option<String>,
    headers: Vec<(String, String)>,
    body: Option<String>,
}

fn resolve_exec_invocation(
    vaultick: &Vaultick,
    workspace_ref: &str,
    env_names: &[String],
    all: bool,
    argv: &[String],
    private_key: Option<&Path>,
) -> Result<ResolvedExecInvocation, Box<dyn std::error::Error>> {
    let mut resolver = ExecTemplateResolver::new(vaultick, workspace_ref, private_key)?;
    let mut env_vars = resolve_exec_env_vars(&mut resolver, env_names, all)?;
    let mut command_start = 0;

    while let Some(token) = argv.get(command_start) {
        let Some((name, raw_value)) = token.split_once('=') else {
            break;
        };

        if !is_valid_env_var_name(name) {
            break;
        }

        let template = if raw_value.is_empty() {
            format!("${name}")
        } else {
            raw_value.to_string()
        };
        let value = resolver.resolve_template(&template)?;
        upsert_env_var(&mut env_vars, name.to_string(), value);
        command_start += 1;
    }

    let Some(program_token) = argv.get(command_start) else {
        return Err(
            io::Error::other("missing command to execute after environment assignments").into(),
        );
    };

    let program = program_token.clone();
    let args = argv[command_start + 1..].to_vec();

    Ok(ResolvedExecInvocation {
        program,
        args,
        env_vars,
        redacted_values: resolver.into_redacted_values(),
    })
}

#[cfg(test)]
fn resolve_exec_template(
    vaultick: &Vaultick,
    workspace_ref: &str,
    input: &str,
    private_key: Option<&Path>,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut resolver = ExecTemplateResolver::new(vaultick, workspace_ref, private_key)?;
    resolver.resolve_template(input)
}

fn resolve_exec_env_vars(
    resolver: &mut ExecTemplateResolver<'_>,
    env_names: &[String],
    all: bool,
) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    let mut env_vars = Vec::new();

    if all {
        for secret_key in resolver.list_secret_keys() {
            let value = resolver.resolve_secret_value(&secret_key)?;
            upsert_env_var(&mut env_vars, secret_key, value);
        }
    } else {
        for env_name in env_names {
            let normalized_env_name = normalize_secret_key(env_name)?;
            if !is_valid_env_var_name(&normalized_env_name) {
                return Err(io::Error::other(format!(
                    "invalid environment variable name: {env_name}"
                ))
                .into());
            }

            let value = resolver.resolve_template(&format!("${normalized_env_name}"))?;
            upsert_env_var(&mut env_vars, normalized_env_name, value);
        }
    }

    Ok(env_vars)
}

fn upsert_env_var(env_vars: &mut Vec<(String, String)>, name: String, value: String) {
    if let Some((_, existing_value)) = env_vars.iter_mut().find(|(key, _)| *key == name) {
        *existing_value = value;
    } else {
        env_vars.push((name, value));
    }
}

struct ExecTemplateResolver<'a> {
    vaultick: &'a Vaultick,
    workspace_ref: &'a str,
    private_key: Option<&'a Path>,
    secret_key_index: RequestTemplateIndex,
    secret_cache: HashMap<String, String>,
    redacted_values: Vec<String>,
}

impl<'a> ExecTemplateResolver<'a> {
    fn new(
        vaultick: &'a Vaultick,
        workspace_ref: &'a str,
        private_key: Option<&'a Path>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            vaultick,
            workspace_ref,
            private_key,
            secret_key_index: RequestTemplateIndex::new(
                vaultick
                    .list_secrets(workspace_ref)?
                    .into_iter()
                    .map(|secret| secret.key),
            )?,
            secret_cache: HashMap::new(),
            redacted_values: Vec::new(),
        })
    }

    fn list_secret_keys(&self) -> Vec<String> {
        self.secret_key_index.keys()
    }

    fn resolve_template(&mut self, input: &str) -> Result<String, Box<dyn std::error::Error>> {
        replace_secret_placeholders(input, |secret_key| {
            self.resolve_secret_value_by_placeholder(secret_key)
        })
    }

    fn resolve_secret_value_by_placeholder(
        &mut self,
        secret_key: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let resolved_key = self
            .secret_key_index
            .canonical_key(secret_key)
            .map(ToString::to_string)
            .ok_or_else(|| io::Error::other(format!("secret not found: {secret_key}")))?;

        self.resolve_secret_value(&resolved_key)
    }

    fn resolve_secret_value(
        &mut self,
        secret_key: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        if let Some(value) = self.secret_cache.get(secret_key) {
            return Ok(value.clone());
        }

        let value = resolve_and_get_secret(
            self.vaultick,
            self.workspace_ref,
            secret_key,
            self.private_key,
        )?;
        if !value.is_empty() && !self.redacted_values.iter().any(|item| item == &value) {
            self.redacted_values.push(value.clone());
        }
        self.secret_cache
            .insert(secret_key.to_string(), value.clone());
        Ok(value)
    }

    fn into_redacted_values(self) -> Vec<String> {
        self.redacted_values
    }
}

#[cfg(test)]
fn redact_output(output: &str, redacted_values: &[String]) -> String {
    let mut redactor = vaultick_request::Redactor::new(redacted_values);
    let mut bytes = Vec::new();
    bytes.extend(redactor.redact_chunk(output.as_bytes()));
    bytes.extend(redactor.finish());
    String::from_utf8_lossy(&bytes).into_owned()
}

fn is_valid_env_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(ch) if ch == '_' || ch.is_ascii_alphabetic() => {}
        _ => return false,
    }

    chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

#[derive(Debug)]
struct ResolvedRsaAddInput {
    label: String,
    public_key_pem: String,
}

fn resolve_rsa_add_input(
    label: Option<String>,
    cert: Option<PathBuf>,
    auto: bool,
) -> Result<ResolvedRsaAddInput, Box<dyn std::error::Error>> {
    if auto {
        if label.is_some() || cert.is_some() {
            return Err(
                io::Error::other("--auto cannot be combined with --label or --cert").into(),
            );
        }

        let candidate = select_auto_rsa_candidate()?;
        return Ok(ResolvedRsaAddInput {
            label: candidate.label,
            public_key_pem: candidate.public_key_pem,
        });
    }

    let label = label.ok_or_else(|| io::Error::other("missing --label or use --auto"))?;
    let cert = cert.ok_or_else(|| io::Error::other("missing --cert or use --auto"))?;
    let public_key_pem = load_public_material_from_file(&cert)?;

    Ok(ResolvedRsaAddInput {
        label,
        public_key_pem,
    })
}

fn select_auto_rsa_candidate() -> Result<AutoRsaCandidate, Box<dyn std::error::Error>> {
    let ssh_dir = resolve_ssh_dir()?;
    let candidates = discover_auto_rsa_candidates(&ssh_dir)?;

    if candidates.is_empty() {
        return Err(io::Error::other(format!(
            "no valid RSA public/private key pairs were found in {}",
            ssh_dir.display()
        ))
        .into());
    }

    let items = candidates
        .iter()
        .map(|candidate| {
            format!(
                "{}  [{}]\n  public: {}\n  private: {}",
                candidate.label,
                candidate.fingerprint,
                candidate.public_path.display(),
                candidate.private_path.display()
            )
        })
        .collect::<Vec<_>>();

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select the RSA public key to add")
        .items(&items)
        .default(0)
        .interact_opt()?;

    let index = selection.ok_or_else(|| io::Error::other("RSA selection cancelled"))?;
    Ok(candidates[index].clone())
}

fn discover_auto_rsa_candidates(
    ssh_dir: &Path,
) -> Result<Vec<AutoRsaCandidate>, Box<dyn std::error::Error>> {
    let mut candidates = Vec::new();

    for entry in fs::read_dir(ssh_dir)? {
        let entry = entry?;
        let path = entry.path();

        if !path.is_file() || path.extension().and_then(|ext| ext.to_str()) != Some("pub") {
            continue;
        }

        let Some(stem) = path.file_stem() else {
            continue;
        };

        let private_path = path.with_file_name(stem);
        if !private_path.is_file() {
            continue;
        }

        let public_contents = fs::read_to_string(&path)?;
        let public_key = match SshPublicKey::from_openssh(&public_contents) {
            Ok(key) => key,
            Err(_) => continue,
        };

        let Some(rsa_public) = public_key.key_data().rsa() else {
            continue;
        };

        let private_contents = fs::read_to_string(&private_path)?;
        let private_key = match parse_supported_private_key(&private_contents) {
            Ok(key) => key,
            Err(_) => continue,
        };

        let Some(private_rsa) = private_key.key_data().rsa() else {
            continue;
        };

        let parsed_public = ssh_rsa_public_to_public_key(rsa_public)?;
        let parsed_private = ssh_rsa_keypair_to_private_key(private_rsa)?;

        if parsed_private.to_public_key() != parsed_public {
            continue;
        }

        let public_key_pem = parsed_public.to_public_key_pem(LineEnding::LF)?.to_string();
        let label = stem.to_string_lossy().to_string();
        let fingerprint = public_key.fingerprint(HashAlg::Sha256).to_string();

        candidates.push(AutoRsaCandidate {
            label,
            public_path: path,
            private_path,
            public_key_pem,
            fingerprint,
        });
    }

    candidates.sort_by(|left, right| left.label.cmp(&right.label));
    Ok(candidates)
}

fn load_public_material_from_file(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let contents = fs::read_to_string(path)?;
    normalize_public_material(&contents)
}

fn normalize_public_material(contents: &str) -> Result<String, Box<dyn std::error::Error>> {
    if let Ok(public_key) = SshPublicKey::from_openssh(contents) {
        let rsa_public = public_key
            .key_data()
            .rsa()
            .ok_or_else(|| io::Error::other("OpenSSH public key is not RSA"))?;
        let rsa_public = ssh_rsa_public_to_public_key(rsa_public)?;
        return Ok(rsa_public.to_public_key_pem(LineEnding::LF)?.to_string());
    }

    Ok(contents.to_string())
}

fn parse_supported_private_key(
    contents: &str,
) -> Result<SshPrivateKey, Box<dyn std::error::Error>> {
    if let Ok(key) = SshPrivateKey::from_openssh(contents) {
        return Ok(key);
    }

    Err(
        io::Error::other("private key must be an unencrypted OpenSSH key for automatic discovery")
            .into(),
    )
}

fn resolve_ssh_dir() -> Result<PathBuf, io::Error> {
    let home = std::env::var("HOME")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| io::Error::other("missing HOME; cannot inspect $HOME/.ssh"))?;

    Ok(PathBuf::from(home).join(".ssh"))
}

fn ssh_rsa_public_to_public_key(
    public_key: &ssh_key::public::RsaPublicKey,
) -> Result<rsa::RsaPublicKey, Box<dyn std::error::Error>> {
    Ok(rsa::RsaPublicKey::new(
        BigUint::try_from(&public_key.n)?,
        BigUint::try_from(&public_key.e)?,
    )?)
}

fn ssh_rsa_keypair_to_private_key(
    keypair: &ssh_key::private::RsaKeypair,
) -> Result<rsa::RsaPrivateKey, Box<dyn std::error::Error>> {
    Ok(rsa::RsaPrivateKey::from_components(
        BigUint::try_from(&keypair.public.n)?,
        BigUint::try_from(&keypair.public.e)?,
        BigUint::try_from(&keypair.private.d)?,
        vec![
            BigUint::try_from(&keypair.private.p)?,
            BigUint::try_from(&keypair.private.q)?,
        ],
    )?)
}

fn print_workspace(workspace: &Workspace) {
    println!(
        "workspace\t{}\t{}\t{}",
        workspace.id, workspace.name, workspace.created_at
    );
}

fn print_certificate(certificate: &RsaCertificate) {
    println!(
        "rsa\t{}\t{}\t{}\t{}\t{}",
        certificate.id,
        certificate.workspace_id,
        certificate.label,
        certificate.fingerprint_sha256,
        certificate.created_at
    );
}

fn print_secret_metadata(secret: &SecretMetadata) {
    println!(
        "secret\t{}\t{}\t{}\t{}\t{}",
        secret.id, secret.workspace_id, secret.key, secret.created_at, secret.updated_at
    );
}

fn print_secret_metadata_json(secret: &SecretMetadata) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "{}",
        serde_json::to_string_pretty(&secret_metadata_json_value(secret))?
    );
    Ok(())
}

fn print_secret_metadata_list_json(
    secrets: &[SecretMetadata],
) -> Result<(), Box<dyn std::error::Error>> {
    let payload = secrets
        .iter()
        .map(secret_metadata_json_value)
        .collect::<Vec<_>>();
    println!("{}", serde_json::to_string_pretty(&payload)?);
    Ok(())
}

fn secret_metadata_json_value(secret: &SecretMetadata) -> serde_json::Value {
    json!({
        "id": secret.id,
        "workspace_id": secret.workspace_id,
        "key": secret.key,
        "created_at": secret.created_at,
        "updated_at": secret.updated_at,
    })
}

fn resolve_workspace_ref(
    vaultick: &Vaultick,
    cli_workspace: Option<&str>,
) -> VaultickResult<String> {
    if let Some(workspace) = cli_workspace {
        return Ok(workspace.to_string());
    }

    if let Some(workspace) = read_env_var(VAULTICK_WORKSPACE_ENV_VAR) {
        return Ok(workspace);
    }

    let workspace = vaultick.get_workspace(DEFAULT_WORKSPACE_NAME)?;
    Ok(workspace.name)
}

fn read_env_var(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, OnceLock};

    use super::*;
    use tempfile::tempdir;

    const SSH_RSA_PUBLIC: &str = r#"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCmjkeMm8k3JkNrf16eb5pG4bc77B6Mt3VN4saltsRV8vASpyWa/PlBgdaeldOaNJ5NK0gqU3KyiUNzHbdcc8572e7IUBDJS/rlaWARiSL4aos2VbNX0k56Z5zYp9m/bq5m9/mlb+PQkNBjIhimgpYNiq2TwBiYeA6tLb79cPtHA0cX5BLk/a5oUpLsiR4kI/f+Q98vVDKasKXXVh5YLkLobrruDB6er2A9fOcIUF0O4JCRLh/Dc161gE3fQrYTMQenbppZzfxrZfQ8YwLPvKjnqm+XRX+pbTtaJuj0EgTSzUK+EZxoSw8CNwiZpxrjwecTMVQ8w/srQmh4ABGuTqk0wP8HcI7hg+fpBv7kiejh5X/Oehxt+Puu85u9GVXb1a0av/vhJvUCBcuISvCA/z1wVJ0xdLhb1/ZiTDdTzyNbZQ0OQijzK+e1SlkNhp+3eGVZu3pNZvnTppwIXv3wg6kV1HodkWGgh1ayY7Buc52Z8okDYqvJat5CzOj5OaQNr/k= user@example.com
"#;
    const SSH_RSA_PRIVATE: &str = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEApo5HjJvJNyZDa39enm+aRuG3O+wejLd1TeLGpbbEVfLwEqclmvz5
QYHWnpXTmjSeTStIKlNysolDcx23XHPOe9nuyFAQyUv65WlgEYki+GqLNlWzV9JOemec2K
fZv26uZvf5pW/j0JDQYyIYpoKWDYqtk8AYmHgOrS2+/XD7RwNHF+QS5P2uaFKS7IkeJCP3
/kPfL1QymrCl11YeWC5C6G667gwenq9gPXznCFBdDuCQkS4fw3NetYBN30K2EzEHp26aWc
38a2X0PGMCz7yo56pvl0V/qW07Wibo9BIE0s1CvhGcaEsPAjcImaca48HnEzFUPMP7K0Jo
eAARrk6pNMD/B3CO4YPn6Qb+5Ino4eV/znocbfj7rvObvRlV29WtGr/74Sb1AgXLiErwgP
89cFSdMXS4W9f2Ykw3U88jW2UNDkIo8yvntUpZDYaft3hlWbt6TWb506acCF798IOpFdR6
HZFhoIdWsmOwbnOdmfKJA2KryWreQszo+TmkDa/5AAAFiD9lruM/Za7jAAAAB3NzaC1yc2
EAAAGBAKaOR4ybyTcmQ2t/Xp5vmkbhtzvsHoy3dU3ixqW2xFXy8BKnJZr8+UGB1p6V05o0
nk0rSCpTcrKJQ3Mdt1xzznvZ7shQEMlL+uVpYBGJIvhqizZVs1fSTnpnnNin2b9urmb3+a
Vv49CQ0GMiGKaClg2KrZPAGJh4Dq0tvv1w+0cDRxfkEuT9rmhSkuyJHiQj9/5D3y9UMpqw
pddWHlguQuhuuu4MHp6vYD185whQXQ7gkJEuH8NzXrWATd9CthMxB6dumlnN/Gtl9DxjAs
+8qOeqb5dFf6ltO1om6PQSBNLNQr4RnGhLDwI3CJmnGuPB5xMxVDzD+ytCaHgAEa5OqTTA
/wdwjuGD5+kG/uSJ6OHlf856HG34+67zm70ZVdvVrRq/++Em9QIFy4hK8ID/PXBUnTF0uF
vX9mJMN1PPI1tlDQ5CKPMr57VKWQ2Gn7d4ZVm7ek1m+dOmnAhe/fCDqRXUeh2RYaCHVrJj
sG5znZnyiQNiq8lq3kLM6Pk5pA2v+QAAAAMBAAEAAAGAa2MLEMaVCsDZ8WJzEDYmw5LewH
zyCYpz0J7ps4jOuBfl4DDy1yZKU4kyZpd1klRgyKKiad/Z8PD9kyhSxAJK3KHcCj1NRWx+
vRGfBk9kQ8T2Mzc4ZeRMAzHw9+PpSjtDqVIzHQ6yVRQ5t+ERAbLqqpqCZeQSN6QY2mHHZc
NF0Dh1yxqbcBd8Lvkmj+msjGLAj6kVKn/gDMrecqOs9vAE5bYXQkqAJ5ItvBdfIoYmKeRy
cZjKlAs7wkySaOOrX15ZZbg4fhRwZ5s+poCWX4FZPLFBMQ1MQVaeJbN2otxO2S+RSbdelw
6CJHMJRswg81H4EVsbv8uzj2vQbGIEcrdtZB01gCre8VIgq5sqV+NZGP4n4TgRnMpWqYzP
PA/Gg6GfJyGodm7N2cV2d2YmVvPT4FMl8/s3MmYj277GOz2YSDCy3Se+u2vS7VNF3/8Y3x
gGrevO2phFgElokwaBrD5SMTjFIWyxNZl+PhQ6eBasw9h0HqzsfhX1PaDwgQaRcI2dAAAA
wFRAWqZjrp4IADWnEAL0w1HX0ALDUgByXm3A/22QGjBLEDouoBZQeZbTGTWLW+pP60CY9T
BSjxK5jFDH3fyF/Er5JXuvmqcjXN9GdzSbd+UqQKXi9EEi0YzkCUGRTpkWnEi3CImNKYaW
VmB7fi62NUHgu9Vo5Pd0vsMTfQKlkcjHey4Yjdb3Lu9c/xknzeVzpMoNQ8K2xqlXIURRIu
HPaqXwW2XLnIYST595+inwXj8G87g+3KmUH1cWUOD7RoquTAAAAMEA0R564khkDTsgKTaR
iGVEzf4HeamqtWyPlia/HmZIv9mIvbCsfRGnPjQFYzbUrTkA/3GE7kBLhLrrEaKjAvmC2U
7vt1cDDsbXfZEV6u+Aq1dJoPW1kLKZ/96U+ZMN7bqyrzMwlbCKUEubMPERLc5R837QDQQz
Q9Qg0uL7iL1/iBt8iZDki5P9HShPzIwcB/vvwE0CklsvFZqan1Zwc+HJT9xuRy9IljvhbF
xUU4Vq0r95FuQsNudaUBiRDY2tA41zAAAAwQDL5Q5+zfXiyG52ypS+iwwFsJBB0rzd7rRn
LnEg6syDgOXWt3yFWDxQj47o1VfKvLbfroxyOF8PaTRevBWl3+yUnAdw0C15Rd01klYtpz
iGYuBTxUVNJpDeKmPMVV4aAQ4toK4wfRwR+FKpx1aOAvk9SbKo+Se3mUOykgytMhqiCEEJ
0TbQhcHQXDn0w2z4n9w8ZqdV5j9EbhYwKxNZlADwqDMhoua5FT3wLwPeMY6gkDkoKFPyAR
4JBdEVdmfK8eMAAAAQdXNlckBleGFtcGxlLmNvbQECAw==
-----END OPENSSH PRIVATE KEY-----
"#;

    #[test]
    fn explicit_workspace_takes_priority() {
        let _guard = env_lock().lock().unwrap_or_else(|err| err.into_inner());
        let store = Vaultick::open(":memory:").unwrap();
        store.create_workspace("team-a").unwrap();
        unsafe { std::env::set_var(VAULTICK_WORKSPACE_ENV_VAR, "team-b") };

        let resolved = resolve_workspace_ref(&store, Some("team-a")).unwrap();

        assert_eq!(resolved, "team-a");
        unsafe { std::env::remove_var(VAULTICK_WORKSPACE_ENV_VAR) };
    }

    #[test]
    fn env_workspace_is_used_when_flag_is_missing() {
        let _guard = env_lock().lock().unwrap_or_else(|err| err.into_inner());
        let store = Vaultick::open(":memory:").unwrap();
        store.create_workspace("team-a").unwrap();
        unsafe { std::env::set_var(VAULTICK_WORKSPACE_ENV_VAR, "team-a") };

        let resolved = resolve_workspace_ref(&store, None).unwrap();

        assert_eq!(resolved, "team-a");
        unsafe { std::env::remove_var(VAULTICK_WORKSPACE_ENV_VAR) };
    }

    #[test]
    fn default_workspace_is_used_when_no_flag_or_env_exist() {
        let _guard = env_lock().lock().unwrap_or_else(|err| err.into_inner());
        let store = Vaultick::open(":memory:").unwrap();
        unsafe { std::env::remove_var(VAULTICK_WORKSPACE_ENV_VAR) };

        let resolved = resolve_workspace_ref(&store, None).unwrap();

        assert_eq!(resolved, DEFAULT_WORKSPACE_NAME);
    }

    #[test]
    fn missing_default_workspace_returns_error() {
        let _guard = env_lock().lock().unwrap_or_else(|err| err.into_inner());
        let store = Vaultick::open(":memory:").unwrap();
        unsafe { std::env::remove_var(VAULTICK_WORKSPACE_ENV_VAR) };
        store.delete_workspace(DEFAULT_WORKSPACE_NAME).unwrap();

        let err = resolve_workspace_ref(&store, None).unwrap_err();

        assert!(matches!(
            err,
            vaultick::VaultickError::NotFound {
                entity: "workspace",
                reference
            } if reference == DEFAULT_WORKSPACE_NAME
        ));
    }

    #[test]
    fn explicit_db_path_takes_priority() {
        let _guard = env_lock().lock().unwrap_or_else(|err| err.into_inner());
        let explicit = PathBuf::from("/tmp/explicit.db");
        unsafe { std::env::set_var(VAULTICK_HOME_ENV_VAR, "/tmp/vaultick-home") };

        let resolved = resolve_db_path(Some(explicit.clone())).unwrap();

        assert_eq!(resolved, explicit);
        unsafe { std::env::remove_var(VAULTICK_HOME_ENV_VAR) };
    }

    #[test]
    fn vaultick_home_is_used_when_db_flag_is_missing() {
        let _guard = env_lock().lock().unwrap_or_else(|err| err.into_inner());
        let dir = tempdir().unwrap();
        unsafe { std::env::set_var(VAULTICK_HOME_ENV_VAR, dir.path()) };

        let resolved = resolve_db_path(None).unwrap();

        assert_eq!(
            resolved,
            dir.path()
                .join(DEFAULT_DB_DIRECTORY)
                .join(DEFAULT_DB_FILENAME)
        );
        assert!(dir.path().join(DEFAULT_DB_DIRECTORY).exists());
        unsafe { std::env::remove_var(VAULTICK_HOME_ENV_VAR) };
    }

    #[test]
    fn missing_vaultick_home_returns_guidance() {
        let _guard = env_lock().lock().unwrap_or_else(|err| err.into_inner());
        unsafe { std::env::remove_var(VAULTICK_HOME_ENV_VAR) };

        let err = resolve_db_path(None).unwrap_err();

        assert!(
            err.to_string()
                .contains("VAULTICK_HOME=\"$HOME/.vaultick\"")
        );
    }

    #[test]
    fn normalize_public_material_converts_openssh_rsa_key_to_pem() {
        let normalized = normalize_public_material(SSH_RSA_PUBLIC).unwrap();

        assert!(normalized.contains("BEGIN PUBLIC KEY"));
    }

    #[test]
    fn discover_auto_rsa_candidates_finds_matching_rsa_pair() {
        let dir = tempdir().unwrap();
        let ssh_dir = dir.path().join(".ssh");
        fs::create_dir_all(&ssh_dir).unwrap();
        fs::write(ssh_dir.join("id_rsa.pub"), SSH_RSA_PUBLIC).unwrap();
        fs::write(ssh_dir.join("id_rsa"), SSH_RSA_PRIVATE).unwrap();
        fs::write(ssh_dir.join("orphan.pub"), SSH_RSA_PUBLIC).unwrap();

        let candidates = discover_auto_rsa_candidates(&ssh_dir).unwrap();

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].label, "id_rsa");
        assert_eq!(candidates[0].public_path, ssh_dir.join("id_rsa.pub"));
        assert_eq!(candidates[0].private_path, ssh_dir.join("id_rsa"));
        assert!(candidates[0].public_key_pem.contains("BEGIN PUBLIC KEY"));
    }

    #[test]
    fn secret_get_uses_private_key_matching_certificate_label() {
        let _guard = env_lock().lock().unwrap_or_else(|err| err.into_inner());
        let original_home = std::env::var("HOME").ok();
        let home = tempdir().unwrap();
        let ssh_dir = home.path().join(".ssh");
        fs::create_dir_all(&ssh_dir).unwrap();
        fs::write(ssh_dir.join("id_rsa"), SSH_RSA_PRIVATE).unwrap();
        unsafe { std::env::set_var("HOME", home.path()) };

        let store = Vaultick::open(":memory:").unwrap();
        let openssh_public = SshPublicKey::from_openssh(SSH_RSA_PUBLIC).unwrap();
        let rsa_public =
            ssh_rsa_public_to_public_key(openssh_public.key_data().rsa().unwrap()).unwrap();
        let public_key_pem = rsa_public.to_public_key_pem(LineEnding::LF).unwrap();

        store
            .add_certificate(
                DEFAULT_WORKSPACE_NAME,
                "id_rsa",
                public_key_pem.as_str(),
                None,
            )
            .unwrap();
        store
            .set_secret(
                DEFAULT_WORKSPACE_NAME,
                "API_KEY",
                "value-from-auto-key",
                false,
            )
            .unwrap();

        let value =
            resolve_and_get_secret(&store, DEFAULT_WORKSPACE_NAME, "API_KEY", None).unwrap();

        assert_eq!(value, "value-from-auto-key");
        restore_home(original_home);
    }

    #[test]
    fn secret_get_without_candidate_private_key_tells_user_to_define_one() {
        let _guard = env_lock().lock().unwrap_or_else(|err| err.into_inner());
        let original_home = std::env::var("HOME").ok();
        let home = tempdir().unwrap();
        let ssh_dir = home.path().join(".ssh");
        fs::create_dir_all(&ssh_dir).unwrap();
        unsafe { std::env::set_var("HOME", home.path()) };

        let store = Vaultick::open(":memory:").unwrap();
        let openssh_public = SshPublicKey::from_openssh(SSH_RSA_PUBLIC).unwrap();
        let rsa_public =
            ssh_rsa_public_to_public_key(openssh_public.key_data().rsa().unwrap()).unwrap();
        let public_key_pem = rsa_public.to_public_key_pem(LineEnding::LF).unwrap();

        store
            .add_certificate(
                DEFAULT_WORKSPACE_NAME,
                "id_rsa",
                public_key_pem.as_str(),
                None,
            )
            .unwrap();
        store
            .set_secret(
                DEFAULT_WORKSPACE_NAME,
                "API_KEY",
                "value-from-auto-key",
                false,
            )
            .unwrap();

        let err =
            resolve_and_get_secret(&store, DEFAULT_WORKSPACE_NAME, "API_KEY", None).unwrap_err();

        assert!(err.to_string().contains("define --private-key"));
        assert!(err.to_string().contains(".ssh"));
        assert!(err.to_string().contains(DEFAULT_SSH_PRIVATE_KEY_NAME));
        restore_home(original_home);
    }

    #[test]
    fn secret_get_falls_back_to_id_rsa_when_label_named_key_is_missing() {
        let _guard = env_lock().lock().unwrap_or_else(|err| err.into_inner());
        let original_home = std::env::var("HOME").ok();
        let home = tempdir().unwrap();
        let ssh_dir = home.path().join(".ssh");
        fs::create_dir_all(&ssh_dir).unwrap();
        fs::write(ssh_dir.join(DEFAULT_SSH_PRIVATE_KEY_NAME), SSH_RSA_PRIVATE).unwrap();
        unsafe { std::env::set_var("HOME", home.path()) };

        let store = Vaultick::open(":memory:").unwrap();
        let openssh_public = SshPublicKey::from_openssh(SSH_RSA_PUBLIC).unwrap();
        let rsa_public =
            ssh_rsa_public_to_public_key(openssh_public.key_data().rsa().unwrap()).unwrap();
        let public_key_pem = rsa_public.to_public_key_pem(LineEnding::LF).unwrap();

        store
            .add_certificate(
                DEFAULT_WORKSPACE_NAME,
                "prod-primary",
                public_key_pem.as_str(),
                None,
            )
            .unwrap();
        store
            .set_secret(
                DEFAULT_WORKSPACE_NAME,
                "API_KEY",
                "value-from-id-rsa",
                false,
            )
            .unwrap();

        let value =
            resolve_and_get_secret(&store, DEFAULT_WORKSPACE_NAME, "API_KEY", None).unwrap();

        assert_eq!(value, "value-from-id-rsa");
        restore_home(original_home);
    }

    #[test]
    fn secret_get_uses_id_rsa_and_reports_failure_when_it_does_not_work() {
        let _guard = env_lock().lock().unwrap_or_else(|err| err.into_inner());
        let original_home = std::env::var("HOME").ok();
        let home = tempdir().unwrap();
        let ssh_dir = home.path().join(".ssh");
        fs::create_dir_all(&ssh_dir).unwrap();
        fs::write(
            ssh_dir.join(DEFAULT_SSH_PRIVATE_KEY_NAME),
            "not-a-valid-private-key",
        )
        .unwrap();
        unsafe { std::env::set_var("HOME", home.path()) };

        let store = Vaultick::open(":memory:").unwrap();
        let openssh_public = SshPublicKey::from_openssh(SSH_RSA_PUBLIC).unwrap();
        let rsa_public =
            ssh_rsa_public_to_public_key(openssh_public.key_data().rsa().unwrap()).unwrap();
        let public_key_pem = rsa_public.to_public_key_pem(LineEnding::LF).unwrap();

        store
            .add_certificate(
                DEFAULT_WORKSPACE_NAME,
                "prod-primary",
                public_key_pem.as_str(),
                None,
            )
            .unwrap();
        store
            .set_secret(
                DEFAULT_WORKSPACE_NAME,
                "API_KEY",
                "value-from-id-rsa",
                false,
            )
            .unwrap();

        let err =
            resolve_and_get_secret(&store, DEFAULT_WORKSPACE_NAME, "API_KEY", None).unwrap_err();

        assert!(err.to_string().contains(DEFAULT_SSH_PRIVATE_KEY_NAME));
        assert!(err.to_string().contains("define --private-key"));
        restore_home(original_home);
    }

    #[test]
    fn secret_get_reports_candidate_that_did_not_work() {
        let _guard = env_lock().lock().unwrap_or_else(|err| err.into_inner());
        let original_home = std::env::var("HOME").ok();
        let home = tempdir().unwrap();
        let ssh_dir = home.path().join(".ssh");
        fs::create_dir_all(&ssh_dir).unwrap();
        fs::write(ssh_dir.join("primary"), "not-a-valid-private-key").unwrap();
        unsafe { std::env::set_var("HOME", home.path()) };

        let store = Vaultick::open(":memory:").unwrap();
        let openssh_public = SshPublicKey::from_openssh(SSH_RSA_PUBLIC).unwrap();
        let rsa_public =
            ssh_rsa_public_to_public_key(openssh_public.key_data().rsa().unwrap()).unwrap();
        let public_key_pem = rsa_public.to_public_key_pem(LineEnding::LF).unwrap();
        store
            .add_certificate(
                DEFAULT_WORKSPACE_NAME,
                "primary",
                public_key_pem.as_str(),
                None,
            )
            .unwrap();
        store
            .set_secret(
                DEFAULT_WORKSPACE_NAME,
                "API_KEY",
                "value-from-auto-key",
                false,
            )
            .unwrap();

        let err =
            resolve_and_get_secret(&store, DEFAULT_WORKSPACE_NAME, "API_KEY", None).unwrap_err();

        assert!(err.to_string().contains("primary"));
        assert!(err.to_string().contains("did not work"));
        assert!(err.to_string().contains("define --private-key"));
        restore_home(original_home);
    }

    #[test]
    fn exec_template_uses_explicit_private_key() {
        let store = Vaultick::open(":memory:").unwrap();
        let openssh_public = SshPublicKey::from_openssh(SSH_RSA_PUBLIC).unwrap();
        let rsa_public =
            ssh_rsa_public_to_public_key(openssh_public.key_data().rsa().unwrap()).unwrap();
        let public_key_pem = rsa_public.to_public_key_pem(LineEnding::LF).unwrap();

        store
            .add_certificate(
                DEFAULT_WORKSPACE_NAME,
                "primary",
                public_key_pem.as_str(),
                None,
            )
            .unwrap();
        store
            .set_secret(DEFAULT_WORKSPACE_NAME, "DB_USER", "alice", false)
            .unwrap();
        store
            .set_secret(DEFAULT_WORKSPACE_NAME, "DB_PASS", "super-secret", false)
            .unwrap();

        let temp = tempdir().unwrap();
        let private_key_path = temp.path().join("id_rsa");
        fs::write(&private_key_path, SSH_RSA_PRIVATE).unwrap();

        let rendered = resolve_exec_template(
            &store,
            DEFAULT_WORKSPACE_NAME,
            "postgres://$db_user:$DB_PASS@localhost/app",
            Some(private_key_path.as_path()),
        )
        .unwrap();

        assert_eq!(rendered, "postgres://alice:super-secret@localhost/app");
    }

    #[test]
    fn exec_template_uses_automatic_private_key_lookup() {
        let _guard = env_lock().lock().unwrap_or_else(|err| err.into_inner());
        let original_home = std::env::var("HOME").ok();
        let home = tempdir().unwrap();
        let ssh_dir = home.path().join(".ssh");
        fs::create_dir_all(&ssh_dir).unwrap();
        fs::write(ssh_dir.join(DEFAULT_SSH_PRIVATE_KEY_NAME), SSH_RSA_PRIVATE).unwrap();
        unsafe { std::env::set_var("HOME", home.path()) };

        let store = Vaultick::open(":memory:").unwrap();
        let openssh_public = SshPublicKey::from_openssh(SSH_RSA_PUBLIC).unwrap();
        let rsa_public =
            ssh_rsa_public_to_public_key(openssh_public.key_data().rsa().unwrap()).unwrap();
        let public_key_pem = rsa_public.to_public_key_pem(LineEnding::LF).unwrap();

        store
            .add_certificate(
                DEFAULT_WORKSPACE_NAME,
                "prod-primary",
                public_key_pem.as_str(),
                None,
            )
            .unwrap();
        store
            .set_secret(DEFAULT_WORKSPACE_NAME, "DB_USER", "alice", false)
            .unwrap();
        store
            .set_secret(DEFAULT_WORKSPACE_NAME, "DB_PASS", "super-secret", false)
            .unwrap();

        let rendered = resolve_exec_template(
            &store,
            DEFAULT_WORKSPACE_NAME,
            "postgres://$DB_USER:$db_pass@localhost/app",
            None,
        )
        .unwrap();

        assert_eq!(rendered, "postgres://alice:super-secret@localhost/app");
        restore_home(original_home);
    }

    #[test]
    fn secret_set_uses_inline_value_without_printing() {
        let mut reader = std::io::Cursor::new(Vec::<u8>::new());

        let resolved =
            resolve_secret_set_input(Some("token-value".to_string()), false, &mut reader).unwrap();

        assert_eq!(
            resolved,
            ResolvedSecretSetInput {
                value: b"token-value".to_vec(),
                print_output: false,
            }
        );
    }

    #[test]
    fn secret_set_env_file_parses_entries_without_revealing_values() {
        let mut reader = std::io::Cursor::new(Vec::<u8>::new());

        let request = resolve_secret_set_request(
            None,
            None,
            false,
            None,
            Some("-"),
            &mut std::io::Cursor::new(
                b"github_token=ghp_123\nexport aws_access_key_id=\"AKIA123\"\n".to_vec(),
            ),
        )
        .unwrap();

        assert_eq!(
            request,
            ResolvedSecretSetRequest::EnvFile {
                entries: vec![
                    ("GITHUB_TOKEN".to_string(), "ghp_123".to_string()),
                    ("AWS_ACCESS_KEY_ID".to_string(), "AKIA123".to_string()),
                ]
            }
        );

        let err = resolve_secret_set_request(
            Some("TOKEN".to_string()),
            None,
            false,
            None,
            Some(".env"),
            &mut reader,
        )
        .unwrap_err();

        assert!(err.to_string().contains("--env-file cannot be combined"));
    }

    #[test]
    fn secret_set_command_parses_skip_existing_flag() {
        let cli = Cli::try_parse_from([
            "vaultick",
            "secret",
            "set",
            "--env-file",
            ".env",
            "--skip-existing",
        ])
        .unwrap();

        let Command::Secret(command) = cli.command else {
            panic!("expected secret command");
        };

        let SecretSubcommand::Set {
            env_file,
            skip_existing,
            overwrite,
            ..
        } = command.command
        else {
            panic!("expected secret set command");
        };

        assert_eq!(env_file, Some(".env".to_string()));
        assert!(skip_existing);
        assert!(!overwrite);
    }

    #[test]
    fn secret_get_and_list_parse_json_flag() {
        let cli = Cli::try_parse_from(["vaultick", "secret", "get", "API_KEY", "--json"]).unwrap();
        let Command::Secret(command) = cli.command else {
            panic!("expected secret command");
        };
        let SecretSubcommand::Get { key, json } = command.command else {
            panic!("expected secret get command");
        };
        assert_eq!(key, "API_KEY");
        assert!(json);

        let cli = Cli::try_parse_from(["vaultick", "secret", "list", "--json"]).unwrap();
        let Command::Secret(command) = cli.command else {
            panic!("expected secret command");
        };
        let SecretSubcommand::List { json } = command.command else {
            panic!("expected secret list command");
        };
        assert!(json);
    }

    #[test]
    fn secret_set_request_normalizes_single_key_to_uppercase() {
        let request = resolve_secret_set_request(
            Some("google_token".to_string()),
            Some("token-value".to_string()),
            false,
            None,
            None,
            &mut std::io::Cursor::new(Vec::<u8>::new()),
        )
        .unwrap();

        assert_eq!(
            request,
            ResolvedSecretSetRequest::Single {
                key: "GOOGLE_TOKEN".to_string(),
                input: ResolvedSecretSetInput {
                    value: b"token-value".to_vec(),
                    print_output: false,
                }
            }
        );
    }

    #[test]
    fn secret_set_file_reads_binary_without_printing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("secret.bin");
        fs::write(&path, [0x00, 0x7f, 0xff, 0x41]).unwrap();

        let request = resolve_secret_set_request(
            Some("TOKEN".to_string()),
            None,
            false,
            Some(path.to_str().unwrap()),
            None,
            &mut std::io::Cursor::new(Vec::<u8>::new()),
        )
        .unwrap();

        assert_eq!(
            request,
            ResolvedSecretSetRequest::Single {
                key: "TOKEN".to_string(),
                input: ResolvedSecretSetInput {
                    value: vec![0x00, 0x7f, 0xff, 0x41],
                    print_output: false,
                }
            }
        );
    }

    #[test]
    fn secret_set_file_rejects_conflicting_inputs() {
        let err = resolve_secret_set_request(
            Some("TOKEN".to_string()),
            Some("value".to_string()),
            false,
            Some("secret.txt"),
            None,
            &mut std::io::Cursor::new(Vec::<u8>::new()),
        )
        .unwrap_err();

        assert!(err.to_string().contains("--file cannot be combined"));
    }

    #[test]
    fn parse_env_file_supports_comments_and_last_value_wins() {
        let entries = parse_env_file(
            "\n# comment\ngithub_token=one\nexport GITHUB_TOKEN=two\naws_region='us-east-1'\n",
        )
        .unwrap();

        assert_eq!(
            entries,
            vec![
                ("GITHUB_TOKEN".to_string(), "two".to_string()),
                ("AWS_REGION".to_string(), "us-east-1".to_string()),
            ]
        );
    }

    #[test]
    fn parse_env_file_rejects_invalid_lines() {
        let err = parse_env_file("not-valid").unwrap_err();

        assert!(err.to_string().contains("expected KEY=VALUE"));
    }

    #[test]
    fn secret_set_reads_stdin_and_marks_output_visible() {
        let mut reader = std::io::Cursor::new(b"token-from-stdin".to_vec());

        let resolved = resolve_secret_set_input(None, true, &mut reader).unwrap();

        assert_eq!(
            resolved,
            ResolvedSecretSetInput {
                value: b"token-from-stdin".to_vec(),
                print_output: true,
            }
        );
    }

    #[test]
    fn secret_set_rejects_value_and_stdin_together() {
        let mut reader = std::io::Cursor::new(Vec::<u8>::new());

        let err = resolve_secret_set_input(Some("token-value".to_string()), true, &mut reader)
            .unwrap_err();

        assert!(err.to_string().contains("cannot be used together"));
    }

    #[test]
    fn secret_set_requires_value_or_stdin() {
        let mut reader = std::io::Cursor::new(Vec::<u8>::new());

        let err = resolve_secret_set_input(None, false, &mut reader).unwrap_err();

        assert!(err.to_string().contains("missing secret value"));
    }

    #[test]
    fn exec_command_parses_arguments_after_double_dash() {
        let cli = Cli::try_parse_from(["vaultick", "exec", "--", "AWS_KEY=$AWS_KEY", "aws", "stg"])
            .unwrap();

        let Command::Exec(command) = cli.command else {
            panic!("expected exec command");
        };

        assert!(command.env.is_empty());
        assert!(!command.all);
        assert_eq!(command.argv, vec!["AWS_KEY=$AWS_KEY", "aws", "stg"]);
    }

    #[test]
    fn exec_command_parses_env_flags_and_all_flag() {
        let cli = Cli::try_parse_from([
            "vaultick",
            "exec",
            "--env",
            "GITHUB_TOKEN",
            "--env",
            "AWS_ACCESS_KEY_ID",
            "--",
            "aws",
            "sts",
            "get-caller-identity",
        ])
        .unwrap();

        let Command::Exec(command) = cli.command else {
            panic!("expected exec command");
        };

        assert_eq!(command.env, vec!["GITHUB_TOKEN", "AWS_ACCESS_KEY_ID"]);
        assert!(!command.all);
        assert_eq!(command.argv, vec!["aws", "sts", "get-caller-identity"]);

        let cli = Cli::try_parse_from([
            "vaultick",
            "exec",
            "--all",
            "--",
            "aws",
            "sts",
            "get-caller-identity",
        ])
        .unwrap();

        let Command::Exec(command) = cli.command else {
            panic!("expected exec command");
        };

        assert!(command.env.is_empty());
        assert!(command.all);
        assert_eq!(command.argv, vec!["aws", "sts", "get-caller-identity"]);
    }

    #[test]
    fn request_command_parses_explicit_flags_and_data() {
        let cli = Cli::try_parse_from([
            "vaultick",
            "request",
            "--url",
            "https://example.com",
            "--method",
            "POST",
            "--header",
            "Authorization: Bearer $TOKEN",
            "--body",
            "{\"token\":\"$TOKEN\"}",
        ])
        .unwrap();

        let Command::Request(command) = cli.command else {
            panic!("expected request command");
        };

        assert_eq!(command.url.as_deref(), Some("https://example.com"));
        assert_eq!(command.method.as_deref(), Some("POST"));
        assert_eq!(command.header, vec!["Authorization: Bearer $TOKEN"]);
        assert_eq!(command.body.as_deref(), Some("{\"token\":\"$TOKEN\"}"));
        assert!(command.data.is_none());

        let cli = Cli::try_parse_from([
            "vaultick",
            "request",
            "--data",
            "{\"url\":\"https://example.com\",\"method\":\"GET\"}",
        ])
        .unwrap();

        let Command::Request(command) = cli.command else {
            panic!("expected request command");
        };

        assert_eq!(
            command.data.as_deref(),
            Some("{\"url\":\"https://example.com\",\"method\":\"GET\"}")
        );
    }

    #[test]
    fn request_invocation_resolves_placeholders_in_url_headers_and_body() {
        let store = Vaultick::open(":memory:").unwrap();
        let openssh_public = SshPublicKey::from_openssh(SSH_RSA_PUBLIC).unwrap();
        let rsa_public =
            ssh_rsa_public_to_public_key(openssh_public.key_data().rsa().unwrap()).unwrap();
        let public_key_pem = rsa_public.to_public_key_pem(LineEnding::LF).unwrap();

        store
            .add_certificate(
                DEFAULT_WORKSPACE_NAME,
                "primary",
                public_key_pem.as_str(),
                None,
            )
            .unwrap();
        store
            .set_secret(DEFAULT_WORKSPACE_NAME, "TOKEN", "secret-token", false)
            .unwrap();

        let temp = tempdir().unwrap();
        let private_key_path = temp.path().join("id_rsa");
        fs::write(&private_key_path, SSH_RSA_PRIVATE).unwrap();

        let invocation = resolve_request_invocation(
            &store,
            DEFAULT_WORKSPACE_NAME,
            &RequestCommand {
                private_key: Some(private_key_path),
                url: Some("https://example.com/$TOKEN".to_string()),
                method: Some("POST".to_string()),
                header: vec!["Authorization: Bearer $TOKEN".to_string()],
                body: Some("{\"token\":\"$TOKEN\"}".to_string()),
                data: None,
            },
        )
        .unwrap();

        assert_eq!(invocation.request.method.as_str(), "POST");
        assert_eq!(invocation.request.url, "https://example.com/secret-token");
        assert_eq!(
            invocation.request.headers,
            vec![(
                "Authorization".to_string(),
                "Bearer secret-token".to_string()
            )]
        );
        assert_eq!(
            invocation.request.body,
            Some(RequestBody::Text(
                "{\"token\":\"secret-token\"}".to_string()
            ))
        );
        assert_eq!(invocation.redacted_values, vec!["secret-token".to_string()]);
    }

    #[test]
    fn request_invocation_rejects_invalid_header_format() {
        let store = Vaultick::open(":memory:").unwrap();
        let err = resolve_request_invocation(
            &store,
            DEFAULT_WORKSPACE_NAME,
            &RequestCommand {
                private_key: None,
                url: Some("https://example.com".to_string()),
                method: None,
                header: vec!["Authorization Bearer token".to_string()],
                body: None,
                data: None,
            },
        )
        .unwrap_err();

        assert!(err.to_string().contains("invalid header"));
    }

    #[test]
    fn request_invocation_defaults_to_get_and_rejects_mixed_data_inputs() {
        let store = Vaultick::open(":memory:").unwrap();

        let invocation = resolve_request_invocation(
            &store,
            DEFAULT_WORKSPACE_NAME,
            &RequestCommand {
                private_key: None,
                url: Some("https://example.com".to_string()),
                method: None,
                header: vec!["Accept: application/json".to_string()],
                body: None,
                data: None,
            },
        )
        .unwrap();

        assert_eq!(invocation.request.method.as_str(), "GET");
        assert_eq!(
            invocation.request.headers,
            vec![("Accept".to_string(), "application/json".to_string())]
        );

        let err = resolve_request_invocation(
            &store,
            DEFAULT_WORKSPACE_NAME,
            &RequestCommand {
                private_key: None,
                url: Some("https://example.com".to_string()),
                method: None,
                header: Vec::new(),
                body: None,
                data: Some("{\"url\":\"https://other.example.com\"}".to_string()),
            },
        )
        .unwrap_err();

        assert!(err.to_string().contains("--data cannot be combined"));
    }

    #[test]
    fn exec_invocation_resolves_env_assignments_and_preserves_args() {
        let store = Vaultick::open(":memory:").unwrap();
        let openssh_public = SshPublicKey::from_openssh(SSH_RSA_PUBLIC).unwrap();
        let rsa_public =
            ssh_rsa_public_to_public_key(openssh_public.key_data().rsa().unwrap()).unwrap();
        let public_key_pem = rsa_public.to_public_key_pem(LineEnding::LF).unwrap();

        store
            .add_certificate(
                DEFAULT_WORKSPACE_NAME,
                "primary",
                public_key_pem.as_str(),
                None,
            )
            .unwrap();
        store
            .set_secret(
                DEFAULT_WORKSPACE_NAME,
                "AWS_KEY",
                "secret-access-key",
                false,
            )
            .unwrap();
        store
            .set_secret(DEFAULT_WORKSPACE_NAME, "AWS_PROFILE", "prod", false)
            .unwrap();

        let temp = tempdir().unwrap();
        let private_key_path = temp.path().join("id_rsa");
        fs::write(&private_key_path, SSH_RSA_PRIVATE).unwrap();

        let invocation = resolve_exec_invocation(
            &store,
            DEFAULT_WORKSPACE_NAME,
            &[],
            false,
            &[
                "AWS_KEY=$AWS_KEY".to_string(),
                "aws".to_string(),
                "--profile".to_string(),
                "$aws_profile".to_string(),
                "stg".to_string(),
            ],
            Some(private_key_path.as_path()),
        )
        .unwrap();

        assert_eq!(invocation.program, "aws");
        assert_eq!(invocation.args, vec!["--profile", "$aws_profile", "stg"]);
        assert_eq!(
            invocation.env_vars,
            vec![("AWS_KEY".to_string(), "secret-access-key".to_string())]
        );
        assert_eq!(
            invocation.redacted_values,
            vec!["secret-access-key".to_string()]
        );
    }

    #[test]
    fn exec_invocation_loads_named_envs_from_workspace() {
        let store = Vaultick::open(":memory:").unwrap();
        let openssh_public = SshPublicKey::from_openssh(SSH_RSA_PUBLIC).unwrap();
        let rsa_public =
            ssh_rsa_public_to_public_key(openssh_public.key_data().rsa().unwrap()).unwrap();
        let public_key_pem = rsa_public.to_public_key_pem(LineEnding::LF).unwrap();

        store
            .add_certificate(
                DEFAULT_WORKSPACE_NAME,
                "primary",
                public_key_pem.as_str(),
                None,
            )
            .unwrap();
        store
            .set_secret(DEFAULT_WORKSPACE_NAME, "GITHUB_TOKEN", "ghp_123", false)
            .unwrap();
        store
            .set_secret(
                DEFAULT_WORKSPACE_NAME,
                "AWS_ACCESS_KEY_ID",
                "AKIA123",
                false,
            )
            .unwrap();

        let temp = tempdir().unwrap();
        let private_key_path = temp.path().join("id_rsa");
        fs::write(&private_key_path, SSH_RSA_PRIVATE).unwrap();

        let invocation = resolve_exec_invocation(
            &store,
            DEFAULT_WORKSPACE_NAME,
            &["github_token".to_string(), "aws_access_key_id".to_string()],
            false,
            &[
                "aws".to_string(),
                "sts".to_string(),
                "get-caller-identity".to_string(),
            ],
            Some(private_key_path.as_path()),
        )
        .unwrap();

        assert_eq!(invocation.program, "aws");
        assert_eq!(invocation.args, vec!["sts", "get-caller-identity"]);
        assert_eq!(
            invocation.env_vars,
            vec![
                ("GITHUB_TOKEN".to_string(), "ghp_123".to_string()),
                ("AWS_ACCESS_KEY_ID".to_string(), "AKIA123".to_string()),
            ]
        );
        assert_eq!(
            invocation.redacted_values,
            vec!["ghp_123".to_string(), "AKIA123".to_string()]
        );
    }

    #[test]
    fn exec_invocation_loads_all_workspace_secrets() {
        let store = Vaultick::open(":memory:").unwrap();
        let openssh_public = SshPublicKey::from_openssh(SSH_RSA_PUBLIC).unwrap();
        let rsa_public =
            ssh_rsa_public_to_public_key(openssh_public.key_data().rsa().unwrap()).unwrap();
        let public_key_pem = rsa_public.to_public_key_pem(LineEnding::LF).unwrap();

        store
            .add_certificate(
                DEFAULT_WORKSPACE_NAME,
                "primary",
                public_key_pem.as_str(),
                None,
            )
            .unwrap();
        store
            .set_secret(
                DEFAULT_WORKSPACE_NAME,
                "AWS_ACCESS_KEY_ID",
                "AKIA123",
                false,
            )
            .unwrap();
        store
            .set_secret(
                DEFAULT_WORKSPACE_NAME,
                "AWS_SECRET_ACCESS_KEY",
                "secret-key",
                false,
            )
            .unwrap();

        let temp = tempdir().unwrap();
        let private_key_path = temp.path().join("id_rsa");
        fs::write(&private_key_path, SSH_RSA_PRIVATE).unwrap();

        let invocation = resolve_exec_invocation(
            &store,
            DEFAULT_WORKSPACE_NAME,
            &[],
            true,
            &[
                "aws".to_string(),
                "sts".to_string(),
                "get-caller-identity".to_string(),
            ],
            Some(private_key_path.as_path()),
        )
        .unwrap();

        assert_eq!(
            invocation.env_vars,
            vec![
                ("AWS_ACCESS_KEY_ID".to_string(), "AKIA123".to_string()),
                (
                    "AWS_SECRET_ACCESS_KEY".to_string(),
                    "secret-key".to_string()
                ),
            ]
        );
        assert_eq!(
            invocation.redacted_values,
            vec!["AKIA123".to_string(), "secret-key".to_string()]
        );
    }

    #[test]
    fn exec_invocation_uses_env_name_when_assignment_value_is_empty() {
        let store = Vaultick::open(":memory:").unwrap();
        let openssh_public = SshPublicKey::from_openssh(SSH_RSA_PUBLIC).unwrap();
        let rsa_public =
            ssh_rsa_public_to_public_key(openssh_public.key_data().rsa().unwrap()).unwrap();
        let public_key_pem = rsa_public.to_public_key_pem(LineEnding::LF).unwrap();

        store
            .add_certificate(
                DEFAULT_WORKSPACE_NAME,
                "primary",
                public_key_pem.as_str(),
                None,
            )
            .unwrap();
        store
            .set_secret(
                DEFAULT_WORKSPACE_NAME,
                "AWS_KEY",
                "secret-access-key",
                false,
            )
            .unwrap();

        let temp = tempdir().unwrap();
        let private_key_path = temp.path().join("id_rsa");
        fs::write(&private_key_path, SSH_RSA_PRIVATE).unwrap();

        let invocation = resolve_exec_invocation(
            &store,
            DEFAULT_WORKSPACE_NAME,
            &[],
            false,
            &["AWS_KEY=".to_string(), "aws".to_string(), "stg".to_string()],
            Some(private_key_path.as_path()),
        )
        .unwrap();

        assert_eq!(
            invocation.env_vars,
            vec![("AWS_KEY".to_string(), "secret-access-key".to_string())]
        );
        assert_eq!(
            invocation.redacted_values,
            vec!["secret-access-key".to_string()]
        );
    }

    #[test]
    fn exec_assignment_overrides_env_flag_value() {
        let store = Vaultick::open(":memory:").unwrap();
        let openssh_public = SshPublicKey::from_openssh(SSH_RSA_PUBLIC).unwrap();
        let rsa_public =
            ssh_rsa_public_to_public_key(openssh_public.key_data().rsa().unwrap()).unwrap();
        let public_key_pem = rsa_public.to_public_key_pem(LineEnding::LF).unwrap();

        store
            .add_certificate(
                DEFAULT_WORKSPACE_NAME,
                "primary",
                public_key_pem.as_str(),
                None,
            )
            .unwrap();
        store
            .set_secret(
                DEFAULT_WORKSPACE_NAME,
                "AWS_KEY",
                "secret-access-key",
                false,
            )
            .unwrap();
        store
            .set_secret(DEFAULT_WORKSPACE_NAME, "OVERRIDE", "override-value", false)
            .unwrap();

        let temp = tempdir().unwrap();
        let private_key_path = temp.path().join("id_rsa");
        fs::write(&private_key_path, SSH_RSA_PRIVATE).unwrap();

        let invocation = resolve_exec_invocation(
            &store,
            DEFAULT_WORKSPACE_NAME,
            &["AWS_KEY".to_string()],
            false,
            &["AWS_KEY=$OVERRIDE".to_string(), "aws".to_string()],
            Some(private_key_path.as_path()),
        )
        .unwrap();

        assert_eq!(
            invocation.env_vars,
            vec![("AWS_KEY".to_string(), "override-value".to_string())]
        );
        assert_eq!(
            invocation.redacted_values,
            vec![
                "secret-access-key".to_string(),
                "override-value".to_string()
            ]
        );
    }

    #[test]
    fn exec_invocation_leaves_shell_variables_in_arguments_untouched() {
        let store = Vaultick::open(":memory:").unwrap();
        let openssh_public = SshPublicKey::from_openssh(SSH_RSA_PUBLIC).unwrap();
        let rsa_public =
            ssh_rsa_public_to_public_key(openssh_public.key_data().rsa().unwrap()).unwrap();
        let public_key_pem = rsa_public.to_public_key_pem(LineEnding::LF).unwrap();

        store
            .add_certificate(
                DEFAULT_WORKSPACE_NAME,
                "primary",
                public_key_pem.as_str(),
                None,
            )
            .unwrap();
        store
            .set_secret(DEFAULT_WORKSPACE_NAME, "GITHUB_TOKEN", "ghp_123", false)
            .unwrap();

        let temp = tempdir().unwrap();
        let private_key_path = temp.path().join("id_rsa");
        fs::write(&private_key_path, SSH_RSA_PRIVATE).unwrap();

        let invocation = resolve_exec_invocation(
            &store,
            DEFAULT_WORKSPACE_NAME,
            &["GITHUB_TOKEN".to_string()],
            false,
            &[
                "sh".to_string(),
                "-c".to_string(),
                "echo \"$GITHUB_TOKEN\"; echo \"$i\"".to_string(),
            ],
            Some(private_key_path.as_path()),
        )
        .unwrap();

        assert_eq!(invocation.program, "sh");
        assert_eq!(
            invocation.args,
            vec!["-c", "echo \"$GITHUB_TOKEN\"; echo \"$i\""]
        );
        assert_eq!(
            invocation.env_vars,
            vec![("GITHUB_TOKEN".to_string(), "ghp_123".to_string())]
        );
    }

    #[test]
    fn redact_output_masks_known_secret_values() {
        let redacted = redact_output(
            "token=ghp_123 profile=prod key=secret-access-key",
            &[
                "secret-access-key".to_string(),
                "ghp_123".to_string(),
                "prod".to_string(),
            ],
        );

        assert_eq!(
            redacted,
            "token=[REDACTED] profile=[REDACTED] key=[REDACTED]"
        );
    }

    #[test]
    fn stream_redacted_output_masks_values_across_chunk_boundaries() {
        let mut reader = ChunkedReader::new(b"prefix ghp_123 suffix".to_vec(), 3);
        let mut writer = Vec::new();

        stream_redacted_output(&mut reader, &mut writer, &["ghp_123".to_string()]).unwrap();

        assert_eq!(
            String::from_utf8(writer).unwrap(),
            "prefix [REDACTED] suffix"
        );
    }

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn restore_home(original_home: Option<String>) {
        match original_home {
            Some(home) => unsafe { std::env::set_var("HOME", home) },
            None => unsafe { std::env::remove_var("HOME") },
        }
    }

    struct ChunkedReader {
        bytes: Vec<u8>,
        chunk_size: usize,
        offset: usize,
    }

    impl ChunkedReader {
        fn new(bytes: Vec<u8>, chunk_size: usize) -> Self {
            Self {
                bytes,
                chunk_size,
                offset: 0,
            }
        }
    }

    impl Read for ChunkedReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.offset >= self.bytes.len() {
                return Ok(0);
            }

            let len = self
                .chunk_size
                .min(buf.len())
                .min(self.bytes.len() - self.offset);
            buf[..len].copy_from_slice(&self.bytes[self.offset..self.offset + len]);
            self.offset += len;
            Ok(len)
        }
    }
}
