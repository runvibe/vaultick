use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand};
use dialoguer::{Select, theme::ColorfulTheme};
use rsa::BigUint;
use rsa::pkcs8::{EncodePublicKey, LineEnding};
use ssh_key::{HashAlg, PrivateKey as SshPrivateKey, PublicKey as SshPublicKey};
use valtick::{Result as ValtickResult, RsaCertificate, SecretMetadata, Valtick, Workspace};

const DEFAULT_WORKSPACE_NAME: &str = "default";
const DEFAULT_DB_DIRECTORY: &str = "databases";
const DEFAULT_DB_FILENAME: &str = "database.db";
const DEFAULT_SSH_PRIVATE_KEY_NAME: &str = "id_rsa";
const VALTICK_HOME_ENV_VAR: &str = "VALTICK_HOME";
const WORKSPACE_ENV_VAR: &str = "VALTICK_WORKSPACE";

#[derive(Debug, Clone)]
struct AutoRsaCandidate {
    label: String,
    public_path: PathBuf,
    private_path: PathBuf,
    public_key_pem: String,
    fingerprint: String,
}

#[derive(Parser, Debug)]
#[command(name = "valtick")]
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
    Workspace(WorkspaceCommand),
    Rsa(RsaCommand),
    Secret(SecretCommand),
}

#[derive(Subcommand, Debug)]
enum WorkspaceSubcommand {
    Create { name: String },
    List,
    Get { workspace_ref: String },
    Delete { workspace_ref: String },
}

#[derive(Args, Debug)]
struct WorkspaceCommand {
    #[command(subcommand)]
    command: WorkspaceSubcommand,
}

#[derive(Subcommand, Debug)]
enum RsaSubcommand {
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
    List,
    Delete {
        cert_ref: String,
    },
}

#[derive(Args, Debug)]
struct RsaCommand {
    #[command(subcommand)]
    command: RsaSubcommand,
}

#[derive(Subcommand, Debug)]
enum SecretSubcommand {
    Set {
        key: String,
        value: String,
    },
    Get {
        key: String,
        #[arg(long = "private-key", value_name = "PEM_PATH")]
        private_key: Option<PathBuf>,
    },
    List,
    Delete {
        key: String,
    },
}

#[derive(Args, Debug)]
struct SecretCommand {
    #[command(subcommand)]
    command: SecretSubcommand,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let db_path = resolve_db_path(cli.db)?;
    let valtick = Valtick::open(&db_path)?;

    match cli.command {
        Command::Workspace(command) => handle_workspace(&valtick, command.command)?,
        Command::Rsa(command) => {
            let workspace_ref = resolve_workspace_ref(&valtick, cli.workspace.as_deref())?;
            handle_rsa(&valtick, &workspace_ref, command.command)?;
        }
        Command::Secret(command) => {
            let workspace_ref = resolve_workspace_ref(&valtick, cli.workspace.as_deref())?;
            handle_secret(&valtick, &workspace_ref, command.command)?;
        }
    }

    Ok(())
}

fn resolve_db_path(cli_db: Option<PathBuf>) -> Result<PathBuf, io::Error> {
    if let Some(path) = cli_db {
        return Ok(path);
    }

    let valtick_home = std::env::var(VALTICK_HOME_ENV_VAR)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            io::Error::other(
                "missing VALTICK_HOME. Configure something like VALTICK_HOME=\"$HOME/.valtick\" or pass --db <path>",
            )
        })?;

    let home_path = PathBuf::from(valtick_home);
    let db_directory = home_path.join(DEFAULT_DB_DIRECTORY);
    fs::create_dir_all(&db_directory)?;
    Ok(db_directory.join(DEFAULT_DB_FILENAME))
}

fn handle_workspace(
    valtick: &Valtick,
    command: WorkspaceSubcommand,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        WorkspaceSubcommand::Create { name } => {
            let workspace = valtick.create_workspace(&name)?;
            print_workspace(&workspace);
        }
        WorkspaceSubcommand::List => {
            let workspaces = valtick.list_workspaces()?;
            for workspace in workspaces {
                print_workspace(&workspace);
            }
        }
        WorkspaceSubcommand::Get { workspace_ref } => {
            let workspace = valtick.get_workspace(&workspace_ref)?;
            print_workspace(&workspace);
        }
        WorkspaceSubcommand::Delete { workspace_ref } => {
            valtick.delete_workspace(&workspace_ref)?;
            println!("deleted workspace {workspace_ref}");
        }
    }

    Ok(())
}

fn handle_rsa(
    valtick: &Valtick,
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
            let certificate = valtick.add_certificate(
                workspace_ref,
                &add_input.label,
                &add_input.public_key_pem,
                rewrap_pem.as_deref(),
            )?;
            print_certificate(&certificate);
        }
        RsaSubcommand::List => {
            let certificates = valtick.list_certificates(workspace_ref)?;
            for certificate in certificates {
                print_certificate(&certificate);
            }
        }
        RsaSubcommand::Delete { cert_ref } => {
            valtick.delete_certificate(workspace_ref, &cert_ref)?;
            println!("deleted certificate {cert_ref}");
        }
    }

    Ok(())
}

fn handle_secret(
    valtick: &Valtick,
    workspace_ref: &str,
    command: SecretSubcommand,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        SecretSubcommand::Set { key, value } => {
            let secret = valtick.set_secret(workspace_ref, &key, &value)?;
            print_secret_metadata(&secret);
        }
        SecretSubcommand::Get { key, private_key } => {
            let value =
                resolve_and_get_secret(valtick, workspace_ref, &key, private_key.as_deref())?;
            println!("{value}");
        }
        SecretSubcommand::List => {
            let secrets = valtick.list_secrets(workspace_ref)?;
            for secret in secrets {
                print_secret_metadata(&secret);
            }
        }
        SecretSubcommand::Delete { key } => {
            valtick.delete_secret(workspace_ref, &key)?;
            println!("deleted secret {key}");
        }
    }

    Ok(())
}

fn resolve_and_get_secret(
    valtick: &Valtick,
    workspace_ref: &str,
    key: &str,
    private_key: Option<&Path>,
) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(private_key_path) = private_key {
        let private_key_pem = fs::read_to_string(private_key_path)?;
        return Ok(valtick.get_secret(workspace_ref, key, &private_key_pem)?);
    }

    let ssh_dir = resolve_ssh_dir().map_err(|_| {
        io::Error::other("no private key candidate was found automatically; define --private-key")
    })?;
    Ok(valtick.get_secret_auto(workspace_ref, key, &ssh_dir)?)
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

fn resolve_workspace_ref(valtick: &Valtick, cli_workspace: Option<&str>) -> ValtickResult<String> {
    if let Some(workspace) = cli_workspace {
        return Ok(workspace.to_string());
    }

    if let Ok(workspace) = std::env::var(WORKSPACE_ENV_VAR) {
        let trimmed = workspace.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }

    let workspace = valtick.get_workspace(DEFAULT_WORKSPACE_NAME)?;
    Ok(workspace.name)
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
        let store = Valtick::open(":memory:").unwrap();
        store.create_workspace("team-a").unwrap();
        unsafe { std::env::set_var(WORKSPACE_ENV_VAR, "team-b") };

        let resolved = resolve_workspace_ref(&store, Some("team-a")).unwrap();

        assert_eq!(resolved, "team-a");
        unsafe { std::env::remove_var(WORKSPACE_ENV_VAR) };
    }

    #[test]
    fn env_workspace_is_used_when_flag_is_missing() {
        let _guard = env_lock().lock().unwrap_or_else(|err| err.into_inner());
        let store = Valtick::open(":memory:").unwrap();
        store.create_workspace("team-a").unwrap();
        unsafe { std::env::set_var(WORKSPACE_ENV_VAR, "team-a") };

        let resolved = resolve_workspace_ref(&store, None).unwrap();

        assert_eq!(resolved, "team-a");
        unsafe { std::env::remove_var(WORKSPACE_ENV_VAR) };
    }

    #[test]
    fn default_workspace_is_used_when_no_flag_or_env_exist() {
        let _guard = env_lock().lock().unwrap_or_else(|err| err.into_inner());
        let store = Valtick::open(":memory:").unwrap();
        unsafe { std::env::remove_var(WORKSPACE_ENV_VAR) };

        let resolved = resolve_workspace_ref(&store, None).unwrap();

        assert_eq!(resolved, DEFAULT_WORKSPACE_NAME);
    }

    #[test]
    fn missing_default_workspace_returns_error() {
        let _guard = env_lock().lock().unwrap_or_else(|err| err.into_inner());
        let store = Valtick::open(":memory:").unwrap();
        unsafe { std::env::remove_var(WORKSPACE_ENV_VAR) };
        store.delete_workspace(DEFAULT_WORKSPACE_NAME).unwrap();

        let err = resolve_workspace_ref(&store, None).unwrap_err();

        assert!(matches!(
            err,
            valtick::ValtickError::NotFound {
                entity: "workspace",
                reference
            } if reference == DEFAULT_WORKSPACE_NAME
        ));
    }

    #[test]
    fn explicit_db_path_takes_priority() {
        let _guard = env_lock().lock().unwrap_or_else(|err| err.into_inner());
        let explicit = PathBuf::from("/tmp/explicit.db");
        unsafe { std::env::set_var(VALTICK_HOME_ENV_VAR, "/tmp/valtick-home") };

        let resolved = resolve_db_path(Some(explicit.clone())).unwrap();

        assert_eq!(resolved, explicit);
        unsafe { std::env::remove_var(VALTICK_HOME_ENV_VAR) };
    }

    #[test]
    fn valtick_home_is_used_when_db_flag_is_missing() {
        let _guard = env_lock().lock().unwrap_or_else(|err| err.into_inner());
        let dir = tempdir().unwrap();
        unsafe { std::env::set_var(VALTICK_HOME_ENV_VAR, dir.path()) };

        let resolved = resolve_db_path(None).unwrap();

        assert_eq!(
            resolved,
            dir.path()
                .join(DEFAULT_DB_DIRECTORY)
                .join(DEFAULT_DB_FILENAME)
        );
        assert!(dir.path().join(DEFAULT_DB_DIRECTORY).exists());
        unsafe { std::env::remove_var(VALTICK_HOME_ENV_VAR) };
    }

    #[test]
    fn missing_valtick_home_returns_guidance() {
        let _guard = env_lock().lock().unwrap_or_else(|err| err.into_inner());
        unsafe { std::env::remove_var(VALTICK_HOME_ENV_VAR) };

        let err = resolve_db_path(None).unwrap_err();

        assert!(err.to_string().contains("VALTICK_HOME=\"$HOME/.valtick\""));
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

        let store = Valtick::open(":memory:").unwrap();
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
            .set_secret(DEFAULT_WORKSPACE_NAME, "API_KEY", "value-from-auto-key")
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

        let store = Valtick::open(":memory:").unwrap();
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
            .set_secret(DEFAULT_WORKSPACE_NAME, "API_KEY", "value-from-auto-key")
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

        let store = Valtick::open(":memory:").unwrap();
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
            .set_secret(DEFAULT_WORKSPACE_NAME, "API_KEY", "value-from-id-rsa")
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

        let store = Valtick::open(":memory:").unwrap();
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
            .set_secret(DEFAULT_WORKSPACE_NAME, "API_KEY", "value-from-id-rsa")
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

        let store = Valtick::open(":memory:").unwrap();
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
            .set_secret(DEFAULT_WORKSPACE_NAME, "API_KEY", "value-from-auto-key")
            .unwrap();

        let err =
            resolve_and_get_secret(&store, DEFAULT_WORKSPACE_NAME, "API_KEY", None).unwrap_err();

        assert!(err.to_string().contains("primary"));
        assert!(err.to_string().contains("did not work"));
        assert!(err.to_string().contains("define --private-key"));
        restore_home(original_home);
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
}
