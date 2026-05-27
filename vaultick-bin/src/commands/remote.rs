use std::io;

use super::{Cli, VAULTICK_REMOTE_ENV_VAR, read_env_var};

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
