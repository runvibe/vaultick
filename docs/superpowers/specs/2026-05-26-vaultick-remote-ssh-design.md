# Vaultick Remote SSH Design

## Context

Vaultick currently uses the local CLI as the main user interface and opens the
SQLite database directly through `Vaultick::open(path)`. The database path is
resolved from `--db` or `VAULTICK_HOME/databases/database.db`.

The target deployment is different:

- The SQLite database should stay on `192.168.88.240`, on an external disk
  attached to that host.
- The Mac should keep the normal `vaultick` CLI experience.
- The server should avoid a long-running Vaultick daemon to minimize resource
  usage.
- The design should avoid mounting the SQLite file over the network because
  SQLite file locking over SMB, NFS, or SSHFS is fragile.

## Goal

Add a remote mode where the local CLI can execute normal Vaultick commands
against a remote host over SSH:

```sh
vaultick -r assis@192.168.88.240:/mnt/hd/vaultick secret list
vaultick --remote assis@192.168.88.240:/mnt/hd/vaultick secret get API_KEY

export VAULTICK_REMOTE=assis@192.168.88.240:/mnt/hd/vaultick
vaultick secret list
```

The remote host runs the `vaultick` binary only for the duration of each command.
The SQLite database remains local to the remote host.

## Non-Goals

- Do not add a long-running HTTP server in the first implementation.
- Do not expose SQLite directly over the network.
- Do not make the client depend on the internal database schema.
- Do not replace `rusqlite` or migrate to a remote SQL driver.
- Do not require Valkey or another always-on service.

## User Interface

Remote mode can be enabled by a CLI flag or environment variable:

```text
1. --remote / -r
2. VAULTICK_REMOTE
3. local mode: --db or VAULTICK_HOME
```

`--remote` takes precedence over `VAULTICK_REMOTE`. If neither is set, the CLI
keeps the current local SQLite behavior.

Remote address format:

```text
[user@]host[:remote_vaultick_home]
```

Examples:

```text
192.168.88.240
assis@192.168.88.240
assis@192.168.88.240:/mnt/hd/vaultick
```

If `remote_vaultick_home` is omitted, the remote binary uses the remote
environment's existing `VAULTICK_HOME`.

## Architecture

The local CLI becomes a dispatcher:

```text
Local Mac
  vaultick -r ADDRESS <normal command>
    -> parse remote address
    -> capture local-only inputs such as stdin and local files
    -> open ssh to the remote host
    -> run "vaultick remote-stdio"
    -> send a structured request through stdin
    -> print the returned stdout/stderr and exit with the returned status

Remote host
  vaultick remote-stdio
    -> receive structured request from stdin
    -> set VAULTICK_HOME if remote_vaultick_home was provided
    -> open SQLite locally
    -> execute the requested Vaultick operation
    -> return structured stdout/stderr/status
```

This keeps SQLite access local to the remote machine while preserving a CLI
interface on the Mac.

## Remote Protocol

The first implementation should use an internal JSON protocol over SSH stdio.
This protocol is not a public API. It is a compatibility layer between matching
Vaultick binaries.

The request should include:

- command arguments after removing `-r/--remote`;
- optional remote `VAULTICK_HOME`;
- selected environment values needed by Vaultick, such as `VAULTICK_WORKSPACE`;
- stdin payload, when the local command reads stdin;
- local file payloads for CLI options that must read local files.

The response should include:

- stdout bytes;
- stderr bytes;
- process exit code.

The CLI should preserve current output formatting by printing the remote stdout
and stderr exactly as returned.

## Local File And Stdin Handling

Remote mode must not make local file arguments unexpectedly refer to files on
the remote host.

For commands that read local input, the dispatcher should read the content on
the Mac and send it in the remote request. Initial targets:

- `secret set --stdin`
- `secret set --env-file <path>`
- `request` body/config paths if those options are local-file based
- RSA certificate import paths if those currently read local files

The remote handler should materialize these payloads in a controlled temporary
location or pass them directly to reusable service functions. Prefer direct
service calls where practical. Temporary files must be deleted after the command.

If a path should intentionally be resolved on the remote host, that should be a
future explicit option, not the default behavior.

## Security

SSH provides transport authentication and encryption. Vaultick should not add a
second network token for this SSH mode.

The implementation should:

- avoid logging secret values or request payloads;
- avoid putting secret values into SSH command arguments;
- send sensitive values through stdin only;
- refuse remote execution if the SSH command exits before the protocol handshake;
- report clear errors when the remote binary is missing or too old.

The default remote command is:

```sh
vaultick remote-stdio
```

A later enhancement can add `VAULTICK_REMOTE_BIN` if the binary is not on the
remote `PATH`.

## Compatibility

Remote mode should be additive:

- existing local commands keep their behavior;
- existing `--db` behavior stays local-only;
- `--db` and `--remote` should be mutually exclusive unless a future design
  defines remote database path semantics;
- remote mode should support `VAULTICK_WORKSPACE` and `--workspace` the same way
  local mode does.

Because the protocol is internal, the local and remote `vaultick` binaries should
have matching or compatible versions. A version field in the protocol request
should allow clear errors for incompatible clients.

## Error Handling

Errors should be easy to diagnose:

- invalid remote address: fail before opening SSH;
- SSH connection failure: show the target host and SSH exit status;
- missing remote binary: suggest installing `vaultick` on the remote host or
  adding it to `PATH`;
- missing remote `VAULTICK_HOME`: show the same guidance as local mode;
- remote command failure: preserve remote stderr and exit code.

## Testing

Unit tests should cover:

- remote address parsing;
- `--remote` precedence over `VAULTICK_REMOTE`;
- mutual exclusion between `--remote` and `--db`;
- request/response JSON encoding;
- local file payload capture.

Integration tests should cover the dispatcher without requiring a real SSH
server by using a fake SSH command that invokes the local test binary in
`remote-stdio` mode.

Manual verification should include:

```sh
vaultick -r assis@192.168.88.240:/mnt/hd/vaultick workspace list
vaultick -r assis@192.168.88.240:/mnt/hd/vaultick secret set API_KEY --value test
vaultick -r assis@192.168.88.240:/mnt/hd/vaultick secret list
vaultick -r assis@192.168.88.240:/mnt/hd/vaultick secret set --env-file ./secrets.env
```

## Implementation Scope

The first implementation should support the core CLI paths that make the remote
SQLite workflow useful:

- workspace commands;
- RSA certificate commands;
- secret commands, including stdin and env-file import;
- local output behavior and exit codes.

`exec` and `request` can be added in the same implementation if their local file
and process semantics remain straightforward. If they introduce ambiguity, they
should fail clearly in remote mode until a follow-up design defines them.
