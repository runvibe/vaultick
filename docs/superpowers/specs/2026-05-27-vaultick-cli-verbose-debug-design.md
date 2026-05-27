# Vaultick CLI Verbose and Debug Logging Design

## Context

Vaultick currently performs important client-side work silently, especially for
remote file workflows:

- resolving local or remote execution;
- reading local files;
- optionally compressing file payloads with zstd;
- sending prepared requests over SSH;
- writing or reading the SQLite database on the remote host;
- decompressing downloaded file payloads before writing output files.

This is correct for clean command output, but it gives operators little feedback
while large files are being uploaded or restored. The CLI needs an explicit
diagnostic mode that explains what is happening step by step without exposing
secret material.

## Goals

- Add global `--verbose` and `--debug` flags to the `vaultick` CLI.
- Print operational progress to `stderr`, never `stdout`.
- Keep existing `stdout` contracts stable for tables, JSON output, command
  output, and remote protocol payloads.
- Make large file upload and download workflows understandable.
- Make remote SSH workflows visibly traceable from the client side.
- Avoid leaking secrets, plaintext file contents, encrypted payloads, request
  bodies, env-file values, or private keys.

## Non-Goals

- No structured logging framework is required for this feature.
- No progress bar is required.
- No logging is required inside `vaultick-lib`.
- No long-lived remote server behavior changes are required.
- No logging of secret values, file contents, stdin contents, env-file values,
  raw ciphertext, or decrypted payloads.
- No change to compression decisions or remote protocol semantics.

## User Interface

Add two global flags:

```bash
vaultick --verbose <COMMAND>
vaultick --debug <COMMAND>
```

`--debug` implies `--verbose`.

These flags are global and should be parsed by Clap at the root CLI level. The
primary supported placement is before the subcommand:

```bash
vaultick --debug -r pi@192.168.88.240 secret set VIDEO --file ./video.ts
```

Existing flags keep their meaning:

```bash
vaultick -r pi@192.168.88.240 secret set VIDEO --file ./video.ts
```

The output format should use stable human-readable prefixes:

```text
[vaultick] using remote: pi@192.168.88.240
[vaultick] reading file: /path/video.ts (82.3 MB)
[vaultick] compressing file with zstd level 10
[vaultick] compression kept: none (compressed payload was not smaller)
[vaultick] opening SSH transport
[vaultick] storing secret on remote workspace: default
[vaultick] stored secret: VIDEO
```

Debug messages may include more detail:

```text
[vaultick:debug] remote protocol version: 1
[vaultick:debug] original bytes: 86297892
[vaultick:debug] prepared payload bytes: 86297892
[vaultick:debug] remote operation: SetPreparedFile
```

## Logging Levels

### Normal

Default behavior stays quiet. Commands only print their existing output.

### Verbose

Verbose prints user-facing operational steps:

- selected local or remote mode;
- selected remote destination;
- database path in local mode;
- workspace reference;
- file path and byte size;
- compression level and final compression decision;
- SSH transport start and finish;
- high-level remote operation;
- output file path and byte size for `secret get --output`;
- completion messages for store/read/delete workflows.

### Debug

Debug prints verbose messages plus implementation details useful for diagnosing
transport and processing:

- resolved remote protocol version;
- remote binary name;
- SSH command name;
- number of captured file payloads;
- stdin byte count when stdin is forwarded;
- original file bytes;
- prepared payload bytes;
- compression enum stored in SQLite;
- original size metadata;
- remote response stdout/stderr byte counts;
- remote response exit code;
- decompressed output byte count.

Debug must still redact sensitive data.

## Redaction and Safety Rules

The logger must never print:

- secret values;
- inline `secret set KEY VALUE` values;
- stdin contents;
- env-file values;
- file contents;
- private key material;
- public certificate body;
- encrypted secret payload bytes;
- decrypted remote payload bytes;
- full HTTP request bodies from the `request` command.

Allowed data:

- file paths;
- key names;
- workspace names or ids;
- byte counts;
- compression mode names;
- compression levels;
- remote host string;
- database path;
- command category.

File paths are considered acceptable operational metadata for this feature.

## Architecture

Introduce a small CLI logging module in `vaultick-bin`, for example
`vaultick-bin/src/commands/logging.rs`.

Suggested API:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LogLevel {
    Quiet,
    Verbose,
    Debug,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CliLogger {
    level: LogLevel,
}

impl CliLogger {
    pub(crate) fn quiet() -> Self;
    pub(crate) fn verbose(enabled: bool, debug: bool) -> Self;
    pub(crate) fn is_verbose(self) -> bool;
    pub(crate) fn is_debug(self) -> bool;
    pub(crate) fn verbose(self, message: impl AsRef<str>);
    pub(crate) fn debug(self, message: impl AsRef<str>);
}
```

The logger writes to `stderr` using `eprintln!`.

Pass `CliLogger` explicitly through command handlers rather than using global
mutable state. This keeps tests deterministic and follows the current
command-oriented style in `vaultick-bin/src/commands/mod.rs`.

## Local Flow

Root command parsing creates a logger from `cli.verbose` and `cli.debug`.

Local execution should log:

1. local mode selected;
2. resolved database path;
3. resolved workspace;
4. command-specific steps.

For `secret set --file`, logging should happen around:

- file read;
- compression preparation;
- SQLite store call.

For `secret get --output`, logging should happen around:

- raw/compressed secret read;
- decompression decision;
- output file write.

## Remote Flow

Remote mode is client-first. The local CLI prepares file payloads and compression
before starting SSH. Logging should therefore be split between:

- client-side preparation logs;
- SSH dispatch logs;
- remote-side operation logs included in the response stderr when appropriate.

Client-side remote logs:

1. remote mode selected;
2. remote destination;
3. optional remote `VAULTICK_HOME` if supplied in the remote address;
4. local file read and compression for `secret set --file`;
5. SSH command and remote binary in debug mode;
6. request sent;
7. response received;
8. local output file write for `secret get --output`.

Remote-side logging must not corrupt the JSON protocol used by `remote-stdio`.
Any remote diagnostic messages must be returned through `RemoteResponse.stderr`
or suppressed. The hidden `remote-stdio` command itself must never print
diagnostics directly to stdout.

The first implementation can keep most remote logs on the client side. Remote
server logs are only required for direct remote secret operations where they can
be safely attached to the structured `RemoteResponse.stderr`.

## Command Coverage

### Required in First Pass

- `secret set --file`
- `secret get --output`
- remote dispatch for supported `workspace`, `rsa`, and `secret` commands
- local database/workspace resolution

### Basic Coverage

These commands should at least log mode, db/workspace, and completion:

- `workspace list/create/get/delete`
- `rsa add/list/delete`
- `secret list/delete`

### Later Coverage

`exec` and `request` can start with minimal logs only. They already handle
redaction and streaming output; avoid adding detailed body/header logging in
this feature.

## Examples

### Remote Upload

Command:

```bash
vaultick --verbose secret set VIDEO_849795180209917952 \
  --file "/Users/assis/projects/rec/fansly-archive/downloads/wildtequilla/wildtequilla/849795180209917952.ts" \
  --overwrite
```

Expected `stderr` shape:

```text
[vaultick] using remote: pi@192.168.88.240
[vaultick] preparing secret file: VIDEO_849795180209917952
[vaultick] reading file: /Users/assis/projects/rec/fansly-archive/downloads/wildtequilla/wildtequilla/849795180209917952.ts (82.3 MB)
[vaultick] compression mode: try zstd level 10
[vaultick] compression result: zstd (stored payload is smaller)
[vaultick] opening SSH transport: pi@192.168.88.240
[vaultick] storing prepared file secret on remote workspace: default
[vaultick] stored secret: VIDEO_849795180209917952
```

### Remote Download

Command:

```bash
vaultick --debug secret get VIDEO_849795180209917952 --output ./video.ts
```

Expected `stderr` shape:

```text
[vaultick] using remote: pi@192.168.88.240
[vaultick] requesting raw secret payload: VIDEO_849795180209917952
[vaultick:debug] remote operation: GetRawFile
[vaultick] received remote payload
[vaultick] decompressing zstd payload
[vaultick] writing output file: ./video.ts
[vaultick] wrote output file
```

## Testing Strategy

Add unit tests for:

- Clap parses `--verbose`;
- Clap parses `--debug`;
- `--debug` implies debug logging behavior;
- logger does not print anything in quiet mode;
- logger writes verbose/debug lines to a test writer if the logger is made
  writer-injectable, or integration tests assert `stderr` otherwise.

Add `vaultick-bin` e2e tests for:

- local `secret set --file --verbose` logs file read and compression decision;
- local `secret get --output --verbose` logs output write and decompression;
- remote `secret set --file --verbose` logs remote destination, SSH dispatch,
  and client-side compression preparation;
- remote `secret get --output --debug` logs payload handling without printing
  payload bytes.

Add negative assertions:

- inline secret values do not appear in verbose/debug logs;
- env-file values do not appear in verbose/debug logs;
- file contents do not appear in verbose/debug logs.

## Acceptance Criteria

- `vaultick --help` shows `--verbose` and `--debug`.
- `vaultick --verbose secret set --file ...` prints step-by-step progress to
  stderr.
- `vaultick --debug secret set --file ...` prints verbose progress plus debug
  metadata to stderr.
- Existing stdout output remains compatible for tables and JSON.
- Remote `remote-stdio` stdout remains valid JSON protocol output.
- Large file upload to `VAULTICK_REMOTE=pi@192.168.88.240` shows enough progress
  to identify whether the CLI is reading, compressing, sending, or storing.
- No secret values or file contents are printed in logs.
- `cargo test --workspace`, `cargo fmt --all -- --check`,
  `cargo clippy --workspace --all-targets -- -D warnings`, and
  `cargo build --release` pass.
