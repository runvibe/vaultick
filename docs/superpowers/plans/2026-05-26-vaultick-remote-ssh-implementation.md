# Vaultick Remote SSH Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `vaultick -r/--remote` and `VAULTICK_REMOTE` so the local CLI can run core commands against a remote host over SSH while SQLite stays local to the remote host.

**Architecture:** The local CLI dispatches remote commands before opening SQLite. It sends an internal JSON request to `ssh <host> vaultick remote-stdio`; the remote side materializes local file payloads, runs the normal local CLI as a child process, captures stdout/stderr/status, and returns a JSON response.

**Tech Stack:** Rust 2024, clap, serde/serde_json, std::process, rusqlite-backed `vaultick` library.

---

## File Structure

- Modify `vaultick-bin/src/commands/mod.rs`: add CLI flags, hidden `remote-stdio`, dispatch hook, and tests tied to existing command parsing.
- Create `vaultick-bin/src/commands/remote.rs`: remote address parsing, argument sanitization, payload capture, SSH dispatch, protocol structs, remote child execution.
- Modify `vaultick-bin/src/commands/mod.rs` to declare `mod remote;` and call the module.
- Modify `vaultick-bin/Cargo.toml`: move `tempfile` from dev-only to normal dependency only if temporary file handling needs it.
- Add `vaultick-bin/tests/remote_e2e.rs` only if unit coverage cannot validate dispatcher behavior without a real SSH server.

## Task 1: Remote Activation And Address Parsing

**Files:**
- Modify: `vaultick-bin/src/commands/mod.rs`
- Create: `vaultick-bin/src/commands/remote.rs`

- [ ] **Step 1: Write failing tests**

Add tests for `-r`, `--remote`, `VAULTICK_REMOTE`, `--db` conflict, and address parsing:

```rust
#[test]
fn remote_flag_parses_short_and_long_forms() {
    let cli = Cli::parse_from(["vaultick", "-r", "assis@192.168.88.240:/mnt/hd/vaultick", "secret", "list"]);
    assert_eq!(cli.remote.as_deref(), Some("assis@192.168.88.240:/mnt/hd/vaultick"));
}

#[test]
fn remote_target_parses_user_host_and_home() {
    let target = remote::RemoteTarget::parse("assis@192.168.88.240:/mnt/hd/vaultick").unwrap();
    assert_eq!(target.ssh_destination, "assis@192.168.88.240");
    assert_eq!(target.vaultick_home.as_deref(), Some("/mnt/hd/vaultick"));
}
```

- [ ] **Step 2: Run red tests**

Run: `cargo test -p vaultick-bin remote`

Expected: fail because `remote` fields and module do not exist.

- [ ] **Step 3: Implement activation**

Add `remote: Option<String>` to `Cli`, `VAULTICK_REMOTE`, a hidden `remote-stdio` subcommand, and `RemoteTarget::parse`.

- [ ] **Step 4: Run green tests**

Run: `cargo test -p vaultick-bin remote`

Expected: pass.

- [ ] **Step 5: Commit**

Run:

```sh
git add vaultick-bin/src/commands/mod.rs vaultick-bin/src/commands/remote.rs
git commit -m "feat(cli): add remote ssh activation parsing"
```

## Task 2: Protocol And Argument Preparation

**Files:**
- Modify: `vaultick-bin/src/commands/remote.rs`
- Modify: `vaultick-bin/src/commands/mod.rs`

- [ ] **Step 1: Write failing tests**

Add tests for removing remote flags, rejecting unsupported `exec`/`request`, capturing `secret set --file`, capturing `secret set --env-file`, and preserving stdin for `secret set --stdin`.

- [ ] **Step 2: Run red tests**

Run: `cargo test -p vaultick-bin remote`

Expected: fail because request preparation is not implemented.

- [ ] **Step 3: Implement request preparation**

Create serializable `RemoteRequest`, `RemoteFilePayload`, and `RemoteResponse`. Implement:

- `strip_remote_args(args)`
- `prepare_remote_request(target, cli, raw_args)`
- `replace_option_value(args, option, placeholder)`
- stdin capture only when the parsed command requires stdin
- local file capture for `secret set --file`, `secret set --env-file`, `rsa add --cert`, and `rsa add --rewrap-from-key`
- clear errors for `exec` and `request` in the first implementation

- [ ] **Step 4: Run green tests**

Run: `cargo test -p vaultick-bin remote`

Expected: pass.

- [ ] **Step 5: Commit**

Run:

```sh
git add vaultick-bin/src/commands/mod.rs vaultick-bin/src/commands/remote.rs
git commit -m "feat(cli): prepare remote ssh requests"
```

## Task 3: SSH Dispatch And Remote Stdio Handler

**Files:**
- Modify: `vaultick-bin/src/commands/remote.rs`
- Modify: `vaultick-bin/src/commands/mod.rs`

- [ ] **Step 1: Write failing tests**

Add protocol round-trip tests and a fake SSH command test using `VAULTICK_REMOTE_SSH_COMMAND` to execute `vaultick remote-stdio` locally.

- [ ] **Step 2: Run red tests**

Run: `cargo test -p vaultick-bin remote`

Expected: fail because dispatch and remote handler are not wired.

- [ ] **Step 3: Implement dispatch**

Implement `dispatch_remote`, `handle_remote_stdio`, and child execution:

- local side spawns `ssh_destination vaultick remote-stdio`;
- request is written to SSH stdin as JSON;
- local side parses `RemoteResponse`;
- stdout/stderr bytes are replayed locally;
- exit code is returned;
- remote side creates temp files, replaces placeholders, sets `VAULTICK_HOME`, removes `VAULTICK_REMOTE`, runs current executable with sanitized args, and returns captured output.

- [ ] **Step 4: Run green tests**

Run: `cargo test -p vaultick-bin remote`

Expected: pass.

- [ ] **Step 5: Commit**

Run:

```sh
git add vaultick-bin/src/commands/mod.rs vaultick-bin/src/commands/remote.rs
git commit -m "feat(cli): execute remote ssh commands"
```

## Task 4: Verification And Publication

**Files:**
- Modify: `docs/superpowers/plans/2026-05-26-vaultick-remote-ssh-implementation.md`

- [ ] **Step 1: Run CLI crate tests**

Run: `cargo test -p vaultick-bin`

Expected: pass.

- [ ] **Step 2: Run workspace verification**

Run:

```sh
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo build --release
```

Expected: all pass.

- [ ] **Step 3: Commit plan and final fixes**

Run:

```sh
git add docs/superpowers/plans/2026-05-26-vaultick-remote-ssh-implementation.md
git commit -m "docs: add remote ssh implementation plan"
```

- [ ] **Step 4: Push branch and update PR**

Run:

```sh
git push
```

Expected: branch updates PR #2.

## Self-Review

- Spec coverage: activation, SSH stdio, local file/stdin handling, no daemon, no SQLite over network, errors, and core command scope are covered.
- Scope decision: `workspace`, `rsa`, and `secret` are supported first; `exec` and `request` fail clearly in remote mode.
- Placeholder scan: no TBD/TODO placeholders.
