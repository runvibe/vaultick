# Vaultick Hardening And Architecture Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden resource handling, align repo conventions with implementation, reduce CLI coupling, and keep release metadata/contracts consistent.

**Architecture:** Make behavior changes behind small config/model additions first, with failing tests for each exposed limit. Keep transport in `routes/`, reusable behavior in `services/` or focused helper modules, and data contracts in `models/`. Refactor the CLI mechanically after behavior is protected by tests.

**Tech Stack:** Rust 2024, Cargo workspace, Axum 0.8, Reqwest 0.13, Rusqlite, Clap, Tokio, Serde JSON/YAML.

---

## File Structure

Planned files:

- Modify: `vaultick-proxy/src/models.rs`
  - Add proxy resource-limit fields to config, resolved settings, and shared state.
- Modify: `vaultick-proxy/src/services.rs`
  - Enforce proxy request body limits and add unit coverage for config defaults.
- Modify: `vaultick-proxy/tests/e2e.rs`
  - Add an over-limit request test.
- Modify: `vaultick-mcp/src/models.rs`
  - Add MCP body/output limit settings.
- Modify: `vaultick-mcp/src/services.rs`
  - Enforce JSON-RPC body limits.
- Modify: `vaultick-mcp/src/runtime.rs`
  - Add bounded redacted collection for exec stdout/stderr and HTTP response bodies.
- Modify: `vaultick-mcp/tests/e2e.rs`
  - Add body/output limit tests.
- Create: `vaultick-lib/migrations/0001_initial.sql`
  - Move initial schema out of inline Rust string.
- Modify: `vaultick-lib/src/lib.rs`
  - Load schema from migration file and set `PRAGMA user_version`.
- Modify: `AGENTS.md`
  - Align persistence guidance with current rusqlite + migrations reality, unless a separate SQLx migration is explicitly approved.
- Create: `PROJECT.md`
  - Document current change/release conventions referenced by `AGENTS.md`.
- Modify: `Cargo.toml`
  - Align local dependency versions with the workspace package version.
- Modify: `vaultick-bin/src/main.rs`
  - Reduce to module wiring after split.
- Create: `vaultick-bin/src/cli.rs`
  - Own Clap structs/enums only.
- Create: `vaultick-bin/src/config.rs`
  - Own DB path and workspace resolution.
- Create: `vaultick-bin/src/commands/mod.rs`
  - Export command modules.
- Create: `vaultick-bin/src/commands/workspace.rs`
  - Own workspace command handlers.
- Create: `vaultick-bin/src/commands/rsa.rs`
  - Own RSA discovery/normalization and command handlers.
- Create: `vaultick-bin/src/commands/secret.rs`
  - Own secret set/get/list/delete parsing and handlers.
- Create: `vaultick-bin/src/commands/exec.rs`
  - Own process invocation resolution and execution.
- Create: `vaultick-bin/src/commands/request.rs`
  - Own HTTP request invocation resolution and execution.

## Task 1: Baseline Guardrail

**Files:**
- Read only: full workspace

- [ ] **Step 1: Confirm clean starting state**

Run:

```bash
git status --short --branch
```

Expected:

```text
## main...origin/main
```

- [ ] **Step 2: Run current verification before edits**

Run:

```bash
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: all commands pass.

- [ ] **Step 3: Commit only if this task introduced repo metadata**

If no files changed, do not commit. If test cache or generated files appear, do not stage them.

## Task 2: Proxy Request Body Limit

**Files:**
- Modify: `vaultick-proxy/src/models.rs`
- Modify: `vaultick-proxy/src/services.rs`
- Modify: `vaultick-proxy/tests/e2e.rs`

- [ ] **Step 1: Write the failing E2E test**

Add this test in `vaultick-proxy/tests/e2e.rs` near the existing proxy error tests:

```rust
#[tokio::test]
async fn proxy_rejects_request_body_over_configured_limit() {
    let upstream = spawn_echo_server().await;
    let env = ProxyTestEnv::new();
    let listen_addr = random_listen_addr();
    let config_path = env.write_config(&format!(
        r#"
listen: "{listen_addr}"
db: "{}"
workspace: default
private_key: "{}"
max_request_body_bytes: 4
routes:
  - match:
      path_prefix: /echo
    forward:
      base_url: "{}"
      path: /echo
"#,
        env.db_path.display(),
        env.private_key_path.display(),
        upstream.url("")
    ));

    let mut child = spawn_proxy_from_config(&config_path).await;
    wait_for_http(&format!("http://{listen_addr}/echo")).await;

    let response = reqwest::Client::new()
        .post(format!("http://{listen_addr}/echo"))
        .body("12345")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
    assert!(response.text().await.unwrap().contains("request body too large"));
    stop_child(&mut child);
}
```

- [ ] **Step 2: Run the failing test**

Run:

```bash
cargo test -p vaultick-proxy --test e2e proxy_rejects_request_body_over_configured_limit
```

Expected: FAIL because `max_request_body_bytes` is not deserialized or enforced.

- [ ] **Step 3: Add the model fields**

In `vaultick-proxy/src/models.rs`, add:

```rust
pub const DEFAULT_MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyConfigFile {
    pub listen: String,
    pub db: Option<PathBuf>,
    pub workspace: Option<String>,
    pub private_key: Option<PathBuf>,
    #[serde(default)]
    pub max_request_body_bytes: Option<usize>,
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
}

#[derive(Debug, Clone)]
pub struct ResolvedSettings {
    pub listen: String,
    pub db_path: PathBuf,
    pub workspace: String,
    pub private_key_path: PathBuf,
    pub max_request_body_bytes: usize,
    pub routes: Vec<RouteConfig>,
}

#[derive(Debug)]
pub struct AppState {
    pub client: AsyncClient,
    pub max_request_body_bytes: usize,
    pub routes: Vec<CompiledRoute>,
}
```

- [ ] **Step 4: Wire settings and state**

In `vaultick-proxy/src/services.rs`, import the constant:

```rust
use crate::models::{
    AppState, CompiledRoute, DEFAULT_MAX_REQUEST_BODY_BYTES, ProxyConfigFile, RequestContext,
    ResolvedSettings, RouteConfig, SharedAppState, StartupOverrides,
};
```

Set the resolved field:

```rust
let max_request_body_bytes = file_config
    .max_request_body_bytes
    .unwrap_or(DEFAULT_MAX_REQUEST_BODY_BYTES);
```

Include it in `ResolvedSettings` and `AppState`.

- [ ] **Step 5: Enforce the limit**

Replace:

```rust
let body_bytes = to_bytes(body, usize::MAX).await.map_err(|err| {
```

with:

```rust
let body_bytes = to_bytes(body, state.max_request_body_bytes)
    .await
    .map_err(|err| {
        let message = err.to_string();
        if message.contains("length limit") {
            (
                StatusCode::PAYLOAD_TOO_LARGE,
                format!(
                    "request body too large; limit is {} bytes",
                    state.max_request_body_bytes
                ),
            )
        } else {
            (
                StatusCode::BAD_REQUEST,
                format!("failed to read request body: {err}"),
            )
        }
    })?;
```

- [ ] **Step 6: Verify proxy tests**

Run:

```bash
cargo test -p vaultick-proxy
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add vaultick-proxy/src/models.rs vaultick-proxy/src/services.rs vaultick-proxy/tests/e2e.rs
git commit -m "fix(proxy): bound request body size"
```

## Task 3: MCP Input And Output Limits

**Files:**
- Modify: `vaultick-mcp/src/models.rs`
- Modify: `vaultick-mcp/src/services.rs`
- Modify: `vaultick-mcp/src/runtime.rs`
- Modify: `vaultick-mcp/tests/e2e.rs`

- [ ] **Step 1: Add failing MCP JSON-RPC body limit test**

Add an E2E test that starts `vaultick-mcp` with a config containing:

```yaml
listen: "127.0.0.1:0"
token: "test-token"
db: "/tmp/test.db"
workspace: default
private_key: "/tmp/id_rsa"
max_jsonrpc_body_bytes: 16
```

Send a POST `/mcp` request with a body longer than 16 bytes and assert:

```rust
assert_eq!(response.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
assert!(response.text().await.unwrap().contains("JSON-RPC body too large"));
```

- [ ] **Step 2: Add failing MCP output limit test**

Add an E2E test that allowlists a local command producing more than 8 bytes:

```json
{
  "name": "vaultick.exec",
  "arguments": {
    "program": "printf",
    "args": ["123456789"],
    "stream": false
  }
}
```

Configure:

```yaml
max_tool_output_bytes: 8
exec_allowlist:
  - printf
```

Assert the tool response has `isError: true` and includes:

```text
tool output exceeded limit of 8 bytes
```

- [ ] **Step 3: Run failing tests**

Run:

```bash
cargo test -p vaultick-mcp --test e2e mcp_rejects_jsonrpc_body_over_configured_limit
cargo test -p vaultick-mcp --test e2e mcp_exec_rejects_output_over_configured_limit
```

Expected: FAIL because limits do not exist yet.

- [ ] **Step 4: Add MCP limit models**

In `vaultick-mcp/src/models.rs`, add:

```rust
pub const DEFAULT_MAX_JSONRPC_BODY_BYTES: usize = 1024 * 1024;
pub const DEFAULT_MAX_TOOL_OUTPUT_BYTES: usize = 1024 * 1024;
```

Extend `McpConfigFile`:

```rust
#[serde(default)]
pub max_jsonrpc_body_bytes: Option<usize>,
#[serde(default)]
pub max_tool_output_bytes: Option<usize>,
```

Extend `ResolvedSettings`:

```rust
pub max_jsonrpc_body_bytes: usize,
pub max_tool_output_bytes: usize,
```

- [ ] **Step 5: Resolve MCP limits**

In `vaultick-mcp/src/services.rs`, import the constants and add:

```rust
let max_jsonrpc_body_bytes = file_config
    .max_jsonrpc_body_bytes
    .unwrap_or(DEFAULT_MAX_JSONRPC_BODY_BYTES);
let max_tool_output_bytes = file_config
    .max_tool_output_bytes
    .unwrap_or(DEFAULT_MAX_TOOL_OUTPUT_BYTES);
```

Include both fields in `ResolvedSettings`.

- [ ] **Step 6: Enforce JSON-RPC body size**

Replace:

```rust
let body_bytes = match axum::body::to_bytes(request.into_body(), usize::MAX).await {
```

with:

```rust
let body_bytes = match axum::body::to_bytes(
    request.into_body(),
    state.settings.max_jsonrpc_body_bytes,
)
.await
{
```

Return `StatusCode::PAYLOAD_TOO_LARGE` with `JSON-RPC body too large` when the Axum limit error is hit.

- [ ] **Step 7: Add bounded collectors**

In `vaultick-mcp/src/runtime.rs`, add:

```rust
fn extend_with_limit(
    output: &mut Vec<u8>,
    chunk: &[u8],
    limit: usize,
) -> Result<(), io::Error> {
    if output.len().saturating_add(chunk.len()) > limit {
        return Err(io::Error::other(format!(
            "tool output exceeded limit of {limit} bytes"
        )));
    }

    output.extend_from_slice(chunk);
    Ok(())
}
```

Change `run_exec_execution` to accept `max_output_bytes: usize`, pass it into both redacted output readers, and use `extend_with_limit` for every redacted chunk and final tail.

Change `collect_request_result` to accept `max_output_bytes: usize` and use `extend_with_limit` before appending body chunks.

- [ ] **Step 8: Wire runtime call sites**

In `vaultick-mcp/src/services.rs`, call:

```rust
run_exec_execution(&execution, state.settings.max_tool_output_bytes)
```

and:

```rust
execute_request(
    &state.client,
    &execution,
    state.settings.max_tool_output_bytes,
    |_| {},
)
```

For SSE request execution, pass the same limit into the spawned task.

- [ ] **Step 9: Verify MCP tests**

Run:

```bash
cargo test -p vaultick-mcp
```

Expected: PASS.

- [ ] **Step 10: Commit**

```bash
git add vaultick-mcp/src/models.rs vaultick-mcp/src/services.rs vaultick-mcp/src/runtime.rs vaultick-mcp/tests/e2e.rs
git commit -m "fix(mcp): bound input and tool output sizes"
```

## Task 4: Versioned Rusqlite Migrations And Agent Docs

**Files:**
- Create: `vaultick-lib/migrations/0001_initial.sql`
- Modify: `vaultick-lib/src/lib.rs`
- Modify: `AGENTS.md`
- Create: `PROJECT.md`

- [ ] **Step 1: Add migration file**

Move the current `SCHEMA` SQL from `vaultick-lib/src/lib.rs` into `vaultick-lib/migrations/0001_initial.sql` and append:

```sql
PRAGMA user_version = 1;
```

- [ ] **Step 2: Update schema loading**

In `vaultick-lib/src/lib.rs`, replace the inline schema constant with:

```rust
const INITIAL_SCHEMA: &str = include_str!("../migrations/0001_initial.sql");
```

Keep `init_schema` behavior equivalent, but execute `INITIAL_SCHEMA`.

- [ ] **Step 3: Add migration regression test**

Add a unit test in `vaultick-lib/src/lib.rs`:

```rust
#[test]
fn new_database_records_schema_version() {
    let store = Vaultick::open(":memory:").unwrap();
    let version: i64 = store
        .conn
        .borrow()
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();

    assert_eq!(version, 1);
}
```

- [ ] **Step 4: Run focused test**

Run:

```bash
cargo test -p vaultick new_database_records_schema_version
```

Expected: PASS.

- [ ] **Step 5: Align AGENTS persistence/process instructions**

Change the persistence bullet in `AGENTS.md` from SQLx-specific guidance to:

```markdown
- **Persistence**: the current storage layer uses `rusqlite`; keep schema
  changes in `vaultick-lib/migrations/`, load them from `vaultick-lib`, use
  bound parameters, and avoid inline schema drift. Do not migrate to SQLx
  without a dedicated migration plan.
```

Keep the release build/push instruction unchanged.

- [ ] **Step 6: Add PROJECT conventions**

Create `PROJECT.md`:

```markdown
# Project Conventions

## Change Flow

- Keep route handlers focused on HTTP transport and delegate reusable behavior to services or focused modules.
- Add regression tests before behavior changes.
- Run `cargo test --workspace`, `cargo fmt --all -- --check`, and `cargo clippy --workspace --all-targets -- -D warnings` before opening review.

## Release Flow

- Release asset names must stay aligned across `.github/workflows/release.yml`, `install.sh`, `release-metadata.json`, and docs.
- After implementation work, run `cargo build --release`.
- If the release build succeeds and the change is intended for publication, commit and push the branch.
```

- [ ] **Step 7: Verify docs and library**

Run:

```bash
cargo test -p vaultick
cargo fmt --all -- --check
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add AGENTS.md PROJECT.md vaultick-lib/src/lib.rs vaultick-lib/migrations/0001_initial.sql
git commit -m "chore: document persistence and project conventions"
```

## Task 5: Split CLI Main Into Focused Modules

**Files:**
- Modify: `vaultick-bin/src/main.rs`
- Create: `vaultick-bin/src/cli.rs`
- Create: `vaultick-bin/src/config.rs`
- Create: `vaultick-bin/src/commands/mod.rs`
- Create: `vaultick-bin/src/commands/workspace.rs`
- Create: `vaultick-bin/src/commands/rsa.rs`
- Create: `vaultick-bin/src/commands/secret.rs`
- Create: `vaultick-bin/src/commands/exec.rs`
- Create: `vaultick-bin/src/commands/request.rs`

- [ ] **Step 1: Capture behavior before moving code**

Run:

```bash
cargo test -p vaultick-bin
```

Expected: PASS.

- [ ] **Step 2: Create module shell**

Make `vaultick-bin/src/main.rs` start with:

```rust
mod cli;
mod commands;
mod config;

fn main() {
    match commands::run() {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    }
}
```

- [ ] **Step 3: Move Clap types to `cli.rs`**

Move `Cli`, `Command`, all `*Command` and `*Subcommand` structs/enums, `ExecCommand`, `RequestCommand`, `ResolvedSecretSetInput`, `ResolvedSecretSetRequest`, `ResolvedRequestInvocation`, and `RequestDataInput` into `vaultick-bin/src/cli.rs`.

Mark the types used outside the module as `pub(crate)`.

- [ ] **Step 4: Move DB/workspace helpers to `config.rs`**

Move these constants and functions into `vaultick-bin/src/config.rs`:

```rust
pub(crate) const DEFAULT_WORKSPACE_NAME: &str = "default";
pub(crate) const DEFAULT_DB_DIRECTORY: &str = "databases";
pub(crate) const DEFAULT_DB_FILENAME: &str = "database.db";
pub(crate) const VAULTICK_HOME_ENV_VAR: &str = "VAULTICK_HOME";
pub(crate) const VAULTICK_WORKSPACE_ENV_VAR: &str = "VAULTICK_WORKSPACE";

pub(crate) fn resolve_db_path(cli_db: Option<PathBuf>) -> Result<PathBuf, io::Error>;
pub(crate) fn resolve_workspace_ref(
    vaultick: &Vaultick,
    cli_workspace: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>>;
pub(crate) fn parse_positive_usize(input: &str) -> Result<usize, String>;
```

- [ ] **Step 5: Move workspace handlers**

Create `vaultick-bin/src/commands/workspace.rs` with:

```rust
pub(crate) fn handle_workspace(
    vaultick: &Vaultick,
    command: WorkspaceSubcommand,
) -> Result<(), Box<dyn std::error::Error>>;
```

Move only workspace rendering and handlers there.

- [ ] **Step 6: Move RSA handlers**

Create `vaultick-bin/src/commands/rsa.rs` with:

```rust
pub(crate) fn handle_rsa(
    vaultick: &Vaultick,
    workspace_ref: &str,
    command: RsaSubcommand,
) -> Result<(), Box<dyn std::error::Error>>;
```

Move RSA public key normalization, auto discovery, fingerprint helpers, and RSA command handlers there.

- [ ] **Step 7: Move secret handlers**

Create `vaultick-bin/src/commands/secret.rs` with:

```rust
pub(crate) fn handle_secret(
    vaultick: &Vaultick,
    workspace_ref: &str,
    command: SecretSubcommand,
) -> Result<(), Box<dyn std::error::Error>>;
```

Move env-file parsing, secret input resolution, metadata rendering, and secret command handlers there.

- [ ] **Step 8: Move exec handlers**

Create `vaultick-bin/src/commands/exec.rs` with:

```rust
pub(crate) fn handle_exec(
    vaultick: &Vaultick,
    workspace_ref: &str,
    command: ExecCommand,
) -> Result<i32, Box<dyn std::error::Error>>;
```

Move exec invocation resolution, command spawning, and redacted process output helpers there.

- [ ] **Step 9: Move request handlers**

Create `vaultick-bin/src/commands/request.rs` with:

```rust
pub(crate) fn handle_request(
    vaultick: &Vaultick,
    workspace_ref: &str,
    command: RequestCommand,
) -> Result<i32, Box<dyn std::error::Error>>;
```

Move request data parsing, placeholder resolution, request execution, and redacted output handling there.

- [ ] **Step 10: Build command dispatcher**

Create `vaultick-bin/src/commands/mod.rs`:

```rust
pub(crate) mod exec;
pub(crate) mod request;
pub(crate) mod rsa;
pub(crate) mod secret;
pub(crate) mod workspace;

use clap::Parser;
use vaultick::Vaultick;

use crate::cli::{Cli, Command};
use crate::config::{resolve_db_path, resolve_workspace_ref};

pub(crate) fn run() -> Result<i32, Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let db_path = resolve_db_path(cli.db)?;
    let vaultick = Vaultick::open(&db_path)?;

    match cli.command {
        Command::Workspace(command) => workspace::handle_workspace(&vaultick, command.command)?,
        Command::Rsa(command) => {
            let workspace_ref = resolve_workspace_ref(&vaultick, cli.workspace.as_deref())?;
            rsa::handle_rsa(&vaultick, &workspace_ref, command.command)?;
        }
        Command::Secret(command) => {
            let workspace_ref = resolve_workspace_ref(&vaultick, cli.workspace.as_deref())?;
            secret::handle_secret(&vaultick, &workspace_ref, command.command)?;
        }
        Command::Exec(command) => {
            let workspace_ref = resolve_workspace_ref(&vaultick, cli.workspace.as_deref())?;
            return exec::handle_exec(&vaultick, &workspace_ref, command);
        }
        Command::Request(command) => {
            let workspace_ref = resolve_workspace_ref(&vaultick, cli.workspace.as_deref())?;
            return request::handle_request(&vaultick, &workspace_ref, command);
        }
    }

    Ok(0)
}
```

- [ ] **Step 11: Move tests with the code they target**

Move existing unit tests from `main.rs` into the module that owns the tested function. Keep E2E tests unchanged.

- [ ] **Step 12: Verify CLI package**

Run:

```bash
cargo test -p vaultick-bin
cargo fmt --all -- --check
cargo clippy -p vaultick-bin --all-targets -- -D warnings
```

Expected: PASS.

- [ ] **Step 13: Commit**

```bash
git add vaultick-bin/src
git commit -m "refactor(cli): split command handlers into modules"
```

## Task 6: Release Metadata And Dependency Alignment

**Files:**
- Modify: `Cargo.toml`
- Read: `.github/workflows/release.yml`
- Read: `install.sh`
- Read: `release-metadata.json`
- Read: `docs/release-install.md`

- [ ] **Step 1: Align internal workspace dependency versions**

In root `Cargo.toml`, change:

```toml
vaultick = { version = "0.0.1-alpha.0", path = "vaultick-lib" }
vaultick-request = { version = "0.0.1-alpha.0", path = "vaultick-request" }
```

to:

```toml
vaultick = { version = "0.0.1-alpha.2", path = "vaultick-lib" }
vaultick-request = { version = "0.0.1-alpha.2", path = "vaultick-request" }
```

- [ ] **Step 2: Confirm release asset names still match**

Run:

```bash
rg -n "vaultick-(proxy-)?(linux|macos|windows)|release-metadata|install.sh|asset" .github/workflows/release.yml install.sh release-metadata.json docs README.md
```

Expected: Linux asset names match `vaultick-linux-amd64`, `vaultick-linux-arm64`, `vaultick-proxy-linux-amd64`, and `vaultick-proxy-linux-arm64`.

- [ ] **Step 3: Verify workspace metadata**

Run:

```bash
cargo metadata --no-deps --format-version 1 >/tmp/vaultick-metadata.json
python -m json.tool release-metadata.json >/dev/null
sh -n install.sh
```

Expected: all commands exit 0.

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml
git commit -m "chore: align workspace dependency versions"
```

## Task 7: Final Verification And Release Build

**Files:**
- Read only unless failures require fixes.

- [ ] **Step 1: Run full verification**

Run:

```bash
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: PASS.

- [ ] **Step 2: Run required release build**

Run:

```bash
cargo build --release
```

Expected: PASS.

- [ ] **Step 3: Inspect final diff**

Run:

```bash
git status --short --branch
git log --oneline -n 8
```

Expected: working tree clean after commits, branch contains the task commits.

- [ ] **Step 4: Push**

Run:

```bash
git push origin HEAD
```

Expected: push succeeds.

## Self-Review

- Spec coverage: covers resource limits, persistence/process documentation mismatch, missing `PROJECT.md`, CLI decomposition, dependency version mismatch, and release verification.
- Placeholder scan: no `TBD`, no unspecified tests, and every behavioral task includes exact commands and expected outcomes.
- Type consistency: proxy and MCP limit field names are consistent across config, resolved settings, and state.

