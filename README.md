# vaultick

`vaultick` is a secret-management product for operators, platform teams and
tooling agents that need to store secrets safely, use them in CLI workflows and
forward them through HTTP services without turning terminals, prompts or logs
into a secret dump.

The two primary user-facing pieces are:

- `vaultick`: the CLI for managing secrets, RSA access, process execution and
  outbound HTTP requests
- `vaultick-proxy`: the reverse proxy service for route-based forwarding with
  secret injection and streamed redaction

`vaultick` is not only about local storage. The local database is the control
plane for secret ownership and encryption, while `vaultick-proxy` extends that
model to service and network workflows.

At the center of the project is one rule:

- secrets may be stored
- secrets may be used
- secrets should not be printed back to operators by normal management commands

## Summary

- [Why vaultick](#why-vaultick)
- [Install](#install)
- [Quick start](#quick-start)
- [CLI capabilities](#cli-capabilities)
- [vaultick-proxy](#vaultick-proxy)
- [Security model](#security-model)
- [Detailed documentation](#detailed-documentation)

## Why vaultick

`vaultick` is built for workflows like:

- storing local or team secrets in SQLite with strong encryption
- using those secrets in shell commands without echoing them back
- making HTTP requests with internal `$SECRET` substitution
- exposing a reverse proxy that injects secrets into upstream requests
- redacting secrets if they appear in child process output or upstream responses

One especially strong use case is modern development with LLM-powered tooling.

Today, development agents and coding copilots often need access to:

- API keys
- GitHub tokens
- cloud credentials
- internal service endpoints
- deployment and automation secrets

Without a layer like `vaultick`, those values tend to become fragile because
they get pushed into:

- local shell environments
- `.env` files spread across projects
- copied prompt context
- ad-hoc scripts and helper commands
- tool logs and command output

`vaultick` improves that model by letting LLM-driven workflows use secrets
through controlled interfaces instead of raw value handling:

- `vaultick exec` lets an agent run a CLI command with secrets injected only for
  that process
- `vaultick request` lets an agent call an HTTP API with secret substitution and
  redacted output
- `vaultick-proxy` lets teams expose a service boundary that injects secrets and
  redacts responses before they reach the caller

That makes `vaultick` a good fit for secure developer tooling, AI agents,
automation pipelines and service integrations that need access to sensitive
systems without normalizing plaintext secret handling.

In practice:

- operators mainly use `vaultick`
- services and deployments mainly use `vaultick-proxy`
- internal crates such as `vaultick-lib` and `vaultick-request` exist to support
  those two products

## Install

Install the CLI with the public installer:

```bash
curl -fsSL https://downloads.vaultick.dev/install.sh | sh
```

Today this installer targets the published Linux `vaultick` binary and configures
`VAULTICK_HOME="$HOME/.vaultick"`.

Build the workspace from source:

```bash
cargo build --release --workspace
```

Build the CLI only:

```bash
cargo build --release -p vaultick
```

Build the proxy only:

```bash
cargo build --release -p vaultick-proxy
```

Run without installing:

```bash
cargo run -p vaultick -- --help
cargo run -p vaultick-proxy -- --help
```

## Quick start

### 1. Configure a home directory

```bash
export VAULTICK_HOME="$HOME/.vaultick"
```

If `--db` is omitted, the CLI uses:

```text
VAULTICK_HOME/databases/database.db
```

Workspace resolution order is:

1. `--workspace <name>`
2. `VAULTICK_WORKSPACE`
3. `default`

When a new database is created, `vaultick` automatically seeds the `default`
workspace.

### 2. Create or reuse an RSA keypair

```bash
ssh-keygen -t rsa -b 4096 -f "$HOME/.ssh/id_rsa"
```

### 3. Attach a public key to the workspace

Manual flow:

```bash
vaultick rsa add --label id_rsa --cert "$HOME/.ssh/id_rsa.pub"
```

Auto-discovery flow:

```bash
vaultick rsa add --auto
```

### 4. Store secrets

Inline:

```bash
vaultick secret set GITHUB_TOKEN ghp_xxx
```

From stdin:

```bash
printf 'ghp_xxx' | vaultick secret set GITHUB_TOKEN --stdin
```

From a file:

```bash
vaultick secret set TLS_CERT --file ./cert.pem
vaultick secret set BINARY_BLOB --file ./payload.bin
```

From `.env`:

```bash
vaultick secret set --env-file .env
vaultick secret set --env-file .env --skip-existing
vaultick secret set --env-file .env --overwrite
```

### 5. Use a secret in a process

Inject selected keys:

```bash
vaultick exec --env GITHUB_TOKEN -- sh -c 'curl -s \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  https://api.github.com/user'
```

Inject everything from the workspace:

```bash
vaultick exec --all -- sh -c 'env | sort'
```

### 6. Use a secret in an HTTP request

Explicit request form:

```bash
vaultick request \
  --url https://api.github.com/user \
  --method GET \
  --header 'Authorization: Bearer $GITHUB_TOKEN' \
  --header 'Accept: application/vnd.github+json'
```

JSON request form:

```bash
vaultick request --data '{
  "url":"https://api.github.com/user",
  "method":"GET",
  "headers":{
    "Authorization":"Bearer $GITHUB_TOKEN",
    "Accept":"application/vnd.github+json"
  }
}'
```

## CLI capabilities

`vaultick` is the main operator interface.

### `workspace`

Manage logical containers of secrets and RSA certificates.

```bash
vaultick workspace create app-prod
vaultick workspace list
vaultick workspace get app-prod
vaultick workspace delete app-prod
```

### `rsa`

Manage public keys allowed to unwrap workspace secrets.

```bash
vaultick rsa add --label primary --cert ./primary.pub
vaultick rsa add --auto
vaultick rsa list
vaultick rsa delete <id-or-fingerprint>
```

### `secret`

Store secret values and inspect secret metadata.

```bash
vaultick secret set DATABASE_URL postgres://...
vaultick secret get DATABASE_URL
vaultick secret get DATABASE_URL --json
vaultick secret list
vaultick secret list --json
vaultick secret delete DATABASE_URL
```

Important behavior:

- key names are case-insensitive at the interface
- stored key names are normalized to uppercase
- `secret get` and `secret list` return metadata only
- `set` fails on conflicts unless `--overwrite` is used

### `exec`

Use `exec` when you want a child process to receive secrets as environment
variables.

Main forms:

```bash
vaultick exec --env KEY -- command ...
vaultick exec --all -- command ...
vaultick exec -- KEY='$KEY' command ...
```

The CLI captures process output and redacts known in-use secrets before printing
it back to the terminal.

### `request`

Use `request` when you want `vaultick` to perform an outbound HTTP call with
secret substitution handled internally.

Main forms:

```bash
vaultick request --url ... --method ... --header ... --body ...
vaultick request --data '{"url":"...","headers":{"Authorization":"Bearer $TOKEN"}}'
```

Supported placeholder locations:

- URL
- headers
- body

The response body is streamed to standard output only after matching secret
values have been redacted.

## vaultick-proxy

`vaultick-proxy` is the service counterpart of the CLI request flow.

It listens for inbound HTTP traffic, matches routes by path prefix, builds
upstream requests with secrets and request-context placeholders, and returns the
upstream response after redaction.

### What it does

- loads config from YAML or JSON
- supports config via `--config` or `VAULTICK_CONFIG`
- resolves `$SECRET_NAME` through the `vaultick` database
- resolves `{{request.*}}` from the incoming request
- streams upstream responses back to clients
- redacts in-use secrets in normal responses, chunked responses and SSE

### Start the proxy

```bash
vaultick-proxy --config ./vaultick-proxy.yaml
```

It can also load configuration from `VAULTICK_CONFIG` as:

- inline JSON
- inline YAML
- URL
- file path
- base64-encoded JSON or YAML

If `VAULTICK_CONFIG` is a URL, optional fetch headers may be provided with:

```bash
export VAULTICK_CONFIG_HEADERS='{"Authorization":"Bearer token"}'
```

### Minimal config example

```yaml
listen: 127.0.0.1:8080
db: /app/.vaultick/databases/database.db
workspace: default
private_key: /app/.ssh/id_rsa
routes:
  - match:
      path_prefix: /github
    forward:
      base_url: https://api.github.com
      method: "{{request.method}}"
      path: /user
      headers:
        Authorization: "Bearer $GITHUB_TOKEN"
        Accept: "application/vnd.github+json"
```

### Example run

```bash
vaultick-proxy --config ./vaultick-proxy.yaml
curl -s http://127.0.0.1:8080/github
```

### Deployment model

`vaultick-proxy` is designed to run as a service, especially in Docker or
container platforms.

Typical deployment patterns:

- mount config and start with `--config`
- inject config through `VAULTICK_CONFIG`
- mount the SQLite database and private key into the container
- publish a multi-arch proxy image from CI

## Security model

`vaultick` is deliberately conservative about secret visibility.

- `secret list` returns metadata only
- `secret get` returns metadata only
- `secret set` never echoes the stored value
- `exec` redacts secrets from child process output
- `request` redacts secrets from HTTP responses
- `vaultick-proxy` redacts secrets before sending upstream responses downstream

Private keys are never stored in SQLite. They are loaded from disk only when a
secret must be used internally.

`vaultick` reduces accidental exposure, but it does not remove the fact that a
child process or an upstream service may receive the secret if you explicitly
inject it into that workflow.

## Detailed documentation

The detailed docs live in [docs/README.md](docs/README.md).

### Main operator and deployment docs

- [vaultick CLI guide](docs/services/vaultick-cli.md)
- [vaultick-proxy guide](docs/services/vaultick-proxy.md)
- [Release and install](docs/release-install.md)
- [Secrets reference](docs/resources/secrets.md)
- [RSA reference](docs/resources/rsa.md)
- [HTTP requests and proxy forwarding](docs/resources/http.md)
- [Security model](docs/security.md)

### Technical reference

- [vaultick-lib](docs/services/vaultick-lib.md)
- [vaultick-request](docs/services/vaultick-request.md)

## Development

Run the standard validation flow:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo build --release --workspace
```
