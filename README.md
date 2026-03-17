# vaultick

`vaultick` is a secret-management stack built to store secrets locally, use them
in CLIs and HTTP workflows, and avoid revealing their raw values during normal
operations.

At the center of the project is a simple rule:

- secrets may be stored
- secrets may be used
- secrets should not be printed back to the user by management commands

## What vaultick includes

The workspace is split into four parts:

- `vaultick-lib`: encrypted storage, SQLite persistence, RSA access control and
  secret lifecycle rules
- `vaultick`: the CLI for workspaces, RSA certificates, secret management,
  process execution and outbound HTTP requests
- `vaultick-request`: the shared Rust library that resolves `$SECRET`
  placeholders, executes HTTP requests and redacts responses
- `vaultick-proxy`: a reverse proxy service that forwards requests to upstreams,
  injects secrets and redacts streamed responses

## Main resources

The project revolves around a few core concepts:

- `workspace`: a logical namespace for certificates and secrets
- `rsa certificate`: a public key allowed to decrypt secret envelopes inside a
  workspace
- `secret`: a key/value entry stored encrypted in SQLite
- `request`: an outbound HTTP invocation that may resolve secrets internally
- `proxy route`: a config-driven mapping from an incoming request to an upstream
  target

## Security model

`vaultick` is intentionally opinionated:

- `secret list` returns metadata only
- `secret get` returns metadata for a single key only
- `secret set` never prints the stored value
- `exec` injects secrets into a child process and redacts known secret values
  from `stdout` and `stderr`
- `request` resolves secrets internally and redacts matching values from the
  response body, including streaming output
- `vaultick-proxy` does the same redaction before returning upstream responses
  to clients

The private key is not stored in SQLite. It is read from disk only when the
system needs to decrypt a secret for an internal operation.

## Quick start

### 1. Set a home directory

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

When a new database is created, `vaultick` automatically creates the
`default` workspace.

### 2. Create or reuse an RSA keypair

```bash
ssh-keygen -t rsa -b 4096 -f "$HOME/.ssh/id_rsa"
```

### 3. Attach the public key to a workspace

```bash
vaultick rsa add --label id_rsa --cert "$HOME/.ssh/id_rsa.pub"
```

### 4. Store a secret

```bash
vaultick secret set GITHUB_TOKEN ghp_xxx
```

### 5. Use the secret inside a process

```bash
vaultick exec --env GITHUB_TOKEN -- sh -c 'curl -s \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  https://api.github.com/user'
```

### 6. Use the secret in an HTTP request

```bash
vaultick request \
  --url https://api.github.com/user \
  --header 'Authorization: Bearer $GITHUB_TOKEN' \
  --header 'Accept: application/vnd.github+json'
```

## Main capabilities

### Secret storage

- SQLite-backed local storage
- AES-256-GCM for secret payloads
- per-secret wrapped data encryption keys
- workspace isolation
- secret keys normalized to uppercase
- support for string values, `stdin`, `.env` imports and binary files

### Access control

- RSA public keys attached to workspaces
- secrets may be opened by matching private keys only
- support for multiple certificates per workspace
- rewrap flow for new certificates in workspaces with existing secrets

### Safe consumption

- `exec --env` to inject selected secrets into a child process
- `exec --all` to inject all workspace secrets
- `request` to perform outbound HTTP calls with internal secret substitution
- `vaultick-proxy` to expose a reverse proxy with route-based transformations

### Response redaction

- CLI process output is redacted when it contains a known in-use secret
- HTTP responses are redacted before reaching the user
- streamed responses and SSE are redacted incrementally

## Documentation map

The detailed documentation lives in `docs/`.

### Overview

- [Documentation index](docs/README.md)
- [Security model](docs/security.md)

### Services

- [vaultick-lib](docs/services/vaultick-lib.md)
- [vaultick CLI](docs/services/vaultick-cli.md)
- [vaultick-request](docs/services/vaultick-request.md)
- [vaultick-proxy](docs/services/vaultick-proxy.md)

### Resources

- [Secrets](docs/resources/secrets.md)
- [RSA certificates](docs/resources/rsa.md)
- [HTTP requests and proxy forwarding](docs/resources/http.md)

## Development

Run the standard validation flow:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo build --release --workspace
```

## Repository layout

```text
vaultick/             vaultick-lib crate
vaultick-bin/         vaultick CLI crate
vaultick-request/     shared request/redaction crate
vaultick-proxy/       reverse proxy service
docs/                 project documentation
```
