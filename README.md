# vaultick

`vaultick` is a local-first secret manager for Rust projects and shell workflows.
It stores encrypted secrets in SQLite, protects each secret with a random data
encryption key, and wraps that key for one or more RSA certificates attached to a
workspace.

The project is split into:

- `vaultick-lib`: the Rust library with persistence, crypto and validation rules
- `vaultick`: the CLI used to manage workspaces, RSA certificates and secrets

## Security model

`vaultick` is designed to avoid printing secret values directly.

- `secret list` returns metadata only
- `secret get` returns metadata for a single key only
- `secret set` never prints secret values
- `exec` injects secrets into a child process and redacts known secret values from
  `stdout` and `stderr`, including streaming output

The private key is never stored in SQLite. It is only loaded from disk when
needed to decrypt secrets for internal operations such as `exec`.

## Install

Build from source:

```bash
cargo build --release -p vaultick
```

Run without installing:

```bash
cargo run -p vaultick -- --help
```

Install the CLI locally:

```bash
cargo install --path vaultick-bin
```

## Defaults

If `--db` is omitted, `vaultick` uses:

```text
VAULTICK_HOME/databases/database.db
```

If `VAULTICK_HOME` is not set, the CLI fails with guidance. A typical setup is:

```bash
export VAULTICK_HOME="$HOME/.vaultick"
```

Workspace resolution order:

1. `--workspace <name>`
2. `VAULTICK_WORKSPACE`
3. `default`

When a new database is created, `vaultick` also creates a `default` workspace.

Legacy env vars `VALTICK_HOME` and `VALTICK_WORKSPACE` are still accepted as
fallbacks.

## Quick start

Generate an RSA keypair if you do not already have one:

```bash
ssh-keygen -t rsa -b 4096 -f "$HOME/.ssh/id_rsa"
```

Add your public key to the default workspace:

```bash
vaultick rsa add --label id_rsa --cert "$HOME/.ssh/id_rsa.pub"
```

Store a secret:

```bash
vaultick secret set GITHUB_TOKEN ghp_xxx
```

Use the secret inside a process:

```bash
vaultick exec --env GITHUB_TOKEN -- sh -c 'curl -s \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  https://api.github.com/user'
```

## Commands

### Workspace

Create, inspect and remove logical groups of certificates and secrets.

```bash
vaultick workspace create app-prod
vaultick workspace list
vaultick workspace get app-prod
vaultick workspace delete app-prod
```

### RSA

Manage the public keys allowed to decrypt secrets in a workspace.

Manual add:

```bash
vaultick rsa add --label primary --cert ./public.pem
```

Auto-discovery from `~/.ssh`:

```bash
vaultick rsa add --auto
```

List and delete:

```bash
vaultick rsa list
vaultick rsa delete <certificate-id-or-fingerprint>
```

### Secret

Store and manage secret metadata.

Set a single value:

```bash
vaultick secret set GITHUB_TOKEN ghp_xxx
```

Set from stdin:

```bash
printf 'ghp_xxx' | vaultick secret set GITHUB_TOKEN --stdin
```

Set from a text or binary file:

```bash
vaultick secret set TLS_CERT --file ./cert.pem
vaultick secret set SERVICE_ACCOUNT --file ./service-account.json
vaultick secret set BINARY_BLOB --file ./payload.bin
```

Set from an env file:

```bash
vaultick secret set --env-file .env
```

Skip existing keys during import:

```bash
vaultick secret set --env-file .env --skip-existing
```

Overwrite existing keys during import:

```bash
vaultick secret set --env-file .env --overwrite
```

Get metadata only:

```bash
vaultick secret get GITHUB_TOKEN
vaultick secret list
```

Delete a key:

```bash
vaultick secret delete GITHUB_TOKEN
```

Behavior notes:

- secret keys are case-insensitive at the interface
- keys are always normalized and stored as uppercase
- by default `secret set` fails if the key already exists
- pass `-o` or `--overwrite` to replace an existing key
- `--overwrite` and `--skip-existing` are mutually exclusive on `--env-file`

### Exec

`exec` is the main way to consume secrets.

Inject specific secrets:

```bash
vaultick exec --env GITHUB_TOKEN --env AWS_ACCESS_KEY_ID -- aws sts get-caller-identity
```

Inject all workspace secrets:

```bash
vaultick exec --all -- env
```

Use explicit leading assignments:

```bash
vaultick exec -- AWS_ACCESS_KEY_ID='$AWS_ACCESS_KEY_ID' aws sts get-caller-identity
```

Important shell note:

- `vaultick exec --env GITHUB_TOKEN -- echo "$GITHUB_TOKEN"` does not do what
  you want, because your current shell expands the variable before `vaultick`
- prefer `sh -c 'echo "$GITHUB_TOKEN"'` when you need expansion inside the
  child process

Example:

```bash
vaultick exec --env GITHUB_TOKEN -- sh -c 'echo "$GITHUB_TOKEN"'
```

If the child process prints a known secret, `vaultick` replaces it with:

```text
[REDACTED]
```

## Development

Run the full local validation suite:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo build --release --workspace
```

The repository also includes:

- CI workflow for formatting, clippy, tests and release build
- release workflow for cross-platform `vaultick` binaries and crates.io publish
