# Secrets

Secrets are the main stored resource in `vaultick`.

Each secret belongs to exactly one workspace and is identified by a normalized
key name.

## Key naming

At the interface, keys are case-insensitive.

Examples:

- `github_token`
- `GITHUB_TOKEN`
- `Github_Token`

All of them resolve to the same stored key:

```text
GITHUB_TOKEN
```

## How secrets are stored

Secret values are encrypted before they reach SQLite.

The library stores:

- metadata
- ciphertext
- nonce
- wrapped data encryption keys per authorized RSA certificate

The CLI does not expose the raw value during normal inspection commands.

## Secret creation modes

### Inline value

```bash
vaultick secret set GITHUB_TOKEN ghp_xxx
```

### Standard input

```bash
printf 'ghp_xxx' | vaultick secret set GITHUB_TOKEN --stdin
```

### File input

```bash
vaultick secret set TLS_CERT --file ./cert.pem
vaultick secret set BINARY_BLOB --file ./payload.bin
```

### Env-file import

```bash
vaultick secret set --env-file .env
```

Supported env-file behavior:

- comments are ignored
- empty lines are ignored
- `export KEY=VALUE` is accepted
- later duplicate keys in the same file win

## Conflict policy

By default, `secret set` does not overwrite an existing key.

Options:

- `--overwrite`: replace an existing value
- `--skip-existing`: only for `--env-file`, keep existing keys and import the
  rest

Without either flag, a conflicting import fails early.

## Inspection

Inspection is metadata-only.

### Single key

```bash
vaultick secret get GITHUB_TOKEN
vaultick secret get GITHUB_TOKEN --json
```

### All keys

```bash
vaultick secret list
vaultick secret list --json
```

Returned metadata includes:

- `id`
- `workspace_id`
- `key`
- `created_at`
- `updated_at`

## Deletion

```bash
vaultick secret delete GITHUB_TOKEN
```

Deleting a secret removes:

- its metadata row
- its ciphertext
- all recipient envelopes linked to it
