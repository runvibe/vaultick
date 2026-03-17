# vaultick CLI

`vaultick` is the main operator interface of the project.

Use it when you want to:

- create or select workspaces
- register RSA readers
- store secrets safely
- inject secrets into shell commands
- make HTTP requests without revealing stored values

## Runtime defaults

### Database resolution

If `--db` is passed, that path is used directly.

Otherwise the CLI uses:

```text
VAULTICK_HOME/databases/database.db
```

If `VAULTICK_HOME` is missing, the CLI fails with guidance instead of guessing a
path.

### Workspace resolution

The workspace is resolved in this order:

1. `--workspace`
2. `VAULTICK_WORKSPACE`
3. `default`

## Recommended operator flow

### 1. Configure home and workspace

```bash
export VAULTICK_HOME="$HOME/.vaultick"
export VAULTICK_WORKSPACE=default
```

### 2. Attach an RSA certificate

Manual:

```bash
vaultick rsa add --label id_rsa --cert "$HOME/.ssh/id_rsa.pub"
```

Auto-discovery:

```bash
vaultick rsa add --auto
```

### 3. Store secrets

```bash
vaultick secret set GITHUB_TOKEN ghp_xxx
vaultick secret set API_KEY --file ./key.txt
vaultick secret set --env-file .env --skip-existing
```

### 4. Use them

```bash
vaultick exec --env GITHUB_TOKEN -- sh -c 'echo "$GITHUB_TOKEN"'
vaultick request --url https://api.github.com/user --header 'Authorization: Bearer $GITHUB_TOKEN'
```

## Command groups

### `workspace`

Use this group to manage logical containers of secrets and RSA certificates.

```bash
vaultick workspace create app-prod
vaultick workspace list
vaultick workspace get app-prod
vaultick workspace delete app-prod
```

### `rsa`

Use this group to manage who can read a workspace.

```bash
vaultick rsa add --label primary --cert ./public.pem
vaultick rsa add --auto
vaultick rsa list
vaultick rsa delete <id-or-fingerprint>
```

`--auto` scans `~/.ssh`, validates `.pub` files with matching private keys and
lets the operator choose from a TUI.

### `secret`

Use this group to store values and inspect metadata.

Supported storage flows:

```bash
vaultick secret set TOKEN abc123
printf 'abc123' | vaultick secret set TOKEN --stdin
vaultick secret set TOKEN --file ./token.txt
vaultick secret set --env-file .env
```

Supported inspection flows:

```bash
vaultick secret get TOKEN
vaultick secret get TOKEN --json
vaultick secret list
vaultick secret list --json
vaultick secret delete TOKEN
```

Important behavior:

- secret names are case-insensitive at the interface
- stored keys are normalized to uppercase
- `set` fails on conflicts by default
- use `--overwrite` to replace an existing key
- use `--skip-existing` with `--env-file` to keep existing values untouched
- `get` and `list` return metadata only

### `exec`

Use `exec` to run a child process with secrets injected as environment
variables.

Main forms:

```bash
vaultick exec --env KEY -- command ...
vaultick exec --all -- command ...
vaultick exec -- KEY='$KEY' command ...
```

Examples:

```bash
vaultick exec --env AWS_ACCESS_KEY_ID --env AWS_SECRET_ACCESS_KEY -- aws sts get-caller-identity
vaultick exec --all -- sh -c 'env | sort'
```

The CLI resolves the required secrets internally, runs the command and redacts
matching secret values from the child output stream.

### `request`

Use `request` to make outbound HTTP calls with secret substitution handled
inside `vaultick`.

Supported forms:

```bash
vaultick request --url ... --method ... --header ... --body ...
vaultick request --data '{"url":"...","headers":{"Authorization":"Bearer $TOKEN"}}'
```

Supported placeholder locations:

- URL
- headers
- body

Examples:

```bash
vaultick request \
  --url https://api.github.com/user \
  --header 'Authorization: Bearer $GITHUB_TOKEN'

vaultick request --data '{
  "url":"https://api.github.com/user/repos",
  "method":"GET",
  "headers":{"Authorization":"Bearer $GITHUB_TOKEN"}
}'
```

The response body is streamed to standard output only after matching in-use
secrets have been redacted.
