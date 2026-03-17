# vaultick CLI

`vaultick` is the user-facing command line interface for the project.

It manages:

- workspaces
- RSA certificates
- secret metadata and storage
- secret-backed process execution
- secret-backed HTTP requests

## Global behavior

### Database resolution

If `--db` is passed, that path is used directly.

Otherwise the CLI uses:

```text
VAULTICK_HOME/databases/database.db
```

If `VAULTICK_HOME` is missing, the CLI fails with guidance.

### Workspace resolution

The workspace is resolved in this order:

1. `--workspace`
2. `VAULTICK_WORKSPACE`
3. `default`

## Command groups

### `workspace`

Use this group to manage logical containers of secrets and certificates.

Supported commands:

- `workspace create <name>`
- `workspace list`
- `workspace get <ref>`
- `workspace delete <ref>`

### `rsa`

Use this group to manage the public keys allowed to unwrap secrets.

Supported commands:

- `rsa add --label <label> --cert <path>`
- `rsa add --auto`
- `rsa list`
- `rsa delete <ref>`

`--auto` scans `~/.ssh`, finds usable `.pub` files with matching private keys
and lets the user choose from a TUI list.

### `secret`

Use this group to manage stored secret entries.

Supported commands:

- `secret set <KEY> <VALUE>`
- `secret set <KEY> --stdin`
- `secret set <KEY> --file <path>`
- `secret set --env-file <path>`
- `secret get <KEY>`
- `secret list`
- `secret delete <KEY>`

Important behavior:

- secret names are case-insensitive at the interface
- stored keys are normalized to uppercase
- `set` fails on conflicts by default
- use `--overwrite` to replace an existing key
- use `--skip-existing` with `--env-file` to keep existing values untouched
- `get` and `list` return metadata only

`--json` is available on:

- `secret get`
- `secret list`

### `exec`

Use this command to run a child process with secrets injected as environment
variables.

Main forms:

- `exec --env KEY -- command ...`
- `exec --all -- command ...`
- `exec -- KEY='$KEY' command ...`

The CLI resolves the required secrets internally, runs the command, and redacts
known secret values from the child output.

### `request`

Use this command to make outbound HTTP requests with internal secret
substitution.

Supported forms:

- `request --url ... --method ... --header ... --body ...`
- `request --data '{"url":"...","headers":{"Authorization":"Bearer $TOKEN"}}'`

Supported placeholder locations:

- URL
- headers
- body

The response body is written to standard output, but known secret values used in
that request are redacted first.

## Recommended operator flow

1. define `VAULTICK_HOME`
2. add an RSA certificate to the target workspace
3. store secrets
4. use `exec` for processes and `request` for outbound HTTP calls
5. use `secret get` and `secret list` only for metadata inspection
