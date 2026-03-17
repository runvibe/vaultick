# RSA certificates

RSA certificates are the access-control layer for `vaultick`.

A workspace can only store usable secrets when it has at least one RSA
certificate attached.

## Why RSA is used here

`vaultick` uses hybrid encryption.

Each secret payload gets its own symmetric encryption key. That key is then
wrapped for every RSA certificate attached to the workspace.

This allows:

- one secret to be usable by multiple private keys
- easy addition of new readers through rewrap
- isolation by workspace

## Resource fields

Each certificate stores:

- `id`
- `workspace_id`
- `label`
- `cert_pem`
- `fingerprint_sha256`
- `created_at`

The `label` is an operator-friendly name, often matching the private key file:

- `id_rsa`
- `primary`
- `ci`

## Adding certificates

### Manual add

```bash
vaultick rsa add --label primary --cert ./public.pem
```

### Auto-discovery

```bash
vaultick rsa add --auto
```

The auto mode scans `~/.ssh`, looks for `.pub` files, validates matching
private keys and lets the user choose from a TUI.

## Rewrap behavior

If a workspace already has secrets and you add a new certificate, the existing
secret envelopes must be rewrapped for the new reader.

That is why the CLI supports:

```bash
vaultick rsa add \
  --label new-reader \
  --cert ./new-reader.pub \
  --rewrap-from-key ~/.ssh/id_rsa
```

## Listing and deletion

```bash
vaultick rsa list
vaultick rsa delete <id-or-fingerprint>
```

Deletion is blocked if removing that certificate would leave an existing secret
without any remaining recipient envelope.

## Private key lookup

The database stores public material only.

Private keys are loaded from disk when needed for internal operations such as:

- `exec`
- `request`
- proxy startup
- certificate rewrap
