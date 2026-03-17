# vaultick-lib

`vaultick-lib` is the core Rust library of the project.

It owns:

- SQLite schema and persistence
- workspace CRUD
- RSA certificate CRUD
- secret encryption and storage
- validation and access rules

It does not own:

- CLI parsing
- proxy routing
- HTTP transport

## Main responsibilities

### Database lifecycle

`Vaultick::open(path)` opens or creates the SQLite database and initializes the
schema.

When the database is created for the first time:

- the schema is applied
- the `default` workspace is seeded automatically

### Workspace management

The library supports:

- `create_workspace`
- `list_workspaces`
- `get_workspace`
- `delete_workspace`

Deleting a workspace cascades through:

- RSA certificates
- secrets
- secret recipients

### RSA certificate management

The library supports:

- `add_certificate`
- `list_certificates`
- `delete_certificate`

Important rules:

- certificates are attached to a specific workspace
- certificate uniqueness is enforced by fingerprint inside a workspace
- adding a new certificate to a workspace with existing secrets requires a
  rewrap private key
- deleting a certificate is blocked if it would orphan existing secrets

### Secret management

The library supports:

- `set_secret`
- `set_secret_bytes`
- `get_secret_metadata`
- `list_secrets`
- `delete_secret`

It also supports internal secret loading for execution and request flows without
turning those values into normal CLI output.

## Data model

The schema contains four main tables:

- `workspaces`
- `rsa_certificates`
- `secrets`
- `secret_recipients`

The `secret_recipients` table is what lets a single secret be opened by any
authorized RSA private key for that workspace.

## Crypto model

The library uses hybrid encryption:

- a random data encryption key per secret
- `AES-256-GCM` for the secret payload
- `RSA-OAEP-SHA256` to wrap the data encryption key for each certificate

The normalized secret key is included as authenticated additional data.

## Error model

The public error type is `VaultickError`.

Key error classes include:

- database errors
- invalid certificate material
- invalid private key material
- not found errors
- workspace-without-certificate errors
- certificate-in-use errors
- validation failures

## Typical embedding flow

Use `vaultick-lib` when you want Rust code to own storage and encryption but not
CLI or proxy concerns.

Typical application flow:

1. open the database
2. resolve the workspace
3. register one or more RSA certificates
4. store secrets
5. use higher-level tooling such as `vaultick` or `vaultick-proxy` to consume
   them safely
