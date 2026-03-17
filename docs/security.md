# Security model

`vaultick` is designed around controlled usage of secrets rather than direct
revelation of secret values.

## Core rule

The system should allow secrets to be:

- stored
- updated
- injected into processes
- forwarded into HTTP requests

The system should avoid:

- printing secret values in normal management commands
- storing private keys in the database
- leaking in-use secrets in subprocess output or HTTP responses

## Storage model

Secrets are stored in SQLite, but not as plaintext.

- each secret gets a random data encryption key
- the secret payload is encrypted with `AES-256-GCM`
- the data encryption key is wrapped with `RSA-OAEP-SHA256`
- each workspace may have multiple RSA certificates, so the same secret can be
  opened by more than one authorized private key

## Workspace boundaries

Workspaces isolate:

- RSA certificates
- secret metadata
- encrypted secret payloads

This lets one database hold multiple logical environments such as:

- `default`
- `dev`
- `staging`
- `prod`

## Secret-name binding

The normalized secret key is part of the authenticated encryption context.

That means:

- a secret can be overwritten under the same key
- the stored key name cannot be renamed without re-encrypting the secret
- tampering with the key name in SQLite invalidates decryption

## Secret visibility rules

Management commands are metadata-oriented.

- `secret list` returns metadata only
- `secret get` returns metadata for one key only
- `secret set` stores data but does not echo the value back

This is why `vaultick` removed any generic replace/export behavior that would
print stored values to standard output.

## Process execution and redaction

`vaultick exec` loads the secrets needed for a child process, injects them into
its environment and captures the process output.

Before that output reaches the user:

- `stdout` is scanned
- `stderr` is scanned
- known in-use secret values are replaced with `[REDACTED]`

This works for:

- one-shot command output
- long-running streaming output
- chunked and partial secret matches across stream boundaries

## HTTP request redaction

`vaultick request` and `vaultick-proxy` apply the same principle to HTTP
responses.

If a response body contains a secret value used during the request:

- the response is redacted before it reaches the caller

This applies to:

- plain text responses
- JSON responses
- chunked transfer responses
- server-sent events

## Private keys

The private key is not persisted in the database.

It is only loaded from disk when required to:

- unwrap a secret for `exec`
- unwrap a secret for `request`
- pre-resolve secrets for the proxy
- rewrap existing secrets when adding a new RSA certificate

## Practical limits

`vaultick` reduces accidental exposure, but it is not a universal DLP system.

Examples:

- a child process still receives the secret in its environment
- an upstream service still receives the secret inside a forwarded request if
  your route or request configuration puts it there
- redaction only applies to secret values that `vaultick` knows were involved
  in the current operation
