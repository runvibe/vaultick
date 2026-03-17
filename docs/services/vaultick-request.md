# vaultick-request

`vaultick-request` is a technical reference crate behind the main user-facing
products, `vaultick` and `vaultick-proxy`.

It is used by:

- `vaultick`
- `vaultick-proxy`

It does not load secrets by itself. Instead, callers:

1. resolve secret values from their own source
2. pass those values into `vaultick-request`
3. let the library perform substitution, request execution and redaction

## Main responsibilities

### Placeholder collection and replacement

The crate supports case-insensitive `$SECRET_NAME` placeholder resolution across
text inputs such as:

- URLs
- header values
- request bodies

The main helpers are:

- `collect_secret_placeholders`
- `replace_secret_placeholders`
- `RequestTemplateIndex`

### Request validation and building

The crate validates and builds outbound requests through:

- `RequestSpec`
- `ResolvedRequest`
- `RequestBody`
- `parse_request_headers`
- `parse_http_method`

This keeps callers from duplicating the same HTTP parsing logic.

### HTTP execution

The crate provides:

- async execution for services such as `vaultick-proxy`
- blocking execution for the CLI

This lets both consumers share the same request semantics while keeping their
own runtime model.

### Response redaction

The crate exposes `Redactor` and streaming helpers so callers can redact
responses before they reach the terminal or downstream HTTP clients.

This supports:

- normal responses
- chunked responses
- SSE
- partial secret matches split across boundaries

## What the crate does not do

`vaultick-request` intentionally stays generic.

It does not know about:

- SQLite
- workspaces
- RSA certificates
- private key lookup
- CLI parsing
- YAML route config

Those concerns remain in:

- `vaultick-lib`
- `vaultick`
- `vaultick-proxy`
