# HTTP requests and proxy forwarding

`vaultick` supports two HTTP-oriented usage modes:

- direct outbound requests from the CLI
- proxy-based forwarding through `vaultick-proxy`

Both rely on `vaultick-request` for request execution and response redaction.

## CLI request mode

The CLI command is:

```bash
vaultick request --url https://example.com
```

You can pass request data explicitly:

```bash
vaultick request \
  --url https://api.github.com/user \
  --method GET \
  --header 'Authorization: Bearer $GITHUB_TOKEN'
```

Or use a JSON payload:

```bash
vaultick request --data '{
  "url":"https://api.github.com/user",
  "method":"GET",
  "headers":{"Authorization":"Bearer $GITHUB_TOKEN"}
}'
```

Supported placeholder locations:

- URL
- headers
- body

## CLI request behavior

- default method is `GET`
- non-`2xx` responses still print the redacted body
- non-`2xx` responses exit nonzero
- transport and setup errors go to `stderr`
- streaming responses are redacted incrementally

## Proxy forwarding mode

`vaultick-proxy` turns a route definition into an upstream request.

Each route can define:

- base URL
- method template
- path template
- query template
- headers
- body template
- timeout

The proxy may use:

- `$SECRET_NAME`
- `{{request.*}}`

inside those templates.

## Request-context variables

The proxy supports these incoming-request values:

- `{{request.method}}`
- `{{request.path}}`
- `{{request.path_tail}}`
- `{{request.query}}`
- `{{request.header.<name>}}`
- `{{request.body}}`

## Redaction model

In both CLI request mode and proxy mode:

- secrets are resolved internally
- request payloads may carry those secrets to upstreams
- if the response body contains those same values, they are replaced with
  `[REDACTED]` before being shown or forwarded

This applies to:

- text
- JSON
- chunked responses
- SSE
