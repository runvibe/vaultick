# vaultick-proxy

`vaultick-proxy` is the service-facing product in the `vaultick` stack.

Use it when you want an HTTP endpoint that:

- receives inbound requests
- transforms them into upstream requests
- injects secrets from `vaultick`
- redacts secret leaks from upstream responses before returning them

## What the proxy does

For every configured route, the proxy can:

- match by path prefix
- build an upstream URL
- set or transform method, path, query, headers and body
- resolve `$SECRET_NAME` from the `vaultick` database
- resolve `{{request.*}}` from the incoming request
- stream the upstream response back to the client
- redact matching in-use secrets from that stream

## Startup model

Start the proxy with a file-based config:

```bash
vaultick-proxy --config ./vaultick-proxy.yaml
```

Or drive it from `VAULTICK_CONFIG`.

Supported `VAULTICK_CONFIG` sources:

- inline JSON
- inline YAML
- URL
- filesystem path
- base64-encoded JSON or YAML string

When `VAULTICK_CONFIG` is a URL, `VAULTICK_CONFIG_HEADERS` may provide fetch
headers as a JSON object.

Precedence is:

1. `--config`
2. `VAULTICK_CONFIG`

## Config shape

Top-level fields:

- `listen`
- `db`
- `workspace`
- `private_key`
- `routes`

Route fields:

- `match.path_prefix`
- `forward.base_url`
- `forward.method`
- `forward.path`
- `forward.query`
- `forward.pass_query`
- `forward.headers`
- `forward.body`
- `forward.timeout_ms`

## Template model

Secrets:

- `$SECRET_NAME`

Incoming-request context:

- `{{request.method}}`
- `{{request.path}}`
- `{{request.path_tail}}`
- `{{request.query}}`
- `{{request.header.<name>}}`
- `{{request.body}}`

This allows patterns such as:

- passing through an incoming method
- forwarding part of the path tail
- copying an inbound header into the upstream request
- combining static configuration with a secret-backed auth header

## Forwarding behavior

The proxy:

- evaluates routes in order
- uses the first matching path prefix
- preserves the upstream status code
- copies upstream response headers except hop-by-hop headers
- streams the upstream body to the downstream client

On error:

- unmatched route returns `404`
- upstream transport failure returns `502`
- upstream timeout returns `504`
- request-template expansion failure returns `500`

## Redaction behavior

The proxy pre-resolves the secrets needed by the configured routes.

If an upstream response includes one of those in-use values:

- the outgoing response is redacted before the client receives it

This applies to:

- normal response bodies
- chunked transfer
- SSE

## Example config

```yaml
listen: 127.0.0.1:8080
db: /app/.vaultick/databases/database.db
workspace: default
private_key: /app/.ssh/id_rsa
routes:
  - match:
      path_prefix: /github
    forward:
      base_url: https://api.github.com
      method: "{{request.method}}"
      path: /user
      headers:
        Authorization: "Bearer $GITHUB_TOKEN"
        Accept: "application/vnd.github+json"
```

## Example deployment flow

1. mount the database and private key into the container
2. provide config via `--config` or `VAULTICK_CONFIG`
3. start `vaultick-proxy`
4. send requests to the local listener
5. let the proxy forward to upstreams with secret injection and redaction

Example:

```bash
export VAULTICK_CONFIG="$(cat ./vaultick-proxy.yaml)"
vaultick-proxy
```

## Container and CI usage

`vaultick-proxy` is designed to run well in Docker and CI/CD environments.

Common patterns:

- mount a config file and use `--config`
- inject inline YAML/JSON through `VAULTICK_CONFIG`
- store config remotely and point `VAULTICK_CONFIG` at a URL
- ship the proxy image and mount only the database plus private key at runtime
