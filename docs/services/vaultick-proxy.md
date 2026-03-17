# vaultick-proxy

`vaultick-proxy` is a config-driven reverse proxy service that forwards incoming
HTTP requests to upstream targets while injecting secrets and redacting the
response before it reaches the client.

## Main responsibilities

- load route config from YAML or JSON sources
- match incoming requests by path prefix
- build upstream requests using route templates
- resolve `$SECRET` placeholders through `vaultick-lib`
- resolve `{{request.*}}` placeholders from the incoming request
- stream the upstream response back to the client
- redact known in-use secrets from that streamed response

## Startup model

The proxy is started with:

```bash
vaultick-proxy --config ./vaultick-proxy.yaml
```

It also supports env-based config resolution through `VAULTICK_CONFIG`.

Supported sources are:

- inline JSON string
- inline YAML string
- URL
- filesystem path
- base64-encoded JSON or YAML string

When the source is a URL, `VAULTICK_CONFIG_HEADERS` may supply fetch headers as a
JSON object.

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

## Request template variables

The proxy supports these request-context placeholders:

- `{{request.method}}`
- `{{request.path}}`
- `{{request.path_tail}}`
- `{{request.query}}`
- `{{request.header.<name>}}`
- `{{request.body}}`

Secrets continue to use `$SECRET_NAME`.

## Forwarding behavior

The proxy:

- matches routes in order
- uses the first matching path prefix
- preserves the upstream status code
- copies upstream response headers except hop-by-hop headers
- streams the upstream response body to the downstream client

On error:

- unmatched route returns `404`
- upstream transport failure returns `502`
- upstream timeout returns `504`
- request-template expansion failure returns `500`

## Redaction behavior

The proxy pre-resolves the secrets required by the configured routes.

When an upstream response includes one of those in-use values:

- the streamed output is redacted before the client receives it

This includes:

- normal bodies
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

## Deployment notes

`vaultick-proxy` is meant to run well as a service, especially in containers.

Common deployment patterns:

- mount a config file and use `--config`
- inject `VAULTICK_CONFIG` directly as YAML or JSON
- load `VAULTICK_CONFIG` from a remote URL
- ship the binary in a Docker image and mount only the database, private key and
  config
