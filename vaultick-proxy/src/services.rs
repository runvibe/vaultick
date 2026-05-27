use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::http::header::{
    CONNECTION, CONTENT_LENGTH, HeaderMap, TE, TRAILER, TRANSFER_ENCODING, UPGRADE,
};
use axum::http::{Method, Request, Response, StatusCode, Uri};
use base64::Engine;
use vaultick::Vaultick;
use vaultick_request::{
    AsyncClient, BoxError, RequestBody, RequestSpec, RequestTemplateIndex, ResolvedRequest, Url,
    collect_secret_placeholders, execute_async_with_client, replace_secret_placeholders,
};

use crate::models::{
    AppState, CompiledRoute, DEFAULT_MAX_REQUEST_BODY_BYTES, ProxyConfigFile, RequestContext,
    ResolvedSettings, RouteConfig, SharedAppState, StartupOverrides,
};

const DEFAULT_WORKSPACE_NAME: &str = "default";
const DEFAULT_DB_DIRECTORY: &str = "databases";
const DEFAULT_DB_FILENAME: &str = "database.db";
const VAULTICK_HOME_ENV_VAR: &str = "VAULTICK_HOME";
const VAULTICK_WORKSPACE_ENV_VAR: &str = "VAULTICK_WORKSPACE";
const VAULTICK_CONFIG_ENV_VAR: &str = "VAULTICK_CONFIG";
const VAULTICK_CONFIG_HEADERS_ENV_VAR: &str = "VAULTICK_CONFIG_HEADERS";

pub async fn load_settings(overrides: StartupOverrides) -> Result<ResolvedSettings, BoxError> {
    let config_text = resolve_config_text(overrides.config_path.as_deref()).await?;
    let file_config = parse_config_text(&config_text)?;

    let db_path = if let Some(path) = overrides.db {
        path
    } else if let Some(path) = file_config.db.clone() {
        path
    } else {
        resolve_default_db_path()?
    };

    let workspace = if let Some(workspace) = overrides.workspace {
        workspace
    } else if let Some(workspace) = file_config.workspace.clone() {
        workspace
    } else if let Ok(workspace) = std::env::var(VAULTICK_WORKSPACE_ENV_VAR) {
        workspace
    } else {
        DEFAULT_WORKSPACE_NAME.to_string()
    };

    let private_key_path = overrides
        .private_key
        .or(file_config.private_key.clone())
        .ok_or_else(|| {
            io::Error::other(
                "missing private key path; configure private_key in YAML or pass --private-key",
            )
        })?;

    let listen = overrides.listen.unwrap_or(file_config.listen.clone());
    let max_request_body_bytes = file_config
        .max_request_body_bytes
        .unwrap_or(DEFAULT_MAX_REQUEST_BODY_BYTES);

    Ok(ResolvedSettings {
        listen,
        db_path,
        workspace,
        private_key_path,
        max_request_body_bytes,
        routes: file_config.routes,
    })
}

pub fn build_state(settings: &ResolvedSettings) -> Result<SharedAppState, BoxError> {
    let vaultick = Vaultick::open(&settings.db_path)?;
    let private_key_pem = fs::read_to_string(&settings.private_key_path)?;
    let secret_index = RequestTemplateIndex::new(
        vaultick
            .list_secrets(&settings.workspace)?
            .into_iter()
            .map(|secret| secret.key),
    )?;

    let referenced_secret_keys = collect_referenced_secret_keys(&settings.routes, &secret_index)?;
    let mut secret_values = HashMap::new();
    for secret_key in referenced_secret_keys {
        let value = vaultick.get_secret(&settings.workspace, &secret_key, &private_key_pem)?;
        secret_values.insert(secret_key, value);
    }

    let mut compiled_routes = Vec::with_capacity(settings.routes.len());
    for route in &settings.routes {
        compiled_routes.push(compile_route(route, &secret_index, &secret_values)?);
    }

    Ok(Arc::new(AppState {
        client: AsyncClient::builder().build()?,
        max_request_body_bytes: settings.max_request_body_bytes,
        routes: compiled_routes,
    }))
}

async fn resolve_config_text(cli_config_path: Option<&Path>) -> Result<String, BoxError> {
    if let Some(path) = cli_config_path {
        return fs::read_to_string(path).map_err(Into::into);
    }

    let raw_config = std::env::var(VAULTICK_CONFIG_ENV_VAR).map_err(|_| {
        io::Error::other("missing proxy config. Pass --config <path> or define VAULTICK_CONFIG")
    })?;

    if parse_config_text(&raw_config).is_ok() {
        return Ok(raw_config);
    }

    if is_config_url(&raw_config) {
        return fetch_remote_config(&raw_config).await;
    }

    let config_path = PathBuf::from(&raw_config);
    if config_path.is_file() {
        return fs::read_to_string(&config_path).map_err(Into::into);
    }

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(raw_config.as_bytes())
        .map_err(|err| {
            io::Error::other(format!(
                "failed to resolve VAULTICK_CONFIG as inline config, URL, path, or base64: {err}"
            ))
        })?;
    let decoded_text = String::from_utf8(decoded).map_err(|err| {
        io::Error::other(format!("VAULTICK_CONFIG base64 was not valid UTF-8: {err}"))
    })?;

    if parse_config_text(&decoded_text).is_ok() {
        return Ok(decoded_text);
    }

    Err(io::Error::other(
        "VAULTICK_CONFIG base64 decoded successfully but did not contain valid JSON or YAML config",
    )
    .into())
}

fn parse_config_text(input: &str) -> Result<ProxyConfigFile, BoxError> {
    if let Ok(config) = serde_json::from_str::<ProxyConfigFile>(input) {
        return Ok(config);
    }

    Ok(serde_yaml::from_str::<ProxyConfigFile>(input)?)
}

fn is_config_url(value: &str) -> bool {
    value.starts_with("http://") || value.starts_with("https://")
}

async fn fetch_remote_config(url: &str) -> Result<String, BoxError> {
    let client = reqwest::Client::builder().build()?;
    let mut request = client.get(url);

    for (name, value) in parse_config_headers_env()? {
        request = request.header(name, value);
    }

    let response = request.send().await?;
    let response = response.error_for_status()?;
    Ok(response.text().await?)
}

fn parse_config_headers_env() -> Result<Vec<(String, String)>, BoxError> {
    let Ok(raw_headers) = std::env::var(VAULTICK_CONFIG_HEADERS_ENV_VAR) else {
        return Ok(Vec::new());
    };

    let headers = serde_json::from_str::<HashMap<String, String>>(&raw_headers).map_err(|err| {
        io::Error::other(format!(
            "invalid {VAULTICK_CONFIG_HEADERS_ENV_VAR}; expected a JSON object of string headers: {err}"
        ))
    })?;

    Ok(headers.into_iter().collect())
}

pub async fn handle_proxy_request(state: SharedAppState, request: Request<Body>) -> Response<Body> {
    let path = request.uri().path().to_string();
    let Some(route) = state
        .routes
        .iter()
        .find(|route| path_matches_prefix(&path, &route.path_prefix))
        .cloned()
    else {
        return plain_response(StatusCode::NOT_FOUND, "route not found");
    };

    match forward_request(state, route, request).await {
        Ok(response) => response,
        Err((status, message)) => plain_response(status, &message),
    }
}

async fn forward_request(
    state: SharedAppState,
    route: CompiledRoute,
    request: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    let (parts, body) = request.into_parts();
    let body_bytes = to_bytes(body, state.max_request_body_bytes)
        .await
        .map_err(|err| {
            let message = err.to_string();
            if message.contains("length limit") {
                (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    format!(
                        "request body too large; limit is {} bytes",
                        state.max_request_body_bytes
                    ),
                )
            } else {
                (
                    StatusCode::BAD_REQUEST,
                    format!("failed to read request body: {err}"),
                )
            }
        })?;

    let request_context = build_request_context(
        &parts.method,
        &parts.uri,
        &parts.headers,
        &route,
        body_bytes.to_vec(),
    );

    let method = if let Some(method_template) = &route.method_template {
        render_request_template(method_template, &request_context)
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?
    } else {
        request_context.method.clone()
    };
    let method = Method::from_bytes(method.trim().as_bytes()).map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("invalid upstream method: {err}"),
        )
    })?;

    let path = render_request_template(&route.path_template, &request_context)
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let query = if let Some(query_template) = &route.query_template {
        Some(
            render_request_template(query_template, &request_context)
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
        )
    } else if route.pass_query {
        request_context.query.clone()
    } else {
        None
    };

    let upstream_url = build_upstream_url(&route.base_url, &path, query.as_deref())
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut headers = Vec::with_capacity(route.headers.len());
    for (name, value_template) in &route.headers {
        let value = render_request_template(value_template, &request_context)
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        headers.push((name.clone(), value));
    }

    let body = if let Some(body_template) = &route.body_template {
        Some(RequestBody::Text(
            render_request_template(body_template, &request_context)
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
        ))
    } else if !request_context.body_bytes.is_empty() {
        Some(RequestBody::Bytes(request_context.body_bytes.clone()))
    } else {
        None
    };

    let request = RequestSpec {
        url: upstream_url.to_string(),
        method: Some(method.as_str().to_string()),
        headers,
        body,
        timeout: route.timeout,
    };
    let request = ResolvedRequest::from_spec(&request, |_| {
        Err(io::Error::other("proxy request should already be fully resolved").into())
    })
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let upstream_response = execute_async_with_client(&state.client, &request)
        .await
        .map_err(|err| {
            if err.is_timeout() {
                (
                    StatusCode::GATEWAY_TIMEOUT,
                    format!("upstream request timed out: {err}"),
                )
            } else {
                (
                    StatusCode::BAD_GATEWAY,
                    format!("upstream request failed: {err}"),
                )
            }
        })?;

    let status = upstream_response.status();
    let headers = filter_response_headers(upstream_response.headers());
    let stream = upstream_response.into_redacted_stream(&route.redacted_values);

    let mut response = Response::builder().status(status);
    let response_headers = response
        .headers_mut()
        .expect("response builder should allow headers");
    response_headers.extend(headers);

    Ok(response
        .body(Body::from_stream(stream))
        .expect("stream response should build"))
}

fn resolve_default_db_path() -> Result<PathBuf, io::Error> {
    let vaultick_home = std::env::var(VAULTICK_HOME_ENV_VAR).map_err(|_| {
        io::Error::other(
            "missing VAULTICK_HOME. Configure something like VAULTICK_HOME=\"$HOME/.vaultick\" or pass --db <path>",
        )
    })?;

    let home_path = PathBuf::from(vaultick_home);
    let db_directory = home_path.join(DEFAULT_DB_DIRECTORY);
    fs::create_dir_all(&db_directory)?;
    Ok(db_directory.join(DEFAULT_DB_FILENAME))
}

fn collect_referenced_secret_keys(
    routes: &[RouteConfig],
    secret_index: &RequestTemplateIndex,
) -> Result<BTreeSet<String>, BoxError> {
    let mut keys = BTreeSet::new();

    for route in routes {
        collect_template_secrets(&route.forward.base_url, false, secret_index, &mut keys)?;
        if let Some(method) = &route.forward.method {
            collect_template_secrets(method, true, secret_index, &mut keys)?;
        }
        if let Some(path) = &route.forward.path {
            collect_template_secrets(path, true, secret_index, &mut keys)?;
        }
        if let Some(query) = &route.forward.query {
            collect_template_secrets(query, true, secret_index, &mut keys)?;
        }
        if let Some(body) = &route.forward.body {
            collect_template_secrets(body, true, secret_index, &mut keys)?;
        }
        for value in route.forward.headers.values() {
            collect_template_secrets(value, true, secret_index, &mut keys)?;
        }
    }

    Ok(keys)
}

fn collect_template_secrets(
    template: &str,
    allow_request_placeholders: bool,
    secret_index: &RequestTemplateIndex,
    keys: &mut BTreeSet<String>,
) -> Result<(), BoxError> {
    validate_request_placeholders(template, allow_request_placeholders)?;

    for placeholder in collect_secret_placeholders(template) {
        let canonical = secret_index
            .canonical_key(&placeholder)
            .ok_or_else(|| io::Error::other(format!("secret not found: {placeholder}")))?;
        keys.insert(canonical.to_string());
    }

    Ok(())
}

fn compile_route(
    route: &RouteConfig,
    secret_index: &RequestTemplateIndex,
    secret_values: &HashMap<String, String>,
) -> Result<CompiledRoute, BoxError> {
    let mut route_secret_keys = BTreeSet::new();

    let base_url = resolve_static_template(
        &route.forward.base_url,
        false,
        secret_index,
        secret_values,
        &mut route_secret_keys,
    )?;
    let method_template = route
        .forward
        .method
        .as_deref()
        .map(|template| {
            resolve_static_template(
                template,
                true,
                secret_index,
                secret_values,
                &mut route_secret_keys,
            )
        })
        .transpose()?;
    let path_template = resolve_static_template(
        route
            .forward
            .path
            .as_deref()
            .unwrap_or("{{request.path_tail}}"),
        true,
        secret_index,
        secret_values,
        &mut route_secret_keys,
    )?;
    let query_template = route
        .forward
        .query
        .as_deref()
        .map(|template| {
            resolve_static_template(
                template,
                true,
                secret_index,
                secret_values,
                &mut route_secret_keys,
            )
        })
        .transpose()?;
    let body_template = route
        .forward
        .body
        .as_deref()
        .map(|template| {
            resolve_static_template(
                template,
                true,
                secret_index,
                secret_values,
                &mut route_secret_keys,
            )
        })
        .transpose()?;

    let mut headers = Vec::with_capacity(route.forward.headers.len());
    for (name, value) in &route.forward.headers {
        headers.push((
            name.clone(),
            resolve_static_template(
                value,
                true,
                secret_index,
                secret_values,
                &mut route_secret_keys,
            )?,
        ));
    }

    let redacted_values = route_secret_keys
        .into_iter()
        .filter_map(|key| secret_values.get(&key).cloned())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();

    Ok(CompiledRoute {
        path_prefix: normalize_path_prefix(&route.route_match.path_prefix),
        base_url,
        method_template,
        path_template,
        query_template,
        pass_query: route.forward.pass_query,
        headers,
        body_template,
        timeout: route.forward.timeout_ms.map(Duration::from_millis),
        redacted_values,
    })
}

fn resolve_static_template(
    template: &str,
    allow_request_placeholders: bool,
    secret_index: &RequestTemplateIndex,
    secret_values: &HashMap<String, String>,
    route_secret_keys: &mut BTreeSet<String>,
) -> Result<String, BoxError> {
    validate_request_placeholders(template, allow_request_placeholders)?;

    replace_secret_placeholders(template, |placeholder| {
        let canonical = secret_index
            .canonical_key(placeholder)
            .ok_or_else(|| io::Error::other(format!("secret not found: {placeholder}")))?;
        route_secret_keys.insert(canonical.to_string());
        secret_values
            .get(canonical)
            .cloned()
            .ok_or_else(|| io::Error::other(format!("secret not loaded: {canonical}")).into())
    })
}

fn validate_request_placeholders(
    template: &str,
    allow_request_placeholders: bool,
) -> Result<(), io::Error> {
    let mut cursor = 0;
    while let Some(start_offset) = template[cursor..].find("{{") {
        let start = cursor + start_offset;
        let end = template[start + 2..].find("}}").ok_or_else(|| {
            io::Error::other(format!(
                "invalid template, missing closing braces in {template:?}"
            ))
        })?;
        let expression = template[start + 2..start + 2 + end].trim();

        if !allow_request_placeholders {
            return Err(io::Error::other(format!(
                "request placeholder {expression:?} is not allowed in this field"
            )));
        }

        validate_request_expression(expression)?;
        cursor = start + 2 + end + 2;
    }

    Ok(())
}

fn validate_request_expression(expression: &str) -> Result<(), io::Error> {
    match expression {
        "request.method" | "request.path" | "request.path_tail" | "request.query"
        | "request.body" => Ok(()),
        _ if expression.starts_with("request.header.") => {
            let header_name = expression.trim_start_matches("request.header.");
            if header_name.is_empty() {
                Err(io::Error::other(
                    "request.header placeholder must include a header name",
                ))
            } else {
                Ok(())
            }
        }
        _ => Err(io::Error::other(format!(
            "unsupported request placeholder: {expression}"
        ))),
    }
}

fn render_request_template(template: &str, context: &RequestContext) -> Result<String, io::Error> {
    let mut output = String::with_capacity(template.len());
    let mut cursor = 0;

    while let Some(start_offset) = template[cursor..].find("{{") {
        let start = cursor + start_offset;
        output.push_str(&template[cursor..start]);

        let end = template[start + 2..].find("}}").ok_or_else(|| {
            io::Error::other(format!(
                "invalid template, missing closing braces in {template:?}"
            ))
        })?;
        let expression = template[start + 2..start + 2 + end].trim();
        output.push_str(&resolve_request_expression(expression, context)?);
        cursor = start + 2 + end + 2;
    }

    output.push_str(&template[cursor..]);
    Ok(output)
}

fn resolve_request_expression(
    expression: &str,
    context: &RequestContext,
) -> Result<String, io::Error> {
    match expression {
        "request.method" => Ok(context.method.clone()),
        "request.path" => Ok(context.path.clone()),
        "request.path_tail" => Ok(context.path_tail.clone()),
        "request.query" => Ok(context.query.clone().unwrap_or_default()),
        "request.body" => String::from_utf8(context.body_bytes.clone())
            .map_err(|_| io::Error::other("request body is not valid UTF-8 for {{request.body}}")),
        _ if expression.starts_with("request.header.") => {
            let header_name = expression.trim_start_matches("request.header.");
            Ok(context
                .headers
                .get(&header_name.to_ascii_lowercase())
                .cloned()
                .unwrap_or_default())
        }
        _ => Err(io::Error::other(format!(
            "unsupported request placeholder: {expression}"
        ))),
    }
}

fn build_request_context(
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    route: &CompiledRoute,
    body_bytes: Vec<u8>,
) -> RequestContext {
    let path = uri.path().to_string();
    let path_tail = path_tail_for_prefix(&path, &route.path_prefix);
    let headers = headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_ascii_lowercase(), value.to_string()))
        })
        .collect::<HashMap<_, _>>();

    RequestContext {
        method: method.as_str().to_string(),
        path,
        path_tail,
        query: uri.query().map(ToString::to_string),
        headers,
        body_bytes,
    }
}

fn build_upstream_url(base_url: &str, path: &str, query: Option<&str>) -> Result<Url, io::Error> {
    let mut url = Url::parse(base_url).map_err(|err| {
        io::Error::other(format!("invalid upstream base URL {base_url:?}: {err}"))
    })?;

    let base_path = url.path().trim_end_matches('/');
    let normalized_path = if path.is_empty() {
        "/".to_string()
    } else if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };

    let full_path = if base_path.is_empty() || base_path == "/" {
        normalized_path
    } else if normalized_path == "/" {
        base_path.to_string()
    } else {
        format!("{base_path}{normalized_path}")
    };

    url.set_path(&full_path);
    match query {
        Some(value) if !value.is_empty() => url.set_query(Some(value)),
        _ => url.set_query(None),
    }

    Ok(url)
}

fn filter_response_headers(headers: &HeaderMap) -> HeaderMap {
    let mut filtered = HeaderMap::new();

    for (name, value) in headers {
        if name == CONNECTION
            || name == CONTENT_LENGTH
            || name == TE
            || name == TRAILER
            || name == TRANSFER_ENCODING
            || name == UPGRADE
            || name.as_str().eq_ignore_ascii_case("keep-alive")
            || name.as_str().eq_ignore_ascii_case("proxy-authenticate")
            || name.as_str().eq_ignore_ascii_case("proxy-authorization")
        {
            continue;
        }

        filtered.append(name.clone(), value.clone());
    }

    filtered
}

fn normalize_path_prefix(prefix: &str) -> String {
    if prefix.is_empty() || prefix == "/" {
        "/".to_string()
    } else if prefix.starts_with('/') {
        prefix.trim_end_matches('/').to_string()
    } else {
        format!("/{}", prefix.trim_end_matches('/'))
    }
}

pub fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    if prefix == "/" {
        return true;
    }

    if path == prefix {
        return true;
    }

    path.strip_prefix(prefix)
        .is_some_and(|tail| tail.starts_with('/'))
}

fn path_tail_for_prefix(path: &str, prefix: &str) -> String {
    if prefix == "/" {
        return if path.is_empty() {
            "/".to_string()
        } else {
            path.to_string()
        };
    }

    if path == prefix {
        return "/".to_string();
    }

    path.strip_prefix(prefix)
        .map(ToString::to_string)
        .unwrap_or_else(|| path.to_string())
}

fn plain_response(status: StatusCode, message: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Body::from(message.to_string()))
        .expect("plain response should build")
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::env::remove_var;
    use std::fs;
    use std::sync::{Mutex, OnceLock};

    use base64::Engine;

    use super::{
        RequestContext, build_upstream_url, normalize_path_prefix, parse_config_headers_env,
        parse_config_text, path_matches_prefix, render_request_template, resolve_config_text,
        validate_request_placeholders,
    };
    use tempfile::tempdir;

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn path_prefix_matching_is_boundary_aware() {
        assert!(path_matches_prefix("/github/user", "/github"));
        assert!(path_matches_prefix("/github", "/github"));
        assert!(!path_matches_prefix("/githubish", "/github"));
    }

    #[test]
    fn normalize_path_prefix_handles_root_and_trailing_slashes() {
        assert_eq!(normalize_path_prefix(""), "/");
        assert_eq!(normalize_path_prefix("/github/"), "/github");
    }

    #[test]
    fn request_template_rendering_uses_context_values() {
        let context = RequestContext {
            method: "POST".to_string(),
            path: "/proxy/item".to_string(),
            path_tail: "/item".to_string(),
            query: Some("x=1".to_string()),
            headers: HashMap::from([("x-user-id".to_string(), "42".to_string())]),
            body_bytes: br#"{"ok":true}"#.to_vec(),
        };

        let rendered = render_request_template(
            "{{request.method}} {{request.path_tail}} {{request.query}} {{request.header.x-user-id}} {{request.body}}",
            &context,
        )
        .unwrap();

        assert_eq!(rendered, "POST /item x=1 42 {\"ok\":true}");
    }

    #[test]
    fn request_template_validation_rejects_unknown_placeholders() {
        let err = validate_request_placeholders("{{request.unknown}}", true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("unsupported request placeholder"));
    }

    #[test]
    fn upstream_url_building_preserves_base_path() {
        let url = build_upstream_url("https://example.com/api", "/v1/items", Some("x=1")).unwrap();
        assert_eq!(url.as_str(), "https://example.com/api/v1/items?x=1");
    }

    #[test]
    fn parse_config_text_supports_json_and_yaml() {
        assert!(
            parse_config_text(
                r#"{"listen":"127.0.0.1:8080","private_key":"/tmp/id_rsa","routes":[]}"#
            )
            .is_ok()
        );
        assert!(
            parse_config_text("listen: 127.0.0.1:8080\nprivate_key: /tmp/id_rsa\nroutes: []\n")
                .is_ok()
        );
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn resolve_config_text_uses_inline_yaml_and_path_and_base64() {
        let _guard = env_lock().lock().unwrap_or_else(|err| err.into_inner());
        let inline = "listen: 127.0.0.1:8080\nprivate_key: /tmp/id_rsa\nroutes: []\n";
        unsafe {
            std::env::set_var("VAULTICK_CONFIG", inline);
        }
        assert_eq!(resolve_config_text(None).await.unwrap(), inline);

        let dir = tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        fs::write(&path, inline).unwrap();
        unsafe {
            std::env::set_var("VAULTICK_CONFIG", path.to_string_lossy().to_string());
        }
        assert_eq!(resolve_config_text(None).await.unwrap(), inline);

        let encoded = base64::engine::general_purpose::STANDARD.encode(inline);
        unsafe {
            std::env::set_var("VAULTICK_CONFIG", encoded);
        }
        assert_eq!(resolve_config_text(None).await.unwrap(), inline);

        unsafe {
            remove_var("VAULTICK_CONFIG");
        }
    }

    #[test]
    fn parse_config_headers_env_accepts_json_object() {
        let _guard = env_lock().lock().unwrap_or_else(|err| err.into_inner());
        unsafe {
            std::env::set_var(
                "VAULTICK_CONFIG_HEADERS",
                r#"{"Authorization":"Bearer token","X-Test":"1"}"#,
            );
        }
        let headers = parse_config_headers_env().unwrap();
        assert!(headers.contains(&("Authorization".to_string(), "Bearer token".to_string())));
        assert!(headers.contains(&("X-Test".to_string(), "1".to_string())));
        unsafe {
            remove_var("VAULTICK_CONFIG_HEADERS");
        }
    }

    #[test]
    fn parse_config_headers_env_rejects_invalid_json() {
        let _guard = env_lock().lock().unwrap_or_else(|err| err.into_inner());
        unsafe {
            std::env::set_var("VAULTICK_CONFIG_HEADERS", "[1,2,3]");
        }
        let err = parse_config_headers_env().unwrap_err().to_string();
        assert!(err.contains("expected a JSON object"));
        unsafe {
            remove_var("VAULTICK_CONFIG_HEADERS");
        }
    }
}
