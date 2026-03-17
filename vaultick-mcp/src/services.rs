use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, MutexGuard};

use axum::body::Body;
use axum::extract::Request;
use axum::http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use axum::http::{Response, StatusCode};
use axum::response::IntoResponse;
use axum::response::sse::{Event, KeepAlive, Sse};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio_stream::wrappers::UnboundedReceiverStream;
use vaultick::Vaultick;
use vaultick_request::{AsyncClient, BoxError};

use crate::models::{
    AppState, DEFAULT_DB_DIRECTORY, DEFAULT_DB_FILENAME, DEFAULT_LISTEN_ADDR,
    DEFAULT_PROTOCOL_VERSION, DEFAULT_WORKSPACE_NAME, JsonRpcError,
    JsonRpcRequest, JsonRpcResponse, KEEPALIVE_INTERVAL, LogLevel, LoggingNotificationParams,
    MCP_PROTOCOL_HEADER, MCP_SESSION_HEADER, McpConfigFile, ResolvedSettings,
    SessionState, SharedAppState, StartupOverrides, ToolCallParams,
};
use crate::runtime::{
    execute_request, parse_exec_allow_patterns, parse_exec_arguments, parse_request_arguments,
    resolve_exec_execution, resolve_request_execution, run_exec_execution,
};

const VAULTICK_HOME_ENV_VAR: &str = "VAULTICK_HOME";
const VAULTICK_WORKSPACE_ENV_VAR: &str = "VAULTICK_WORKSPACE";
const VAULTICK_MCP_LISTEN_ENV_VAR: &str = "VAULTICK_MCP_LISTEN";
const VAULTICK_MCP_TOKEN_ENV_VAR: &str = "VAULTICK_MCP_TOKEN";
const VAULTICK_MCP_DB_ENV_VAR: &str = "VAULTICK_MCP_DB";
const VAULTICK_MCP_PRIVATE_KEY_ENV_VAR: &str = "VAULTICK_MCP_PRIVATE_KEY";
const VAULTICK_MCP_EXEC_ALLOWLIST_ENV_VAR: &str = "VAULTICK_MCP_EXEC_ALLOWLIST";

const JSONRPC_PARSE_ERROR: i32 = -32700;
const JSONRPC_INVALID_REQUEST: i32 = -32600;
const JSONRPC_METHOD_NOT_FOUND: i32 = -32601;
const JSONRPC_INVALID_PARAMS: i32 = -32602;
const JSONRPC_INTERNAL_ERROR: i32 = -32603;

pub fn load_settings(overrides: StartupOverrides) -> Result<ResolvedSettings, BoxError> {
    let file_config = if let Some(path) = overrides.config_path.as_deref() {
        let contents = fs::read_to_string(path)?;
        parse_config_text(&contents)?
    } else {
        McpConfigFile::default()
    };

    let listen = overrides
        .listen
        .or_else(|| read_env_var(VAULTICK_MCP_LISTEN_ENV_VAR))
        .or(file_config.listen)
        .unwrap_or_else(|| DEFAULT_LISTEN_ADDR.to_string());
    if !listen.starts_with("127.0.0.1:") {
        return Err(io::Error::other("vaultick-mcp must bind to 127.0.0.1 in v1").into());
    }

    let token = overrides
        .token
        .or_else(|| read_env_var(VAULTICK_MCP_TOKEN_ENV_VAR))
        .or(file_config.token)
        .ok_or_else(|| io::Error::other("missing MCP token; pass --token, set VAULTICK_MCP_TOKEN, or use --config"))?;

    let db_path = if let Some(path) = overrides.db {
        path
    } else if let Some(path) = read_env_var(VAULTICK_MCP_DB_ENV_VAR).map(PathBuf::from) {
        path
    } else if let Some(path) = file_config.db {
        path
    } else {
        resolve_default_db_path()?
    };

    let workspace = overrides
        .workspace
        .or_else(|| read_env_var(VAULTICK_WORKSPACE_ENV_VAR))
        .or(file_config.workspace)
        .unwrap_or_else(|| DEFAULT_WORKSPACE_NAME.to_string());

    let private_key_path = overrides
        .private_key
        .or_else(|| read_env_var(VAULTICK_MCP_PRIVATE_KEY_ENV_VAR).map(PathBuf::from))
        .or(file_config.private_key)
        .ok_or_else(|| io::Error::other("missing private key path; pass --private-key, set VAULTICK_MCP_PRIVATE_KEY, or use --config"))?;

    let allowlist_inputs = if !overrides.allow_commands.is_empty() {
        overrides.allow_commands
    } else if let Some(raw) = read_env_var(VAULTICK_MCP_EXEC_ALLOWLIST_ENV_VAR) {
        raw.split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect()
    } else {
        file_config.exec_allowlist
    };

    Ok(ResolvedSettings {
        listen,
        token,
        db_path,
        workspace,
        private_key_path,
        exec_allowlist: parse_exec_allow_patterns(&allowlist_inputs)?,
    })
}

pub fn build_state(settings: ResolvedSettings) -> Result<SharedAppState, BoxError> {
    let _ = Vaultick::open(&settings.db_path)?;
    Ok(Arc::new(AppState {
        client: AsyncClient::builder().build()?,
        sessions: std::sync::Mutex::new(HashMap::new()),
        settings,
    }))
}

pub async fn handle_sse(state: SharedAppState, request: Request<Body>) -> Response<Body> {
    if let Err(response) = authorize(&state, &request) {
        return *response;
    }

    let session_id = match required_session_id(&request) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let protocol = match required_protocol_header(&request) {
        Ok(value) => value,
        Err(response) => return *response,
    };

    let sessions = match state.sessions.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let Some(session) = sessions.get(&session_id) else {
        return plain_response(StatusCode::NOT_FOUND, "unknown MCP session");
    };
    if session.protocol_version != protocol {
        return plain_response(StatusCode::BAD_REQUEST, "protocol version mismatch");
    }
    drop(sessions);

    let stream = futures_util::stream::pending::<Result<Event, std::convert::Infallible>>();
    Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(KEEPALIVE_INTERVAL)
                .text("keepalive"),
        )
        .into_response()
}

pub async fn handle_delete_session(
    state: SharedAppState,
    request: Request<Body>,
) -> Response<Body> {
    if let Err(response) = authorize(&state, &request) {
        return *response;
    }

    let session_id = match required_session_id(&request) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    if let Err(response) = required_protocol_header(&request) {
        return *response;
    }

    let mut sessions = match state.sessions.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    sessions.remove(&session_id);
    StatusCode::NO_CONTENT.into_response()
}

pub async fn handle_message(state: SharedAppState, request: Request<Body>) -> Response<Body> {
    if let Err(response) = authorize(&state, &request) {
        return *response;
    }

    let accept_sse = request
        .headers()
        .get(ACCEPT)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.contains("text/event-stream"))
        .unwrap_or(false);

    let protocol_header = request
        .headers()
        .get(MCP_PROTOCOL_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    let session_header = request
        .headers()
        .get(MCP_SESSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);

    let body_bytes = match axum::body::to_bytes(request.into_body(), usize::MAX).await {
        Ok(bytes) => bytes,
        Err(err) => {
            return json_error_response(None, JSONRPC_INVALID_REQUEST, &format!("failed to read request body: {err}"));
        }
    };
    let payload = if body_bytes.is_empty() {
        return json_error_response(None, JSONRPC_INVALID_REQUEST, "empty request body");
    } else {
        body_bytes
    };

    let raw_value: Value = match serde_json::from_slice(&payload) {
        Ok(value) => value,
        Err(err) => return json_error_response(None, JSONRPC_PARSE_ERROR, &format!("invalid JSON-RPC payload: {err}")),
    };
    if raw_value.is_array() {
        return json_error_response(None, JSONRPC_INVALID_REQUEST, "batch requests are not supported");
    }
    let rpc_request: JsonRpcRequest = match serde_json::from_value(raw_value) {
        Ok(request) => request,
        Err(err) => return json_error_response(None, JSONRPC_INVALID_REQUEST, &format!("invalid JSON-RPC request: {err}")),
    };
    if rpc_request.jsonrpc != "2.0" {
        return json_error_response(rpc_request.id.clone(), JSONRPC_INVALID_REQUEST, "jsonrpc must be \"2.0\"");
    }

    if rpc_request.method == "initialize" {
        return handle_initialize(state, rpc_request).await;
    }

    let session_id = match session_header {
        Some(value) => value,
        None => return plain_response(StatusCode::BAD_REQUEST, "missing mcp-session-id header"),
    };
    let protocol_version = match protocol_header {
        Some(value) => value,
        None => return plain_response(StatusCode::BAD_REQUEST, "missing mcp-protocol-version header"),
    };

    {
        let mut sessions = lock_sessions(&state);
        let Some(session) = sessions.get_mut(&session_id) else {
            return plain_response(StatusCode::NOT_FOUND, "unknown MCP session");
        };
        if session.protocol_version != protocol_version {
            return plain_response(StatusCode::BAD_REQUEST, "protocol version mismatch");
        }

        match rpc_request.method.as_str() {
            "notifications/initialized" => {
                session.initialized = true;
                return StatusCode::ACCEPTED.into_response();
            }
            "logging/setLevel" => {
                let response = handle_logging_set_level(&rpc_request, session);
                return json_response(response, Some(&session.id));
            }
            _ => {
                if !session.initialized {
                    return json_error_response(
                        rpc_request.id.clone(),
                        JSONRPC_INVALID_REQUEST,
                        "session is not initialized",
                    );
                }
            }
        }
    }

    dispatch_request(state, session_id, accept_sse, rpc_request).await
}

async fn handle_initialize(state: SharedAppState, request: JsonRpcRequest) -> Response<Body> {
    let params = request.params.clone().unwrap_or_else(|| json!({}));
    let protocol_version = params
        .get("protocolVersion")
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_PROTOCOL_VERSION)
        .to_string();

    let session = SessionState::new(protocol_version.clone());
    let session_id = session.id.clone();
    lock_sessions(&state).insert(session_id.clone(), session);

    let response = JsonRpcResponse {
        jsonrpc: "2.0",
        id: request.id,
        result: Some(json!({
            "protocolVersion": protocol_version,
            "capabilities": {
                "tools": {
                    "listChanged": false
                },
                "logging": {}
            },
            "serverInfo": {
                "name": "vaultick-mcp",
                "version": env!("CARGO_PKG_VERSION")
            },
            "instructions": "Use vaultick.exec and vaultick.request for safe command and HTTP access without revealing stored secrets."
        })),
        error: None,
    };

    let mut axum_response = json_response(response, Some(&session_id));
    axum_response.headers_mut().insert(
        MCP_PROTOCOL_HEADER,
        HeaderValue::from_str(&protocol_version).unwrap_or_else(|_| HeaderValue::from_static(DEFAULT_PROTOCOL_VERSION)),
    );
    axum_response
}

async fn dispatch_request(
    state: SharedAppState,
    session_id: String,
    accept_sse: bool,
    request: JsonRpcRequest,
) -> Response<Body> {
    match request.method.as_str() {
        "ping" => json_response(
            JsonRpcResponse {
                jsonrpc: "2.0",
                id: request.id,
                result: Some(json!({})),
                error: None,
            },
            Some(&session_id),
        ),
        "tools/list" => json_response(
            JsonRpcResponse {
                jsonrpc: "2.0",
                id: request.id,
                result: Some(json!({
                    "tools": [exec_tool_schema(), request_tool_schema()]
                })),
                error: None,
            },
            Some(&session_id),
        ),
        "tools/call" => handle_tools_call(state, session_id, accept_sse, request).await,
        _ => json_error_response(
            request.id,
            JSONRPC_METHOD_NOT_FOUND,
            &format!("method not found: {}", request.method),
        ),
    }
}

async fn handle_tools_call(
    state: SharedAppState,
    session_id: String,
    accept_sse: bool,
    request: JsonRpcRequest,
) -> Response<Body> {
    let params = match serde_json::from_value::<ToolCallParams>(
        request.params.clone().unwrap_or_else(|| json!({})),
    ) {
        Ok(params) => params,
        Err(err) => {
            return json_error_response(
                request.id,
                JSONRPC_INVALID_PARAMS,
                &format!("invalid tool call params: {err}"),
            )
        }
    };

    match params.name.as_str() {
        "vaultick.exec" => handle_exec_tool(state, session_id, accept_sse, request.id, params).await,
        "vaultick.request" => handle_request_tool(state, session_id, accept_sse, request.id, params).await,
        _ => json_error_response(
            request.id,
            JSONRPC_INVALID_PARAMS,
            &format!("unknown tool: {}", params.name),
        ),
    }
}

async fn handle_exec_tool(
    state: SharedAppState,
    session_id: String,
    accept_sse: bool,
    request_id: Option<Value>,
    params: ToolCallParams,
) -> Response<Body> {
    let arguments = match parse_exec_arguments(params.arguments.as_ref()) {
        Ok(arguments) => arguments,
        Err(err) => return json_error_response(request_id, JSONRPC_INVALID_PARAMS, &err.to_string()),
    };

    let vaultick = match Vaultick::open(&state.settings.db_path) {
        Ok(store) => store,
        Err(err) => return json_error_response(request_id, JSONRPC_INTERNAL_ERROR, &err.to_string()),
    };
    let execution = match resolve_exec_execution(
        &vaultick,
        &state.settings.workspace,
        &state.settings.private_key_path,
        &state.settings.exec_allowlist,
        &arguments,
    ) {
        Ok(execution) => execution,
        Err(err) => {
            return json_response(
                tool_result_response(
                    request_id,
                    tool_error(
                        "vaultick.exec failed",
                        json!({"message": err.to_string()}),
                    ),
                ),
                Some(&session_id),
            )
        }
    };

    let result = match tokio::task::block_in_place(|| run_exec_execution(&execution)) {
        Ok(result) => result,
        Err(err) => {
            return json_response(
                tool_result_response(
                    request_id,
                    tool_error(
                        "vaultick.exec failed",
                        json!({"message": err.to_string()}),
                    ),
                ),
                Some(&session_id),
            )
        }
    };

    let response = tool_result_response(
        request_id,
        json!({
            "content": [{
                "type": "text",
                "text": format!("exit_code={} stdout_bytes={} stderr_bytes={}", result.exit_code, result.stdout.len(), result.stderr.len())
            }],
            "structuredContent": {
                "program": result.program,
                "args": result.args,
                "exit_code": result.exit_code,
                "stdout": result.stdout,
                "stderr": result.stderr
            },
            "isError": result.exit_code != 0
        }),
    );

    if accept_sse && arguments.stream {
        return sse_single_response(response, Some(&session_id));
    }

    json_response(response, Some(&session_id))
}

async fn handle_request_tool(
    state: SharedAppState,
    session_id: String,
    accept_sse: bool,
    request_id: Option<Value>,
    params: ToolCallParams,
) -> Response<Body> {
    let arguments = match parse_request_arguments(params.arguments.as_ref()) {
        Ok(arguments) => arguments,
        Err(err) => return json_error_response(request_id, JSONRPC_INVALID_PARAMS, &err.to_string()),
    };
    let use_sse_response = accept_sse && arguments.stream;

    let vaultick = match Vaultick::open(&state.settings.db_path) {
        Ok(store) => store,
        Err(err) => return json_error_response(request_id, JSONRPC_INTERNAL_ERROR, &err.to_string()),
    };
    let execution = match resolve_request_execution(
        &vaultick,
        &state.settings.workspace,
        &state.settings.private_key_path,
        &arguments,
    ) {
        Ok(execution) => execution,
        Err(err) => {
            return json_response(
                tool_result_response(
                    request_id,
                    tool_error(
                        "vaultick.request failed",
                        json!({"message": err.to_string()}),
                    ),
                ),
                Some(&session_id),
            )
        }
    };

    if use_sse_response {
        let (tx, rx) = mpsc::unbounded_channel::<Result<Event, std::convert::Infallible>>();
        let client = state.client.clone();
        tokio::spawn(async move {
            let chunk_tx = tx.clone();
            let result = execute_request(&client, &execution, move |chunk| {
                let _ = chunk_tx.send(Ok(sse_event(notification_message(
                    "info",
                    "vaultick.request.body",
                    chunk,
                ))));
            })
            .await;
            let response = match result {
                Ok(result) => tool_result_response(
                    request_id,
                    json!({
                        "content": [{
                            "type": "text",
                            "text": result.body
                        }],
                        "structuredContent": {
                            "url": result.url,
                            "method": result.method,
                            "status": result.status,
                            "headers": result.headers,
                            "body": result.body,
                            "ok": result.ok
                        },
                        "isError": !result.ok
                    }),
                ),
                Err(err) => tool_result_response(
                    request_id,
                    tool_error(
                        "vaultick.request failed",
                        json!({"message": err.to_string()}),
                    ),
                ),
            };
            let _ = tx.send(Ok(sse_event(response)));
            drop(tx);
        });

        let stream = UnboundedReceiverStream::new(rx);
        return sse_response(stream, Some(&session_id));
    }

    let result = match execute_request(&state.client, &execution, |_| {}).await {
        Ok(result) => result,
        Err(err) => {
            return json_response(
                tool_result_response(
                    request_id,
                    tool_error(
                        "vaultick.request failed",
                        json!({"message": err.to_string()}),
                    ),
                ),
                Some(&session_id),
            )
        }
    };

    json_response(
        tool_result_response(
            request_id,
            json!({
                "content": [{
                    "type": "text",
                    "text": result.body
                }],
                "structuredContent": {
                    "url": result.url,
                    "method": result.method,
                    "status": result.status,
                    "headers": result.headers,
                    "body": result.body,
                    "ok": result.ok
                },
                "isError": !result.ok
            }),
        ),
        Some(&session_id),
    )
}

fn exec_tool_schema() -> Value {
    json!({
        "name": "vaultick.exec",
        "description": "Execute an allowlisted local command with vaultick-backed secret injection and redacted output.",
        "inputSchema": {
            "type": "object",
            "required": ["program"],
            "properties": {
                "program": { "type": "string" },
                "args": { "type": "array", "items": { "type": "string" } },
                "env": { "type": "array", "items": { "type": "string" } },
                "all": { "type": "boolean" },
                "assignments": {
                    "type": "object",
                    "additionalProperties": { "type": "string" }
                },
                "stream": { "type": "boolean" }
            },
            "additionalProperties": false
        }
    })
}

fn request_tool_schema() -> Value {
    json!({
        "name": "vaultick.request",
        "description": "Execute an outbound HTTP request with vaultick-backed secret substitution and redacted responses.",
        "inputSchema": {
            "type": "object",
            "required": ["url"],
            "properties": {
                "url": { "type": "string" },
                "method": { "type": "string" },
                "headers": {
                    "type": "object",
                    "additionalProperties": { "type": "string" }
                },
                "body": { "type": "string" },
                "timeout_ms": { "type": "integer", "minimum": 1 },
                "stream": { "type": "boolean" }
            },
            "additionalProperties": false
        }
    })
}

fn handle_logging_set_level(
    request: &JsonRpcRequest,
    session: &mut SessionState,
) -> JsonRpcResponse {
    let level = request
        .params
        .as_ref()
        .and_then(|params| params.get("level"))
        .and_then(Value::as_str)
        .and_then(LogLevel::parse);

    match level {
        Some(level) => {
            session.log_level = level;
            JsonRpcResponse {
                jsonrpc: "2.0",
                id: request.id.clone(),
                result: Some(json!({})),
                error: None,
            }
        }
        None => JsonRpcResponse {
            jsonrpc: "2.0",
            id: request.id.clone(),
            result: None,
            error: Some(JsonRpcError {
                code: JSONRPC_INVALID_PARAMS,
                message: "invalid logging level".to_string(),
                data: None,
            }),
        },
    }
}

fn authorize(state: &SharedAppState, request: &Request<Body>) -> Result<(), Box<Response<Body>>> {
    let expected = format!("Bearer {}", state.settings.token);
    let authorized = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(|value| value == expected)
        .unwrap_or(false);

    if authorized {
        return Ok(());
    }

    let mut response = plain_response(StatusCode::UNAUTHORIZED, "unauthorized");
    response.headers_mut().insert(
        axum::http::header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer"),
    );
    Err(Box::new(response))
}

fn required_session_id(request: &Request<Body>) -> Result<String, Box<Response<Body>>> {
    request
        .headers()
        .get(MCP_SESSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string)
        .ok_or_else(|| {
            Box::new(plain_response(
                StatusCode::BAD_REQUEST,
                "missing mcp-session-id header",
            ))
        })
}

fn required_protocol_header(request: &Request<Body>) -> Result<String, Box<Response<Body>>> {
    request
        .headers()
        .get(MCP_PROTOCOL_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string)
        .ok_or_else(|| {
            Box::new(plain_response(
                StatusCode::BAD_REQUEST,
                "missing mcp-protocol-version header",
            ))
        })
}

fn parse_config_text(input: &str) -> Result<McpConfigFile, BoxError> {
    if let Ok(config) = serde_json::from_str::<McpConfigFile>(input) {
        return Ok(config);
    }

    Ok(serde_yaml::from_str::<McpConfigFile>(input)?)
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

fn read_env_var(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn plain_response(status: StatusCode, message: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(Body::from(message.to_string()))
        .expect("plain response should build")
}

fn json_error_response(id: Option<Value>, code: i32, message: &str) -> Response<Body> {
    json_response(
        JsonRpcResponse {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.to_string(),
                data: None,
            }),
        },
        None,
    )
}

fn json_response(response: JsonRpcResponse, session_id: Option<&str>) -> Response<Body> {
    let body = serde_json::to_vec(&response).expect("json-rpc response should serialize");
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    if let Some(session_id) = session_id {
        builder = builder.header(MCP_SESSION_HEADER, session_id);
    }
    builder
        .body(Body::from(body))
        .expect("json response should build")
}

fn sse_single_response(response: JsonRpcResponse, session_id: Option<&str>) -> Response<Body> {
    let event_stream = futures_util::stream::iter(vec![Ok::<Event, std::convert::Infallible>(
        sse_event(response),
    )]);
    sse_response(event_stream, session_id)
}

fn sse_response<S>(stream: S, session_id: Option<&str>) -> Response<Body>
where
    S: futures_util::Stream<Item = Result<Event, std::convert::Infallible>> + Send + 'static,
{
    let mut response = Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(KEEPALIVE_INTERVAL)
                .text("keepalive"),
        )
        .into_response();
    if let Some(session_id) = session_id {
        response.headers_mut().insert(
            MCP_SESSION_HEADER,
            HeaderValue::from_str(session_id).unwrap_or_else(|_| HeaderValue::from_static("invalid")),
        );
    }
    response
}

fn sse_event<T: serde::Serialize>(payload: T) -> Event {
    Event::default()
        .event("message")
        .data(serde_json::to_string(&payload).expect("sse payload should serialize"))
}

fn notification_message(level: &'static str, logger: &'static str, data: String) -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": "notifications/message",
        "params": LoggingNotificationParams { level, logger, data }
    })
}

fn tool_result_response(id: Option<Value>, result: Value) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0",
        id,
        result: Some(result),
        error: None,
    }
}

fn tool_error(summary: &str, structured: Value) -> Value {
    json!({
        "content": [{
            "type": "text",
            "text": summary
        }],
        "structuredContent": structured,
        "isError": true
    })
}

fn lock_sessions(state: &SharedAppState) -> MutexGuard<'_, HashMap<String, SessionState>> {
    match state.sessions.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;

    use super::{JSONRPC_INVALID_REQUEST, json_error_response, load_settings, parse_config_text};
    use crate::models::StartupOverrides;

    #[test]
    fn parse_config_text_supports_json_and_yaml() {
        let yaml = r#"
listen: 127.0.0.1:4040
token: secret
private_key: /tmp/id_rsa
exec_allowlist:
  - git
"#;
        let json = r#"{"listen":"127.0.0.1:4040","token":"secret","private_key":"/tmp/id_rsa","exec_allowlist":["git"]}"#;
        assert_eq!(parse_config_text(yaml).unwrap().token.as_deref(), Some("secret"));
        assert_eq!(parse_config_text(json).unwrap().token.as_deref(), Some("secret"));
    }

    #[test]
    fn load_settings_rejects_non_loopback_listen_addresses() {
        let err = load_settings(StartupOverrides {
            config_path: None,
            listen: Some("0.0.0.0:4040".to_string()),
            token: Some("secret".to_string()),
            db: Some("/tmp/test.db".into()),
            workspace: Some("default".to_string()),
            private_key: Some("/tmp/id_rsa".into()),
            allow_commands: vec!["git".to_string()],
        })
        .unwrap_err();

        assert!(err.to_string().contains("127.0.0.1"));
    }

    #[test]
    fn json_error_response_returns_json_rpc_error_shape() {
        let response = json_error_response(None, JSONRPC_INVALID_REQUEST, "bad request");
        assert_eq!(response.status(), StatusCode::OK);
    }
}
