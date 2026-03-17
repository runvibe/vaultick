use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;
use vaultick_request::AsyncClient;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct McpConfigFile {
    pub listen: Option<String>,
    pub token: Option<String>,
    pub db: Option<PathBuf>,
    pub workspace: Option<String>,
    pub private_key: Option<PathBuf>,
    #[serde(default)]
    pub exec_allowlist: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct StartupOverrides {
    pub config_path: Option<PathBuf>,
    pub listen: Option<String>,
    pub token: Option<String>,
    pub db: Option<PathBuf>,
    pub workspace: Option<String>,
    pub private_key: Option<PathBuf>,
    pub allow_commands: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ResolvedSettings {
    pub listen: String,
    pub token: String,
    pub db_path: PathBuf,
    pub workspace: String,
    pub private_key_path: PathBuf,
    pub exec_allowlist: Vec<ExecAllowPattern>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecAllowPattern {
    pub raw: String,
    pub tokens: Vec<String>,
}

#[derive(Debug)]
pub struct AppState {
    pub client: AsyncClient,
    pub sessions: Mutex<HashMap<String, SessionState>>,
    pub settings: ResolvedSettings,
}

pub type SharedAppState = Arc<AppState>;

#[derive(Debug, Clone)]
pub struct SessionState {
    pub id: String,
    pub protocol_version: String,
    pub initialized: bool,
    pub log_level: LogLevel,
}

impl SessionState {
    pub fn new(protocol_version: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            protocol_version,
            initialized: false,
            log_level: LogLevel::Info,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Debug,
    Info,
    Notice,
    Warning,
    Error,
    Critical,
    Alert,
    Emergency,
}

impl LogLevel {
    pub fn parse(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "debug" => Some(Self::Debug),
            "info" => Some(Self::Info),
            "notice" => Some(Self::Notice),
            "warning" => Some(Self::Warning),
            "error" => Some(Self::Error),
            "critical" => Some(Self::Critical),
            "alert" => Some(Self::Alert),
            "emergency" => Some(Self::Emergency),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoggingNotificationParams {
    pub level: &'static str,
    pub logger: &'static str,
    pub data: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ToolCallParams {
    pub name: String,
    #[serde(default)]
    pub arguments: Option<Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExecArguments {
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub all: bool,
    #[serde(default)]
    pub assignments: HashMap<String, String>,
    #[serde(default)]
    pub stream: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RequestArguments {
    pub url: String,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub stream: bool,
}

#[derive(Debug, Clone)]
pub struct ExecResult {
    pub program: String,
    pub args: Vec<String>,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone)]
pub struct RequestResult {
    pub url: String,
    pub method: String,
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub ok: bool,
}

#[derive(Debug, Clone)]
pub struct RequestExecution {
    pub request: vaultick_request::ResolvedRequest,
    pub redacted_values: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ExecExecution {
    pub program: String,
    pub args: Vec<String>,
    pub env_vars: Vec<(String, String)>,
    pub redacted_values: Vec<String>,
}

pub const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:4040";
pub const DEFAULT_WORKSPACE_NAME: &str = "default";
pub const DEFAULT_DB_DIRECTORY: &str = "databases";
pub const DEFAULT_DB_FILENAME: &str = "database.db";
pub const DEFAULT_PROTOCOL_VERSION: &str = "2025-06-18";
pub const MCP_SESSION_HEADER: &str = "mcp-session-id";
pub const MCP_PROTOCOL_HEADER: &str = "mcp-protocol-version";
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
