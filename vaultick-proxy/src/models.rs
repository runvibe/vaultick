use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyConfigFile {
    pub listen: String,
    pub db: Option<PathBuf>,
    pub workspace: Option<String>,
    pub private_key: Option<PathBuf>,
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RouteConfig {
    #[serde(rename = "match")]
    pub route_match: RouteMatchConfig,
    pub forward: ForwardConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RouteMatchConfig {
    pub path_prefix: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ForwardConfig {
    pub base_url: String,
    pub method: Option<String>,
    pub path: Option<String>,
    pub query: Option<String>,
    #[serde(default)]
    pub pass_query: bool,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    pub body: Option<String>,
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct StartupOverrides {
    pub config_path: PathBuf,
    pub db: Option<PathBuf>,
    pub workspace: Option<String>,
    pub private_key: Option<PathBuf>,
    pub listen: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ResolvedSettings {
    pub listen: String,
    pub db_path: PathBuf,
    pub workspace: String,
    pub private_key_path: PathBuf,
    pub routes: Vec<RouteConfig>,
}

#[derive(Debug, Clone)]
pub struct CompiledRoute {
    pub path_prefix: String,
    pub base_url: String,
    pub method_template: Option<String>,
    pub path_template: String,
    pub query_template: Option<String>,
    pub pass_query: bool,
    pub headers: Vec<(String, String)>,
    pub body_template: Option<String>,
    pub timeout: Option<Duration>,
    pub redacted_values: Vec<String>,
}

#[derive(Debug)]
pub struct AppState {
    pub client: Client,
    pub routes: Vec<CompiledRoute>,
}

pub type SharedAppState = Arc<AppState>;

#[derive(Debug, Clone)]
pub struct RequestContext {
    pub method: String,
    pub path: String,
    pub path_tail: String,
    pub query: Option<String>,
    pub headers: HashMap<String, String>,
    pub body_bytes: Vec<u8>,
}
