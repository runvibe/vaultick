mod models;
mod routes;
mod runtime;
mod services;

use std::path::PathBuf;

use clap::Parser;
use vaultick_request::BoxError;

use crate::models::StartupOverrides;

#[derive(Parser, Debug)]
#[command(name = "vaultick-mcp")]
#[command(about = "Local MCP HTTP/SSE server for safe vaultick-backed tools")]
struct Cli {
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,
    #[arg(long, value_name = "ADDR")]
    listen: Option<String>,
    #[arg(long, value_name = "TOKEN")]
    token: Option<String>,
    #[arg(long, value_name = "PATH")]
    db: Option<PathBuf>,
    #[arg(long, value_name = "WORKSPACE")]
    workspace: Option<String>,
    #[arg(long = "private-key", value_name = "PATH")]
    private_key: Option<PathBuf>,
    #[arg(long = "allow-command", value_name = "COMMAND_PREFIX")]
    allow_command: Vec<String>,
}

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), BoxError> {
    let cli = Cli::parse();
    let settings = services::load_settings(StartupOverrides {
        config_path: cli.config,
        listen: cli.listen,
        token: cli.token,
        db: cli.db,
        workspace: cli.workspace,
        private_key: cli.private_key,
        allow_commands: cli.allow_command,
    })?;
    let listen_addr = settings.listen.clone();
    let app_state = services::build_state(settings)?;
    let app = routes::router(app_state);
    let listener = tokio::net::TcpListener::bind(listen_addr).await?;

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
