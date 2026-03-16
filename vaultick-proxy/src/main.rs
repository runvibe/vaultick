mod models;
mod routes;
mod services;

use std::path::PathBuf;

use clap::Parser;

use crate::models::StartupOverrides;

#[derive(Parser, Debug)]
#[command(name = "vaultick-proxy")]
#[command(about = "Config-driven reverse proxy for vaultick-backed secret forwarding")]
struct Cli {
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
    #[arg(long, value_name = "PATH")]
    db: Option<PathBuf>,
    #[arg(long, value_name = "WORKSPACE")]
    workspace: Option<String>,
    #[arg(long = "private-key", value_name = "PATH")]
    private_key: Option<PathBuf>,
    #[arg(long, value_name = "ADDR")]
    listen: Option<String>,
}

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let settings = services::load_settings(StartupOverrides {
        config_path: cli.config,
        db: cli.db,
        workspace: cli.workspace,
        private_key: cli.private_key,
        listen: cli.listen,
    })?;
    let app_state = services::build_state(&settings)?;
    let app = routes::router(app_state);

    let listener = tokio::net::TcpListener::bind(&settings.listen).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
