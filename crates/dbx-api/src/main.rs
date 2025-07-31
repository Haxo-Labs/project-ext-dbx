use std::env;
use tracing::{error, info};

use dbx_api::server::{run_server, ServerError};

#[tokio::main]
async fn main() {
    // Load .env file if it exists (ignore errors if file doesn't exist)
    if let Err(e) = dotenvy::dotenv() {
        // Only warn if the file exists but has issues, not if it's missing
        if e.to_string().contains("No such file") {
            // .env file doesn't exist, that's fine
        } else {
            tracing::warn!("Error loading .env file: {}", e);
        }
    }

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    // Get configuration file path if provided
    let args: Vec<String> = env::args().collect();
    let config_path = args
        .iter()
        .position(|arg| arg == "--config")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str());

    info!("Starting DBX Server");
    if let Some(path) = config_path {
        info!("Using configuration file: {}", path);
    } else {
        info!("Using default configuration from environment variables");
    }

    if let Err(e) = run_server(config_path).await {
        match e {
            ServerError::Configuration(config_err) => {
                error!("Configuration error: {}", config_err);
                error!("Make sure all required environment variables are set or provide a valid config file");
            }
            ServerError::DatabaseConnection(db_err) => {
                error!("Database connection error: {}", db_err);
                error!("Make sure all configured backends are accessible");
            }
            _ => {
                error!("Server error: {}", e);
            }
        }
        std::process::exit(1);
    }
}


