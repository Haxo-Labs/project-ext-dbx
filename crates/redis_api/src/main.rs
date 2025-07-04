use std::env;
use tracing::{error, info};

use dbx_redis_api::server::{run_server, ServerError};

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    // Check if JWT secret is provided
    if env::var("JWT_SECRET").is_err() {
        error!("JWT_SECRET environment variable is required!");
        error!("   Set a secure secret: export JWT_SECRET='dbx-jwt-secret'");
        std::process::exit(1);
    }

    info!("Starting DBX");
    
    if let Err(e) = run_server().await {
        match e {
            ServerError::Configuration(config_err) => {
                error!("Configuration error: {}", config_err);
                error!("Make sure all required environment variables are set");
            }
            ServerError::DatabaseConnection(db_err) => {
                error!("Database connection error: {}", db_err);
                error!("Make sure Redis is running and REDIS_URL is correct");
            }
            _ => {
                error!("Server error: {}", e);
            }
        }
        std::process::exit(1);
    }
}
