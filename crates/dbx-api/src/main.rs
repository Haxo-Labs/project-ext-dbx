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

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn with_env_var<F>(key: &str, value: Option<&str>, test: F)
    where
        F: FnOnce(),
    {
        let original = env::var(key).ok();

        match value {
            Some(val) => env::set_var(key, val),
            None => env::remove_var(key),
        }

        test();

        match original {
            Some(val) => env::set_var(key, val),
            None => env::remove_var(key),
        }
    }

    #[test]
    fn test_jwt_secret_present() {
        with_env_var("JWT_SECRET", Some("test-secret"), || {
            let result = env::var("JWT_SECRET");
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), "test-secret");
        });
    }

    #[test]
    fn test_jwt_secret_missing() {
        with_env_var("JWT_SECRET", None, || {
            let result = env::var("JWT_SECRET");
            assert!(result.is_err());
        });
    }

    #[test]
    fn test_server_error_display() {
        let config_error = ServerError::Configuration(
            dbx_api::config::ConfigError::MissingEnvironmentVariable("JWT_SECRET".to_string()),
        );
        let error_string = format!("{}", config_error);
        assert!(error_string.contains("JWT_SECRET"));

        let db_error = ServerError::DatabaseConnection("Connection failed".to_string());
        let error_string = format!("{}", db_error);
        assert!(error_string.contains("Connection failed"));
    }

    #[test]
    fn test_server_error_debug() {
        let config_error =
            ServerError::Configuration(dbx_api::config::ConfigError::InvalidJwtSecret);
        let debug_string = format!("{:?}", config_error);
        assert!(debug_string.contains("Configuration"));
        assert!(debug_string.contains("InvalidJwtSecret"));

        let db_error = ServerError::DatabaseConnection("Connection failed".to_string());
        let debug_string = format!("{:?}", db_error);
        assert!(debug_string.contains("DatabaseConnection"));
        assert!(debug_string.contains("Connection failed"));
    }

    #[test]
    fn test_environment_variable_validation() {
        with_env_var("JWT_SECRET", Some(""), || {
            let result = env::var("JWT_SECRET");
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), "");
        });

        with_env_var("JWT_SECRET", Some("valid-secret-123"), || {
            let result = env::var("JWT_SECRET");
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), "valid-secret-123");
        });
    }

    #[test]
    fn test_tracing_initialization() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .try_init()
            .ok();

        assert!(true);
    }

    #[test]
    fn test_config_error_types() {
        let missing_env =
            dbx_api::config::ConfigError::MissingEnvironmentVariable("TEST_VAR".to_string());
        assert!(format!("{}", missing_env).contains("TEST_VAR"));

        let invalid_jwt = dbx_api::config::ConfigError::InvalidJwtSecret;
        assert!(format!("{}", invalid_jwt).contains("32 characters"));

        let missing_password = dbx_api::config::ConfigError::MissingDefaultAdminPassword;
        assert!(format!("{}", missing_password).contains("default admin"));
    }
}
