use std::env;
use tracing::{error, info, warn};

use dbx_redis_api::config::ConfigError;
use dbx_redis_api::server::{run_server, run_universal_server, ServerError};

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

    // Check which server mode to run
    let args: Vec<String> = env::args().collect();
    let use_universal =
        args.contains(&"--universal".to_string()) || env::var("DBX_UNIVERSAL_MODE").is_ok();

    let config_path = args
        .iter()
        .position(|arg| arg == "--config")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str());

    if use_universal {
        info!("Starting DBX Universal Server");
        if let Some(path) = config_path {
            info!("Using configuration file: {}", path);
        } else {
            info!("Using default configuration from environment variables");
        }

        if let Err(e) = run_universal_server(config_path).await {
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
    } else {
        info!("Starting DBX Legacy Redis Server");
        warn!("Running in legacy mode. Use --universal flag for the new universal API");

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
        let config_error = ServerError::Configuration(ConfigError::MissingEnvironmentVariable(
            "JWT_SECRET".to_string(),
        ));
        let error_string = format!("{}", config_error);
        assert!(error_string.contains("JWT_SECRET"));

        let db_error = ServerError::DatabaseConnection("Connection failed".to_string());
        let error_string = format!("{}", db_error);
        assert!(error_string.contains("Connection failed"));
    }

    #[test]
    fn test_server_error_debug() {
        let config_error = ServerError::Configuration(ConfigError::InvalidJwtSecret);
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
        let missing_env = ConfigError::MissingEnvironmentVariable("TEST_VAR".to_string());
        assert!(format!("{}", missing_env).contains("TEST_VAR"));

        let invalid_jwt = ConfigError::InvalidJwtSecret;
        assert!(format!("{}", invalid_jwt).contains("32 characters"));

        let missing_password = ConfigError::MissingDefaultAdminPassword;
        assert!(format!("{}", missing_password).contains("default admin"));
    }
}
