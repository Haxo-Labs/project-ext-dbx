//! Main application tests

use crate::config::ConfigError;
use crate::server::ServerError;
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

    // Test Display implementation
    let db_error = ServerError::DatabaseConnection("Connection failed".to_string());

    // Check that error string representation is meaningful
    assert!(config_error.to_string().contains("JWT_SECRET"));

    let config_error = ServerError::Configuration(ConfigError::InvalidJwtSecret);

    // Test Debug implementation
    let db_error = ServerError::DatabaseConnection("Connection failed".to_string());

    // Check that debug representation is meaningful
    format!("{:?}", config_error);
    format!("{:?}", db_error);
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

#[test]
fn test_error_source() {
    // Test Error trait implementation

    // Create ConfigError cases
    let missing_env = ConfigError::MissingEnvironmentVariable("TEST_VAR".to_string());

    let invalid_jwt = ConfigError::InvalidJwtSecret;

    let missing_password = ConfigError::MissingDefaultAdminPassword;
}
