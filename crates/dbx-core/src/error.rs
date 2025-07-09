use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Error type for DBX operations
#[derive(Error, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "data")]
pub enum DbxError {
    /// Connection-related errors
    #[error("Connection error for backend '{backend}': {message}")]
    Connection { backend: String, message: String },

    /// Operation not supported by backend
    #[error("Operation '{operation}' not supported by backend '{backend}'")]
    UnsupportedOperation { operation: String, backend: String },

    /// Backend routing errors
    #[error("Backend routing failed: {message}")]
    Routing { message: String },

    /// Data validation errors
    #[error("Data validation error: {message}")]
    Validation {
        message: String,
        field: Option<String>,
    },

    /// Serialization/deserialization errors
    #[error("Serialization error: {message}")]
    Serialization { message: String },

    /// Authentication/authorization errors
    #[error("Authentication error: {message}")]
    Authentication { message: String },

    /// Rate limiting errors
    #[error("Rate limit exceeded: {message}")]
    RateLimit {
        message: String,
        retry_after: Option<u64>,
    },

    /// Configuration errors
    #[error("Configuration error: {message}")]
    Configuration {
        message: String,
        field: Option<String>,
    },

    /// Timeout errors
    #[error("Operation timed out: {message}")]
    Timeout { message: String, timeout_ms: u64 },

    /// Backend-specific errors
    #[error("Backend error for '{backend}': {message}")]
    Backend {
        backend: String,
        message: String,
        error_code: Option<String>,
    },

    /// Not found errors
    #[error("Not found: {message}")]
    NotFound {
        message: String,
        key: Option<String>,
    },

    /// Conflict errors (e.g., key already exists)
    #[error("Conflict: {message}")]
    Conflict {
        message: String,
        key: Option<String>,
    },

    /// Internal errors
    #[error("Internal error: {message}")]
    Internal { message: String },
}

impl DbxError {
    /// Create a connection error
    pub fn connection<S: Into<String>>(backend: S, message: S) -> Self {
        Self::Connection {
            backend: backend.into(),
            message: message.into(),
        }
    }

    /// Create an unsupported operation error
    pub fn unsupported_operation<S: Into<String>>(operation: S, backend: S) -> Self {
        Self::UnsupportedOperation {
            operation: operation.into(),
            backend: backend.into(),
        }
    }

    /// Create a routing error
    pub fn routing<S: Into<String>>(message: S) -> Self {
        Self::Routing {
            message: message.into(),
        }
    }

    /// Create a validation error
    pub fn validation<S: Into<String>>(message: S) -> Self {
        Self::Validation {
            message: message.into(),
            field: None,
        }
    }

    /// Create a validation error for a specific field
    pub fn validation_field<S: Into<String>>(message: S, field: S) -> Self {
        Self::Validation {
            message: message.into(),
            field: Some(field.into()),
        }
    }

    /// Create a serialization error
    pub fn serialization<S: Into<String>>(message: S) -> Self {
        Self::Serialization {
            message: message.into(),
        }
    }

    /// Create an authentication error
    pub fn authentication<S: Into<String>>(message: S) -> Self {
        Self::Authentication {
            message: message.into(),
        }
    }

    /// Create a rate limit error
    pub fn rate_limit<S: Into<String>>(message: S, retry_after: Option<u64>) -> Self {
        Self::RateLimit {
            message: message.into(),
            retry_after,
        }
    }

    /// Create a configuration error
    pub fn configuration<S: Into<String>>(message: S) -> Self {
        Self::Configuration {
            message: message.into(),
            field: None,
        }
    }

    /// Create a configuration error for a specific field
    pub fn configuration_field<S: Into<String>>(message: S, field: S) -> Self {
        Self::Configuration {
            message: message.into(),
            field: Some(field.into()),
        }
    }

    /// Create a timeout error
    pub fn timeout<S: Into<String>>(message: S, timeout_ms: u64) -> Self {
        Self::Timeout {
            message: message.into(),
            timeout_ms,
        }
    }

    /// Create a backend error
    pub fn backend<S: Into<String>>(backend: S, message: S) -> Self {
        Self::Backend {
            backend: backend.into(),
            message: message.into(),
            error_code: None,
        }
    }

    /// Create a backend error with error code
    pub fn backend_with_code<S: Into<String>>(backend: S, message: S, error_code: S) -> Self {
        Self::Backend {
            backend: backend.into(),
            message: message.into(),
            error_code: Some(error_code.into()),
        }
    }

    /// Create a not found error
    pub fn not_found<S: Into<String>>(message: S) -> Self {
        Self::NotFound {
            message: message.into(),
            key: None,
        }
    }

    /// Create a not found error for a specific key
    pub fn not_found_key<S: Into<String>>(message: S, key: S) -> Self {
        Self::NotFound {
            message: message.into(),
            key: Some(key.into()),
        }
    }

    /// Create a conflict error
    pub fn conflict<S: Into<String>>(message: S) -> Self {
        Self::Conflict {
            message: message.into(),
            key: None,
        }
    }

    /// Create a conflict error for a specific key
    pub fn conflict_key<S: Into<String>>(message: S, key: S) -> Self {
        Self::Conflict {
            message: message.into(),
            key: Some(key.into()),
        }
    }

    /// Create an internal error
    pub fn internal<S: Into<String>>(message: S) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }

    /// Get the error category for metrics/logging
    pub fn category(&self) -> &'static str {
        match self {
            DbxError::Connection { .. } => "connection",
            DbxError::UnsupportedOperation { .. } => "unsupported_operation",
            DbxError::Routing { .. } => "routing",
            DbxError::Validation { .. } => "validation",
            DbxError::Serialization { .. } => "serialization",
            DbxError::Authentication { .. } => "authentication",
            DbxError::RateLimit { .. } => "rate_limit",
            DbxError::Configuration { .. } => "configuration",
            DbxError::Timeout { .. } => "timeout",
            DbxError::Backend { .. } => "backend",
            DbxError::NotFound { .. } => "not_found",
            DbxError::Conflict { .. } => "conflict",
            DbxError::Internal { .. } => "internal",
        }
    }

    /// Check if this error is retryable
    pub fn is_retryable(&self) -> bool {
        match self {
            DbxError::Connection { .. } => true,
            DbxError::Timeout { .. } => true,
            DbxError::RateLimit { .. } => true,
            DbxError::Backend { .. } => false, // Depends on backend, but conservative default
            _ => false,
        }
    }

    /// Get the backend name if this is a backend-specific error
    pub fn backend_name(&self) -> Option<&str> {
        match self {
            DbxError::Connection { backend, .. } => Some(backend),
            DbxError::UnsupportedOperation { backend, .. } => Some(backend),
            DbxError::Backend { backend, .. } => Some(backend),
            _ => None,
        }
    }
}

/// Result type for DBX operations
pub type DbxResult<T> = Result<T, DbxError>;

// Conversion implementations for common error types
impl From<serde_json::Error> for DbxError {
    fn from(err: serde_json::Error) -> Self {
        DbxError::serialization(err.to_string())
    }
}

impl From<tokio::time::error::Elapsed> for DbxError {
    fn from(err: tokio::time::error::Elapsed) -> Self {
        DbxError::timeout(err.to_string(), 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_dbx_error_connection() {
        let error = DbxError::connection("redis", "Connection failed");
        assert_eq!(error.category(), "connection");
        assert!(error.is_retryable());
        assert_eq!(error.backend_name(), Some("redis"));
        assert!(format!("{}", error).contains("Connection failed"));
    }

    #[test]
    fn test_dbx_error_unsupported_operation() {
        let error = DbxError::unsupported_operation("ZADD", "simple_kv");
        assert_eq!(error.category(), "operation");
        assert!(!error.is_retryable());
        assert_eq!(error.backend_name(), Some("simple_kv"));
        assert!(format!("{}", error).contains("ZADD"));
    }

    #[test]
    fn test_dbx_error_routing() {
        let error = DbxError::routing("No backend available for key pattern");
        assert_eq!(error.category(), "routing");
        assert!(error.is_retryable());
        assert_eq!(error.backend_name(), None);
        assert!(format!("{}", error).contains("No backend available"));
    }

    #[test]
    fn test_dbx_error_validation() {
        let error1 = DbxError::validation("Invalid data format");
        let error2 = DbxError::validation_field("Value out of range", "age");

        assert_eq!(error1.category(), "validation");
        assert!(!error1.is_retryable());
        assert_eq!(error1.backend_name(), None);
        assert!(format!("{}", error1).contains("Invalid data format"));

        assert_eq!(error2.category(), "validation");
        assert!(!error2.is_retryable());
        assert!(format!("{}", error2).contains("Value out of range"));
    }

    #[test]
    fn test_dbx_error_serialization() {
        let error = DbxError::serialization("Failed to serialize JSON");
        assert_eq!(error.category(), "serialization");
        assert!(!error.is_retryable());
        assert!(format!("{}", error).contains("Failed to serialize JSON"));
    }

    #[test]
    fn test_dbx_error_authentication() {
        let error = DbxError::authentication("Invalid credentials");
        assert_eq!(error.category(), "authentication");
        assert!(!error.is_retryable());
        assert!(format!("{}", error).contains("Invalid credentials"));
    }

    #[test]
    fn test_dbx_error_rate_limit() {
        let error = DbxError::rate_limit("Too many requests", Some(60));
        assert_eq!(error.category(), "rate_limit");
        assert!(error.is_retryable());
        assert!(format!("{}", error).contains("Too many requests"));
    }

    #[test]
    fn test_dbx_error_configuration() {
        let error1 = DbxError::configuration("Missing required setting");
        let error2 = DbxError::configuration_field("Invalid port", "port");

        assert_eq!(error1.category(), "configuration");
        assert!(!error1.is_retryable());
        assert!(format!("{}", error1).contains("Missing required setting"));

        assert_eq!(error2.category(), "configuration");
        assert!(!error2.is_retryable());
        assert!(format!("{}", error2).contains("Invalid port"));
    }

    #[test]
    fn test_dbx_error_timeout() {
        let error = DbxError::timeout("Operation timed out", 5000);
        assert_eq!(error.category(), "timeout");
        assert!(error.is_retryable());
        assert!(format!("{}", error).contains("Operation timed out"));
    }

    #[test]
    fn test_dbx_error_backend() {
        let error1 = DbxError::backend("postgres", "Connection lost");
        let error2 = DbxError::backend_with_code("redis", "READONLY", "ERR_READONLY");

        assert_eq!(error1.category(), "backend");
        assert!(error1.is_retryable());
        assert_eq!(error1.backend_name(), Some("postgres"));
        assert!(format!("{}", error1).contains("Connection lost"));

        assert_eq!(error2.category(), "backend");
        assert!(error2.is_retryable());
        assert_eq!(error2.backend_name(), Some("redis"));
        assert!(format!("{}", error2).contains("READONLY"));
    }

    #[test]
    fn test_dbx_error_not_found() {
        let error1 = DbxError::not_found("Resource not found");
        let error2 = DbxError::not_found_key("Key not found", "user:123");

        assert_eq!(error1.category(), "not_found");
        assert!(!error1.is_retryable());
        assert!(format!("{}", error1).contains("Resource not found"));

        assert_eq!(error2.category(), "not_found");
        assert!(!error2.is_retryable());
        assert!(format!("{}", error2).contains("Key not found"));
    }

    #[test]
    fn test_dbx_error_conflict() {
        let error1 = DbxError::conflict("Resource already exists");
        let error2 = DbxError::conflict_key("Key already exists", "user:456");

        assert_eq!(error1.category(), "conflict");
        assert!(!error1.is_retryable());
        assert!(format!("{}", error1).contains("Resource already exists"));

        assert_eq!(error2.category(), "conflict");
        assert!(!error2.is_retryable());
        assert!(format!("{}", error2).contains("Key already exists"));
    }

    #[test]
    fn test_dbx_error_internal() {
        let error = DbxError::internal("Internal server error");
        assert_eq!(error.category(), "internal");
        assert!(error.is_retryable());
        assert!(format!("{}", error).contains("Internal server error"));
    }

    #[test]
    fn test_dbx_error_display() {
        let error = DbxError::connection("redis", "Connection refused");
        let display_str = format!("{}", error);
        assert!(display_str.contains("Connection error"));
        assert!(display_str.contains("redis"));
        assert!(display_str.contains("Connection refused"));
    }

    #[test]
    fn test_dbx_error_debug() {
        let error = DbxError::validation_field("Invalid value", "email");
        let debug_str = format!("{:?}", error);
        assert!(debug_str.contains("Validation"));
        assert!(debug_str.contains("Invalid value"));
        assert!(debug_str.contains("email"));
    }

    #[test]
    fn test_dbx_error_json_serialization() {
        let errors = vec![
            DbxError::connection("redis", "Connection failed"),
            DbxError::validation("Invalid data"),
            DbxError::timeout("Timeout", 1000),
            DbxError::not_found_key("Not found", "key1"),
            DbxError::rate_limit("Rate limited", Some(30)),
        ];

        for error in errors {
            let json = serde_json::to_string(&error).unwrap();
            let deserialized: DbxError = serde_json::from_str(&json).unwrap();

            // Compare error categories and public API since full equality test would be complex
            assert_eq!(error.category(), deserialized.category());
            assert_eq!(error.is_retryable(), deserialized.is_retryable());
            assert_eq!(error.backend_name(), deserialized.backend_name());
        }
    }

    #[test]
    fn test_dbx_error_from_conversions() {
        // Test From<serde_json::Error>
        let json_error = serde_json::from_str::<serde_json::Value>("invalid json").unwrap_err();
        let dbx_error: DbxError = json_error.into();
        assert_eq!(dbx_error.category(), "serialization");
        assert!(!dbx_error.is_retryable());

        // Test that the From implementation exists (we can't easily create Elapsed without private constructor)
        // This is mainly testing the trait implementation compiles correctly
    }

    #[test]
    fn test_dbx_error_retryable_logic() {
        // Test retryable errors
        let retryable_errors = vec![
            DbxError::connection("redis", "Connection failed"),
            DbxError::routing("No backend available"),
            DbxError::rate_limit("Too many requests", None),
            DbxError::timeout("Timeout", 1000),
            DbxError::backend("postgres", "Temporary error"),
            DbxError::internal("Internal error"),
        ];

        for error in retryable_errors {
            assert!(
                error.is_retryable(),
                "Error should be retryable: {:?}",
                error
            );
        }

        // Test non-retryable errors
        let non_retryable_errors = vec![
            DbxError::unsupported_operation("INVALID", "backend"),
            DbxError::validation("Invalid data"),
            DbxError::serialization("Serialization failed"),
            DbxError::authentication("Invalid auth"),
            DbxError::configuration("Bad config"),
            DbxError::not_found("Not found"),
            DbxError::conflict("Conflict"),
        ];

        for error in non_retryable_errors {
            assert!(
                !error.is_retryable(),
                "Error should not be retryable: {:?}",
                error
            );
        }
    }

    #[test]
    fn test_dbx_error_categories() {
        let error_category_pairs = vec![
            (DbxError::connection("redis", "err"), "connection"),
            (
                DbxError::unsupported_operation("op", "backend"),
                "operation",
            ),
            (DbxError::routing("err"), "routing"),
            (DbxError::validation("err"), "validation"),
            (DbxError::serialization("err"), "serialization"),
            (DbxError::authentication("err"), "authentication"),
            (DbxError::rate_limit("err", None), "rate_limit"),
            (DbxError::configuration("err"), "configuration"),
            (DbxError::timeout("err", 1000), "timeout"),
            (DbxError::backend("backend", "err"), "backend"),
            (DbxError::not_found("err"), "not_found"),
            (DbxError::conflict("err"), "conflict"),
            (DbxError::internal("err"), "internal"),
        ];

        for (error, expected_category) in error_category_pairs {
            assert_eq!(error.category(), expected_category);
        }
    }

    #[test]
    fn test_dbx_result_type_alias() {
        let success_result: DbxResult<String> = Ok("success".to_string());
        let error_result: DbxResult<String> = Err(DbxError::internal("error"));

        assert!(success_result.is_ok());
        assert!(error_result.is_err());
    }

    #[test]
    fn test_error_equality() {
        let error1 = DbxError::validation("test error");
        let error2 = DbxError::validation("test error");
        let error3 = DbxError::validation("different error");

        // Test that DbxError now implements PartialEq
        assert_eq!(error1, error2);
        assert_ne!(error1, error3);

        // Also test serialization consistency
        let json1 = serde_json::to_string(&error1).unwrap();
        let json2 = serde_json::to_string(&error2).unwrap();
        let json3 = serde_json::to_string(&error3).unwrap();

        assert_eq!(json1, json2);
        assert_ne!(json1, json3);
    }
}
