use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Universal error type for DBX operations
#[derive(Error, Debug, Clone, Serialize, Deserialize)]
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
