use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Router-specific error types
#[derive(Error, Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum RouterError {
    /// Backend not found
    #[error("Backend '{backend}' not found")]
    BackendNotFound { backend: String },

    /// Backend registration error
    #[error("Backend registration failed: {message}")]
    BackendRegistration {
        message: String,
        backend: Option<String>,
    },

    /// Invalid routing pattern
    #[error("Invalid {pattern_type} pattern '{pattern}': {error}")]
    InvalidPattern {
        pattern: String,
        pattern_type: String,
        error: String,
    },

    /// Load balancing error
    #[error("Load balancing error: {message}")]
    LoadBalancingError { message: String },

    /// No healthy backends available
    #[error("No healthy backends available for operation")]
    NoHealthyBackends,

    /// Backend initialization error
    #[error("Backend '{backend}' initialization failed: {message}")]
    BackendInitialization { backend: String, message: String },

    /// Routing configuration error
    #[error("Routing configuration error: {message}")]
    RoutingConfiguration {
        message: String,
        field: Option<String>,
    },

    /// Circuit breaker error
    #[error("Circuit breaker open for backend '{backend}'")]
    CircuitBreakerOpen { backend: String },

    /// Timeout error during routing
    #[error("Routing timeout: {message}")]
    RoutingTimeout { message: String, timeout_ms: u64 },
}

impl RouterError {
    /// Create a backend not found error
    pub fn backend_not_found<S: Into<String>>(backend: S) -> Self {
        Self::BackendNotFound {
            backend: backend.into(),
        }
    }

    /// Create a backend registration error
    pub fn backend_registration<S: Into<String>>(message: S, backend: Option<S>) -> Self {
        Self::BackendRegistration {
            message: message.into(),
            backend: backend.map(|s| s.into()),
        }
    }

    /// Create an invalid pattern error
    pub fn invalid_pattern<S: Into<String>>(pattern: S, pattern_type: S, error: S) -> Self {
        Self::InvalidPattern {
            pattern: pattern.into(),
            pattern_type: pattern_type.into(),
            error: error.into(),
        }
    }

    /// Create a load balancing error
    pub fn load_balancing_error<S: Into<String>>(message: S) -> Self {
        Self::LoadBalancingError {
            message: message.into(),
        }
    }

    /// Create a no healthy backends error
    pub fn no_healthy_backends() -> Self {
        Self::NoHealthyBackends
    }

    /// Create a backend initialization error
    pub fn backend_initialization<S: Into<String>>(backend: S, message: S) -> Self {
        Self::BackendInitialization {
            backend: backend.into(),
            message: message.into(),
        }
    }

    /// Create a routing configuration error
    pub fn routing_configuration<S: Into<String>>(message: S) -> Self {
        Self::RoutingConfiguration {
            message: message.into(),
            field: None,
        }
    }

    /// Create a routing configuration error for a specific field
    pub fn routing_configuration_field<S: Into<String>>(message: S, field: S) -> Self {
        Self::RoutingConfiguration {
            message: message.into(),
            field: Some(field.into()),
        }
    }

    /// Create a circuit breaker error
    pub fn circuit_breaker_open<S: Into<String>>(backend: S) -> Self {
        Self::CircuitBreakerOpen {
            backend: backend.into(),
        }
    }

    /// Create a routing timeout error
    pub fn routing_timeout<S: Into<String>>(message: S, timeout_ms: u64) -> Self {
        Self::RoutingTimeout {
            message: message.into(),
            timeout_ms,
        }
    }

    /// Get the error category for metrics/logging
    pub fn category(&self) -> &'static str {
        match self {
            RouterError::BackendNotFound { .. } => "backend_not_found",
            RouterError::BackendRegistration { .. } => "backend_registration",
            RouterError::InvalidPattern { .. } => "invalid_pattern",
            RouterError::LoadBalancingError { .. } => "load_balancing_error",
            RouterError::NoHealthyBackends => "no_healthy_backends",
            RouterError::BackendInitialization { .. } => "backend_initialization",
            RouterError::RoutingConfiguration { .. } => "routing_configuration",
            RouterError::CircuitBreakerOpen { .. } => "circuit_breaker_open",
            RouterError::RoutingTimeout { .. } => "routing_timeout",
        }
    }

    /// Check if this error is retryable
    pub fn is_retryable(&self) -> bool {
        match self {
            RouterError::BackendNotFound { .. } => false,
            RouterError::BackendRegistration { .. } => false,
            RouterError::InvalidPattern { .. } => false,
            RouterError::LoadBalancingError { .. } => true,
            RouterError::NoHealthyBackends => true,
            RouterError::BackendInitialization { .. } => true,
            RouterError::RoutingConfiguration { .. } => false,
            RouterError::CircuitBreakerOpen { .. } => true,
            RouterError::RoutingTimeout { .. } => true,
        }
    }

    /// Get the backend name if this is a backend-specific error
    pub fn backend_name(&self) -> Option<&str> {
        match self {
            RouterError::BackendNotFound { backend } => Some(backend),
            RouterError::BackendRegistration { backend, .. } => backend.as_deref(),
            RouterError::BackendInitialization { backend, .. } => Some(backend),
            RouterError::CircuitBreakerOpen { backend } => Some(backend),
            _ => None,
        }
    }
}

/// Result type for router operations
pub type RouterResult<T> = Result<T, RouterError>;

// Convert RouterError to DbxError for unified error handling
impl From<RouterError> for dbx_core::DbxError {
    fn from(err: RouterError) -> Self {
        match err {
            RouterError::BackendNotFound { backend } => {
                dbx_core::DbxError::routing(format!("Backend '{}' not found", backend))
            }
            RouterError::BackendRegistration { message, .. } => {
                dbx_core::DbxError::routing(format!("Backend registration failed: {}", message))
            }
            RouterError::InvalidPattern {
                pattern,
                pattern_type,
                error,
            } => dbx_core::DbxError::configuration(format!(
                "Invalid {} pattern '{}': {}",
                pattern_type, pattern, error
            )),
            RouterError::LoadBalancingError { message } => {
                dbx_core::DbxError::routing(format!("Load balancing error: {}", message))
            }
            RouterError::NoHealthyBackends => {
                dbx_core::DbxError::routing("No healthy backends available".to_string())
            }
            RouterError::BackendInitialization { backend, message } => {
                dbx_core::DbxError::connection(backend, message)
            }
            RouterError::RoutingConfiguration { message, .. } => {
                dbx_core::DbxError::configuration(message)
            }
            RouterError::CircuitBreakerOpen { backend } => {
                dbx_core::DbxError::connection(backend, "Circuit breaker is open".to_string())
            }
            RouterError::RoutingTimeout {
                message,
                timeout_ms,
            } => dbx_core::DbxError::timeout(message, timeout_ms),
        }
    }
}
