use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Configuration error types
#[derive(Error, Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ConfigError {
    /// File I/O errors
    #[error("Config file error: {message}")]
    FileError {
        message: String,
        path: Option<String>,
    },

    /// Parsing errors (YAML, JSON, etc.)
    #[error("Config parsing error: {message}")]
    ParseError {
        message: String,
        line: Option<usize>,
        column: Option<usize>,
    },

    /// Validation errors
    #[error("Config validation error: {message}")]
    Validation {
        message: String,
        field_errors: Vec<FieldError>,
    },

    /// Invalid backend reference
    #[error("Invalid backend reference '{backend}' in {context}")]
    InvalidBackendReference { backend: String, context: String },

    /// Duplicate routing rule
    #[error("Duplicate routing rule for pattern '{pattern}' with priority {priority}")]
    DuplicateRoutingRule { pattern: String, priority: u32 },

    /// Duplicate load balancing backend
    #[error("Duplicate backend '{backend}' in load balancing configuration")]
    DuplicateLoadBalancingBackend { backend: String },

    /// Missing load balancing weight
    #[error("Missing weight for backend '{backend}' in weighted load balancing")]
    MissingLoadBalancingWeight { backend: String },

    /// Invalid load balancing weight
    #[error("Invalid weight {weight} for backend '{backend}' - must be positive")]
    InvalidLoadBalancingWeight { backend: String, weight: f64 },

    /// Missing security configuration
    #[error("Missing {config_type}: {reason}")]
    MissingSecurityConfig { config_type: String, reason: String },

    /// Invalid URL
    #[error("Invalid URL '{url}': {error}")]
    InvalidUrl { url: String, error: String },

    /// Invalid provider URL
    #[error("Invalid URL scheme for provider '{provider}': '{url}' (expected {expected_scheme})")]
    InvalidProviderUrl {
        provider: String,
        url: String,
        expected_scheme: String,
    },

    /// Environment variable error
    #[error("Environment variable error: {message}")]
    EnvironmentError {
        message: String,
        variable: Option<String>,
    },

    /// Migration error
    #[error("Configuration migration error: {message}")]
    MigrationError {
        message: String,
        from_version: Option<String>,
        to_version: Option<String>,
    },

    /// Schema error
    #[error("Configuration schema error: {message}")]
    SchemaError {
        message: String,
        field: Option<String>,
    },
}

/// Field validation error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldError {
    pub field: String,
    pub code: String,
    pub message: String,
}

impl ConfigError {
    /// Create a file error
    pub fn file_error<S: Into<String>>(message: S, path: Option<S>) -> Self {
        Self::FileError {
            message: message.into(),
            path: path.map(|s| s.into()),
        }
    }

    /// Create a parse error
    pub fn parse_error<S: Into<String>>(message: S) -> Self {
        Self::ParseError {
            message: message.into(),
            line: None,
            column: None,
        }
    }

    /// Create a parse error with location
    pub fn parse_error_with_location<S: Into<String>>(
        message: S,
        line: usize,
        column: usize,
    ) -> Self {
        Self::ParseError {
            message: message.into(),
            line: Some(line),
            column: Some(column),
        }
    }

    /// Create a validation error
    pub fn validation<S: Into<String>>(message: S, field_errors: Vec<FieldError>) -> Self {
        Self::Validation {
            message: message.into(),
            field_errors,
        }
    }

    /// Create an environment error
    pub fn environment_error<S: Into<String>>(message: S, variable: Option<S>) -> Self {
        Self::EnvironmentError {
            message: message.into(),
            variable: variable.map(|s| s.into()),
        }
    }

    /// Create a migration error
    pub fn migration_error<S: Into<String>>(
        message: S,
        from_version: Option<S>,
        to_version: Option<S>,
    ) -> Self {
        Self::MigrationError {
            message: message.into(),
            from_version: from_version.map(|s| s.into()),
            to_version: to_version.map(|s| s.into()),
        }
    }

    /// Create a schema error
    pub fn schema_error<S: Into<String>>(message: S, field: Option<S>) -> Self {
        Self::SchemaError {
            message: message.into(),
            field: field.map(|s| s.into()),
        }
    }

    /// Get the error category for metrics/logging
    pub fn category(&self) -> &'static str {
        match self {
            ConfigError::FileError { .. } => "file_error",
            ConfigError::ParseError { .. } => "parse_error",
            ConfigError::Validation { .. } => "validation",
            ConfigError::InvalidBackendReference { .. } => "invalid_backend_reference",
            ConfigError::DuplicateRoutingRule { .. } => "duplicate_routing_rule",
            ConfigError::DuplicateLoadBalancingBackend { .. } => "duplicate_load_balancing_backend",
            ConfigError::MissingLoadBalancingWeight { .. } => "missing_load_balancing_weight",
            ConfigError::InvalidLoadBalancingWeight { .. } => "invalid_load_balancing_weight",
            ConfigError::MissingSecurityConfig { .. } => "missing_security_config",
            ConfigError::InvalidUrl { .. } => "invalid_url",
            ConfigError::InvalidProviderUrl { .. } => "invalid_provider_url",
            ConfigError::EnvironmentError { .. } => "environment_error",
            ConfigError::MigrationError { .. } => "migration_error",
            ConfigError::SchemaError { .. } => "schema_error",
        }
    }

    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            ConfigError::FileError { .. } => false,
            ConfigError::ParseError { .. } => false,
            ConfigError::Validation { .. } => false,
            ConfigError::EnvironmentError { .. } => true, // Can be fixed by setting env vars
            ConfigError::MigrationError { .. } => false,
            _ => false,
        }
    }
}

/// Result type for configuration operations
pub type ConfigResult<T> = Result<T, ConfigError>;

// Conversion implementations for common error types
impl From<std::io::Error> for ConfigError {
    fn from(err: std::io::Error) -> Self {
        ConfigError::file_error(err.to_string(), None)
    }
}

impl From<serde_yaml::Error> for ConfigError {
    fn from(err: serde_yaml::Error) -> Self {
        if let Some(location) = err.location() {
            ConfigError::parse_error_with_location(
                err.to_string(),
                location.line(),
                location.column(),
            )
        } else {
            ConfigError::parse_error(err.to_string())
        }
    }
}

impl From<serde_json::Error> for ConfigError {
    fn from(err: serde_json::Error) -> Self {
        if err.line() > 0 {
            ConfigError::parse_error_with_location(err.to_string(), err.line(), err.column())
        } else {
            ConfigError::parse_error(err.to_string())
        }
    }
}

impl From<url::ParseError> for ConfigError {
    fn from(err: url::ParseError) -> Self {
        ConfigError::InvalidUrl {
            url: "unknown".to_string(),
            error: err.to_string(),
        }
    }
}

impl From<validator::ValidationErrors> for ConfigError {
    fn from(errors: validator::ValidationErrors) -> Self {
        let field_errors: Vec<FieldError> = errors
            .field_errors()
            .iter()
            .flat_map(|(field, errors)| {
                let field = field.to_string();
                errors.iter().map(move |error| FieldError {
                    field: field.clone(),
                    code: error.code.to_string(),
                    message: error
                        .message
                        .as_ref()
                        .map(|msg| msg.to_string())
                        .unwrap_or_else(|| format!("Validation error for field '{}'", field)),
                })
            })
            .collect();

        ConfigError::validation("Configuration validation failed", field_errors)
    }
}
