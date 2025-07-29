use napi::bindgen_prelude::*;
use serde::{Deserialize, Serialize};

/// Error types for DBX operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DbxError {
    Authentication(String),
    Authorization(String),
    Network(String),
    Serialization(String),
    Validation(String),
    RateLimit(String),
    Backend(String),
    Timeout(String),
    InvalidConfig(String),
    Unknown(String),
}

impl DbxError {
    pub fn authentication(msg: String) -> Self {
        DbxError::Authentication(msg)
    }

    pub fn authorization(msg: String) -> Self {
        DbxError::Authorization(msg)
    }

    pub fn network(msg: String) -> Self {
        DbxError::Network(msg)
    }

    pub fn serialization(msg: String) -> Self {
        DbxError::Serialization(msg)
    }

    pub fn validation(msg: String) -> Self {
        DbxError::Validation(msg)
    }

    pub fn rate_limit(msg: String) -> Self {
        DbxError::RateLimit(msg)
    }

    pub fn backend(msg: String) -> Self {
        DbxError::Backend(msg)
    }

    pub fn timeout(msg: String) -> Self {
        DbxError::Timeout(msg)
    }

    pub fn invalid_config(msg: String) -> Self {
        DbxError::InvalidConfig(msg)
    }

    pub fn unknown(msg: String) -> Self {
        DbxError::Unknown(msg)
    }

    pub fn message(&self) -> &str {
        match self {
            DbxError::Authentication(msg) => msg,
            DbxError::Authorization(msg) => msg,
            DbxError::Network(msg) => msg,
            DbxError::Serialization(msg) => msg,
            DbxError::Validation(msg) => msg,
            DbxError::RateLimit(msg) => msg,
            DbxError::Backend(msg) => msg,
            DbxError::Timeout(msg) => msg,
            DbxError::InvalidConfig(msg) => msg,
            DbxError::Unknown(msg) => msg,
        }
    }

    pub fn error_type(&self) -> &'static str {
        match self {
            DbxError::Authentication(_) => "Authentication",
            DbxError::Authorization(_) => "Authorization",
            DbxError::Network(_) => "Network",
            DbxError::Serialization(_) => "Serialization",
            DbxError::Validation(_) => "Validation",
            DbxError::RateLimit(_) => "RateLimit",
            DbxError::Backend(_) => "Backend",
            DbxError::Timeout(_) => "Timeout",
            DbxError::InvalidConfig(_) => "InvalidConfig",
            DbxError::Unknown(_) => "Unknown",
        }
    }
}

impl From<DbxError> for napi::Error {
    fn from(err: DbxError) -> Self {
        let status = match err {
            DbxError::Authentication(_) => Status::GenericFailure,
            DbxError::Authorization(_) => Status::GenericFailure,
            DbxError::Network(_) => Status::GenericFailure,
            DbxError::Serialization(_) => Status::InvalidArg,
            DbxError::Validation(_) => Status::InvalidArg,
            DbxError::RateLimit(_) => Status::GenericFailure,
            DbxError::Backend(_) => Status::GenericFailure,
            DbxError::Timeout(_) => Status::GenericFailure,
            DbxError::InvalidConfig(_) => Status::InvalidArg,
            DbxError::Unknown(_) => Status::GenericFailure,
        };
        napi::Error::new(status, err.message().to_string())
    }
}

impl From<reqwest::Error> for DbxError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_timeout() {
            DbxError::timeout(format!("Request timeout: {}", err))
        } else if err.is_connect() {
            DbxError::network(format!("Connection error: {}", err))
        } else if err.is_decode() {
            DbxError::serialization(format!("Response decode error: {}", err))
        } else {
            DbxError::network(format!("Network error: {}", err))
        }
    }
}

impl From<serde_json::Error> for DbxError {
    fn from(err: serde_json::Error) -> Self {
        DbxError::serialization(format!("JSON serialization error: {}", err))
    }
}

/// Convert HTTP status codes to appropriate DbxError
pub fn status_to_error(status: reqwest::StatusCode, body: Option<String>) -> DbxError {
    let message = body.unwrap_or_else(|| format!("HTTP error: {}", status));

    match status.as_u16() {
        401 => DbxError::authentication(message),
        403 => DbxError::authorization(message),
        422 => DbxError::validation(message),
        429 => DbxError::rate_limit(message),
        500..=599 => DbxError::backend(message),
        _ => DbxError::unknown(message),
    }
}
