use serde::{Deserialize, Serialize};
use std::env;
use std::str::FromStr;

use crate::constants::defaults::Defaults;

/// Supported database types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DatabaseType {
    Redis,
    // Future database types
    // Postgres,
    // MongoDB,
    // MySQL,
}

impl FromStr for DatabaseType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "redis" => Ok(DatabaseType::Redis),
            // "postgres" => Ok(DatabaseType::Postgres),
            // "mongodb" => Ok(DatabaseType::MongoDB),
            // "mysql" => Ok(DatabaseType::MySQL),
            _ => Err(format!("Unsupported database type: {s}")),
        }
    }
}

impl std::fmt::Display for DatabaseType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DatabaseType::Redis => write!(f, "redis"),
            // DatabaseType::Postgres => write!(f, "postgres"),
            // DatabaseType::MongoDB => write!(f, "mongodb"),
            // DatabaseType::MySQL => write!(f, "mysql"),
        }
    }
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Database connection URL
    pub database_url: String,
    /// Server host
    pub host: String,
    /// Server port
    pub port: u16,
    /// Connection pool size
    pub pool_size: u32,
    /// JWT configuration
    pub jwt: JwtConfig,
}

/// JWT configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    /// JWT secret key
    pub secret: String,
    /// JWT access token expiration in seconds (default: 15 minutes)
    pub access_token_expiration: i64,
    /// JWT refresh token expiration in seconds (default: 7 days)
    pub refresh_token_expiration: i64,
    /// JWT issuer
    pub issuer: String,
}

impl JwtConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        let secret = env::var("JWT_SECRET").map_err(|_| ConfigError::MissingJwtSecret)?;

        if secret.len() < 32 {
            return Err(ConfigError::WeakJwtSecret);
        }

        Ok(Self {
            secret,
            access_token_expiration: env::var("JWT_ACCESS_TOKEN_EXPIRATION")
                .unwrap_or_else(|_| Defaults::JWT_ACCESS_TOKEN_EXPIRATION.to_string())
                .parse()
                .map_err(|_| ConfigError::InvalidTokenExpiration)?,
            refresh_token_expiration: env::var("JWT_REFRESH_TOKEN_EXPIRATION")
                .unwrap_or_else(|_| Defaults::JWT_REFRESH_TOKEN_EXPIRATION.to_string())
                .parse()
                .map_err(|_| ConfigError::InvalidTokenExpiration)?,
            issuer: env::var("JWT_ISSUER").unwrap_or_else(|_| Defaults::JWT_ISSUER.to_string()),
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("JWT_SECRET environment variable is required")]
    MissingJwtSecret,
    #[error("JWT_SECRET must be at least 32 characters long")]
    WeakJwtSecret,
    #[error("Invalid token expiration time")]
    InvalidTokenExpiration,
    #[error(
        "DEFAULT_ADMIN_PASSWORD environment variable is required when CREATE_DEFAULT_ADMIN=true"
    )]
    MissingDefaultAdminPassword,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub redis_url: String,
    pub pool_size: u32,
}

impl ServerConfig {
    pub fn from_env() -> Self {
        Self {
            host: env::var("HOST").unwrap_or_else(|_| Defaults::HOST.to_string()),
            port: env::var("PORT")
                .unwrap_or_else(|_| Defaults::PORT.to_string())
                .parse()
                .expect("PORT must be a valid number"),
            redis_url: env::var("REDIS_URL").unwrap_or_else(|_| Defaults::REDIS_URL.to_string()),
            pool_size: env::var("POOL_SIZE")
                .unwrap_or_else(|_| Defaults::POOL_SIZE.to_string())
                .parse()
                .expect("POOL_SIZE must be a valid number"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub jwt: JwtConfig,
    pub create_default_admin: bool,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            server: ServerConfig::from_env(),
            jwt: JwtConfig::from_env()?,
            create_default_admin: env::var("CREATE_DEFAULT_ADMIN")
                .unwrap_or_else(|_| "false".to_string())
                .parse()
                .unwrap_or(false),
        })
    }
}
