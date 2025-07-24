use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::str::FromStr;
use thiserror::Error;

use crate::auth::RbacConfig;

/// Supported database types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DatabaseType {
    Redis,
}

impl FromStr for DatabaseType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "redis" => Ok(DatabaseType::Redis),
            _ => Err(format!("Unsupported database type: {s}")),
        }
    }
}

impl std::fmt::Display for DatabaseType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DatabaseType::Redis => write!(f, "redis"),
        }
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Missing environment variable: {0}")]
    MissingEnvironmentVariable(String),
    #[error("Invalid JWT secret: must be at least 32 characters")]
    InvalidJwtSecret,
    #[error("Missing default admin password when CREATE_DEFAULT_ADMIN is true")]
    MissingDefaultAdminPassword,
    #[error("Failed to parse environment variable {var}: {source}")]
    ParseError {
        var: String,
        #[source]
        source: std::num::ParseIntError,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub redis_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    pub secret: String,
    pub access_token_expiration: u64,
    pub refresh_token_expiration: u64,
    pub issuer: String,
}

impl JwtConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.secret.len() < 32 {
            return Err(ConfigError::InvalidJwtSecret);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointRateLimitConfig {
    pub requests: u32,
    pub window_seconds: u32,
    pub burst_allowance: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub global_requests_per_window: u32,
    pub global_window_seconds: u32,
    pub global_burst_allowance: Option<u32>,
    pub per_user_enabled: bool,
    pub per_ip_enabled: bool,
    pub endpoint_overrides: HashMap<String, EndpointRateLimitConfig>,
    pub redis_key_prefix: String,
    pub graceful_degradation: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            global_requests_per_window: 1000,
            global_window_seconds: 60,
            global_burst_allowance: Some(1500),
            per_user_enabled: true,
            per_ip_enabled: true,
            endpoint_overrides: HashMap::new(),
            redis_key_prefix: "dbx:rate_limit".to_string(),
            graceful_degradation: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub jwt: JwtConfig,
    pub rbac: RbacConfig,
    pub rate_limit: RateLimitConfig,
    pub create_default_admin: bool,
    pub default_admin_username: Option<String>,
    pub default_admin_password: Option<String>,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        let port = env::var("PORT")
            .unwrap_or_else(|_| "3000".to_string())
            .parse()
            .map_err(|e| ConfigError::ParseError {
                var: "PORT".to_string(),
                source: e,
            })?;
        let redis_url =
            env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());

        let jwt_secret = env::var("JWT_SECRET")
            .map_err(|_| ConfigError::MissingEnvironmentVariable("JWT_SECRET".to_string()))?;

        let access_token_expiration = env::var("ACCESS_TOKEN_EXPIRATION")
            .unwrap_or_else(|_| "900".to_string())
            .parse()
            .map_err(|e| ConfigError::ParseError {
                var: "ACCESS_TOKEN_EXPIRATION".to_string(),
                source: e,
            })?;

        let refresh_token_expiration = env::var("REFRESH_TOKEN_EXPIRATION")
            .unwrap_or_else(|_| "604800".to_string())
            .parse()
            .map_err(|e| ConfigError::ParseError {
                var: "REFRESH_TOKEN_EXPIRATION".to_string(),
                source: e,
            })?;

        let issuer = env::var("JWT_ISSUER").unwrap_or_else(|_| "dbx-api".to_string());

        let create_default_admin = env::var("CREATE_DEFAULT_ADMIN")
            .unwrap_or_else(|_| "false".to_string())
            .parse()
            .unwrap_or(false);

        let default_admin_username = env::var("DEFAULT_ADMIN_USERNAME").ok();
        let default_admin_password = env::var("DEFAULT_ADMIN_PASSWORD").ok();

        // Validate default admin configuration
        if create_default_admin && default_admin_password.is_none() {
            return Err(ConfigError::MissingDefaultAdminPassword);
        }

        let jwt_config = JwtConfig {
            secret: jwt_secret,
            access_token_expiration,
            refresh_token_expiration,
            issuer,
        };

        jwt_config.validate()?;

        // Parse RBAC configuration
        let rbac_audit_enabled = env::var("RBAC_AUDIT_ENABLED")
            .unwrap_or_else(|_| "true".to_string())
            .parse()
            .unwrap_or(true);

        let rbac_audit_retention_days = env::var("RBAC_AUDIT_RETENTION_DAYS")
            .unwrap_or_else(|_| "90".to_string())
            .parse()
            .map_err(|e| ConfigError::ParseError {
                var: "RBAC_AUDIT_RETENTION_DAYS".to_string(),
                source: e,
            })?;

        let rbac_max_role_inheritance_depth = env::var("RBAC_MAX_ROLE_INHERITANCE_DEPTH")
            .unwrap_or_else(|_| "5".to_string())
            .parse()
            .map_err(|e| ConfigError::ParseError {
                var: "RBAC_MAX_ROLE_INHERITANCE_DEPTH".to_string(),
                source: e,
            })?;

        let rbac_performance_cache_ttl_seconds = env::var("RBAC_PERFORMANCE_CACHE_TTL_SECONDS")
            .unwrap_or_else(|_| "300".to_string())
            .parse()
            .map_err(|e| ConfigError::ParseError {
                var: "RBAC_PERFORMANCE_CACHE_TTL_SECONDS".to_string(),
                source: e,
            })?;

        let rbac_default_assignment_ttl_days = env::var("RBAC_DEFAULT_ASSIGNMENT_TTL_DAYS")
            .ok()
            .and_then(|s| s.parse().ok());

        let rbac_config = RbacConfig {
            audit_enabled: rbac_audit_enabled,
            audit_retention_days: rbac_audit_retention_days,
            max_role_inheritance_depth: rbac_max_role_inheritance_depth,
            performance_cache_ttl_seconds: rbac_performance_cache_ttl_seconds,
            default_assignment_ttl_days: rbac_default_assignment_ttl_days,
        };

        // Parse Rate Limit configuration
        let rate_limit_enabled = env::var("RATE_LIMIT_ENABLED")
            .unwrap_or_else(|_| "true".to_string())
            .parse()
            .unwrap_or(true);

        let global_requests_per_window = env::var("GLOBAL_REQUESTS_PER_WINDOW")
            .unwrap_or_else(|_| "1000".to_string())
            .parse()
            .map_err(|e| ConfigError::ParseError {
                var: "GLOBAL_REQUESTS_PER_WINDOW".to_string(),
                source: e,
            })?;

        let global_window_seconds = env::var("GLOBAL_WINDOW_SECONDS")
            .unwrap_or_else(|_| "60".to_string())
            .parse()
            .map_err(|e| ConfigError::ParseError {
                var: "GLOBAL_WINDOW_SECONDS".to_string(),
                source: e,
            })?;

        let global_burst_allowance = env::var("GLOBAL_BURST_ALLOWANCE")
            .ok()
            .and_then(|s| s.parse().ok());

        let per_user_enabled = env::var("PER_USER_ENABLED")
            .unwrap_or_else(|_| "true".to_string())
            .parse()
            .unwrap_or(true);

        let per_ip_enabled = env::var("PER_IP_ENABLED")
            .unwrap_or_else(|_| "true".to_string())
            .parse()
            .unwrap_or(true);

        let redis_key_prefix =
            env::var("REDIS_KEY_PREFIX").unwrap_or_else(|_| "dbx:rate_limit".to_string());

        let graceful_degradation = env::var("GRACEFUL_DEGRADATION")
            .unwrap_or_else(|_| "true".to_string())
            .parse()
            .unwrap_or(true);

        let rate_limit_config = RateLimitConfig {
            enabled: rate_limit_enabled,
            global_requests_per_window,
            global_window_seconds,
            global_burst_allowance,
            per_user_enabled,
            per_ip_enabled,
            endpoint_overrides: HashMap::new(),
            redis_key_prefix,
            graceful_degradation,
        };

        Ok(AppConfig {
            server: ServerConfig {
                host,
                port,
                redis_url,
            },
            jwt: jwt_config,
            rbac: rbac_config,
            rate_limit: rate_limit_config,
            create_default_admin,
            default_admin_username,
            default_admin_password,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::env;

    fn clear_env_vars() {
        env::remove_var("HOST");
        env::remove_var("PORT");
        env::remove_var("REDIS_URL");
        env::remove_var("JWT_SECRET");
        env::remove_var("ACCESS_TOKEN_EXPIRATION");
        env::remove_var("REFRESH_TOKEN_EXPIRATION");
        env::remove_var("JWT_ISSUER");
        env::remove_var("CREATE_DEFAULT_ADMIN");
        env::remove_var("DEFAULT_ADMIN_USERNAME");
        env::remove_var("DEFAULT_ADMIN_PASSWORD");
    }

    fn setup_basic_env() {
        env::set_var(
            "JWT_SECRET",
            "test-jwt-secret-that-is-at-least-32-characters-long",
        );
    }

    #[test]
    fn test_jwt_config_validation_valid_secret() {
        let config = JwtConfig {
            secret: "test-jwt-secret-that-is-at-least-32-characters-long".to_string(),
            access_token_expiration: 900,
            refresh_token_expiration: 604800,
            issuer: "test".to_string(),
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_jwt_config_validation_invalid_secret() {
        let config = JwtConfig {
            secret: "short".to_string(),
            access_token_expiration: 900,
            refresh_token_expiration: 604800,
            issuer: "test".to_string(),
        };
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidJwtSecret)
        ));
    }

    #[test]
    fn test_database_type_from_str() {
        assert_eq!(
            DatabaseType::from_str("redis").unwrap(),
            DatabaseType::Redis
        );
        assert!(DatabaseType::from_str("invalid").is_err());
    }

    #[test]
    fn test_database_type_display() {
        assert_eq!(DatabaseType::Redis.to_string(), "redis");
    }

    #[test]
    #[serial]
    fn test_app_config_from_env_defaults() {
        clear_env_vars();
        setup_basic_env();

        let config = AppConfig::from_env().unwrap();
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 3000);
        assert_eq!(config.server.redis_url, "redis://localhost:6379");
        assert_eq!(config.jwt.access_token_expiration, 900);
        assert_eq!(config.jwt.refresh_token_expiration, 604800);
        assert_eq!(config.jwt.issuer, "dbx-api");
        assert!(!config.create_default_admin);

        clear_env_vars();
    }

    #[test]
    #[serial]
    fn test_app_config_from_env_custom_values() {
        clear_env_vars();
        env::set_var("HOST", "127.0.0.1");
        env::set_var("PORT", "8080");
        env::set_var("REDIS_URL", "redis://127.0.0.1:6380");
        env::set_var(
            "JWT_SECRET",
            "custom-jwt-secret-that-is-at-least-32-characters-long",
        );
        env::set_var("ACCESS_TOKEN_EXPIRATION", "1800");
        env::set_var("REFRESH_TOKEN_EXPIRATION", "86400");
        env::set_var("JWT_ISSUER", "custom-api");
        env::set_var("CREATE_DEFAULT_ADMIN", "true");
        env::set_var("DEFAULT_ADMIN_USERNAME", "admin");
        env::set_var("DEFAULT_ADMIN_PASSWORD", "password123");

        let config = AppConfig::from_env().unwrap();
        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 8080);
        assert_eq!(config.server.redis_url, "redis://127.0.0.1:6380");
        assert_eq!(config.jwt.access_token_expiration, 1800);
        assert_eq!(config.jwt.refresh_token_expiration, 86400);
        assert_eq!(config.jwt.issuer, "custom-api");
        assert!(config.create_default_admin);
        assert_eq!(config.default_admin_username, Some("admin".to_string()));
        assert_eq!(
            config.default_admin_password,
            Some("password123".to_string())
        );

        clear_env_vars();
    }

    #[test]
    #[serial]
    fn test_app_config_missing_jwt_secret() {
        clear_env_vars();

        let result = AppConfig::from_env();
        assert!(matches!(
            result,
            Err(ConfigError::MissingEnvironmentVariable(_))
        ));

        clear_env_vars();
    }

    #[test]
    #[serial]
    fn test_app_config_invalid_port() {
        clear_env_vars();
        setup_basic_env();
        env::set_var("PORT", "invalid");

        let result = AppConfig::from_env();
        assert!(matches!(result, Err(ConfigError::ParseError { .. })));

        clear_env_vars();
    }

    #[test]
    #[serial]
    fn test_app_config_create_admin_without_password() {
        clear_env_vars();
        setup_basic_env();
        env::set_var("CREATE_DEFAULT_ADMIN", "true");
        env::set_var("DEFAULT_ADMIN_USERNAME", "admin");

        let result = AppConfig::from_env();
        assert!(matches!(
            result,
            Err(ConfigError::MissingDefaultAdminPassword)
        ));

        clear_env_vars();
    }

    #[test]
    #[serial]
    fn test_app_config_short_jwt_secret() {
        clear_env_vars();
        env::set_var("JWT_SECRET", "short");

        let result = AppConfig::from_env();
        assert!(matches!(result, Err(ConfigError::InvalidJwtSecret)));

        clear_env_vars();
    }
}
