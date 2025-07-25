use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use thiserror::Error;

use crate::auth::RbacConfig;
use dbx_config::{ConfigLoader, DbxConfig};

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
    #[error("Configuration error: {0}")]
    DbxConfig(#[from] dbx_config::ConfigError),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

impl From<dbx_config::ServerConfig> for ServerConfig {
    fn from(config: dbx_config::ServerConfig) -> Self {
        Self {
            host: config.host,
            port: config.port,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    pub secret: String,
    pub access_token_expiration: u64,
    pub refresh_token_expiration: u64,
    pub issuer: String,
}

impl From<dbx_config::JwtConfig> for JwtConfig {
    fn from(config: dbx_config::JwtConfig) -> Self {
        Self {
            secret: config.secret,
            access_token_expiration: config.expiration_seconds,
            refresh_token_expiration: config.expiration_seconds * 7, // Default to 7x access token expiration
            issuer: config.issuer,
        }
    }
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
pub struct SecurityHeadersConfig {
    pub x_content_type_options: String,
    pub x_frame_options: String,
    pub x_xss_protection: String,
    pub strict_transport_security: Option<String>,
    pub referrer_policy: String,
    pub content_security_policy: String,
    pub permissions_policy: Option<String>,
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        Self {
            x_content_type_options: "nosniff".to_string(),
            x_frame_options: "DENY".to_string(),
            x_xss_protection: "1; mode=block".to_string(),
            strict_transport_security: Some("max-age=31536000; includeSubDomains".to_string()),
            referrer_policy: "strict-origin-when-cross-origin".to_string(),
            content_security_policy: "default-src 'self'".to_string(),
            permissions_policy: Some("geolocation=(), microphone=(), camera=()".to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsConfig {
    pub enabled: bool,
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    pub exposed_headers: Vec<String>,
    pub allow_credentials: bool,
    pub max_age: Option<u32>,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allowed_origins: vec![
                "http://localhost:3000".to_string(),
                "http://127.0.0.1:3000".to_string(),
            ],
            allowed_methods: vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "DELETE".to_string(),
                "OPTIONS".to_string(),
            ],
            allowed_headers: vec![
                "Authorization".to_string(),
                "Content-Type".to_string(),
                "X-API-Key".to_string(),
            ],
            exposed_headers: vec![
                "X-Rate-Limit-Remaining".to_string(),
                "X-Rate-Limit-Reset".to_string(),
            ],
            allow_credentials: true,
            max_age: Some(3600),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub headers: SecurityHeadersConfig,
    pub cors: CorsConfig,
    pub development_mode: bool,
    pub strict_transport_security_enabled: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            headers: SecurityHeadersConfig::default(),
            cors: CorsConfig::default(),
            development_mode: false,
            strict_transport_security_enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub jwt: JwtConfig,
    pub rbac: RbacConfig,
    pub rate_limit: RateLimitConfig,
    pub security: SecurityConfig,
    pub create_default_admin: bool,
    pub default_admin_username: Option<String>,
    pub default_admin_password: Option<String>,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        // Use the runtime to run async function
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(Self::from_env_async())
    }

    pub async fn from_env_async() -> Result<Self, ConfigError> {
        Self::from_dbx_config(None).await
    }

    pub async fn from_dbx_config(config_path: Option<&str>) -> Result<Self, ConfigError> {
        // Load configuration using dbx-config
        let dbx_config = if let Some(path) = config_path {
            ConfigLoader::load_from_file(path).await?
        } else {
            ConfigLoader::load_from_env().await?
        };

        Self::from_dbx_config_direct(dbx_config)
    }

    pub fn from_dbx_config_direct(config: DbxConfig) -> Result<Self, ConfigError> {
        // Get JWT config from security section
        let jwt_config = config
            .security
            .jwt
            .ok_or(ConfigError::MissingEnvironmentVariable(
                "JWT_SECRET".to_string(),
            ))?;

        // Get admin configuration from DbxConfig
        let admin_config = &config.admin;

        // Validate default admin configuration
        if admin_config.create_default_admin && admin_config.default_admin_password.is_none() {
            return Err(ConfigError::MissingDefaultAdminPassword);
        }

        let jwt_config = JwtConfig::from(jwt_config);
        jwt_config.validate()?;

        // Map rate limiting config (use defaults if not present)
        let rate_limit_config = config
            .security
            .rate_limiting
            .map(|rl| RateLimitConfig {
                enabled: true,
                global_requests_per_window: rl.requests_per_second * (rl.window_ms / 1000) as u32,
                global_window_seconds: (rl.window_ms / 1000) as u32,
                global_burst_allowance: Some(rl.burst_size),
                per_user_enabled: rl.per_user,
                per_ip_enabled: rl.per_ip,
                endpoint_overrides: HashMap::new(),
                redis_key_prefix: "dbx:rate_limit".to_string(),
                graceful_degradation: true,
            })
            .unwrap_or_default();

        // Use default security configuration
        let security_config = SecurityConfig::default();

        // Map RBAC config from admin configuration
        let rbac_config = RbacConfig {
            audit_enabled: admin_config.rbac.audit_enabled,
            audit_retention_days: admin_config.rbac.audit_retention_days,
            max_role_inheritance_depth: admin_config.rbac.max_role_inheritance_depth,
            performance_cache_ttl_seconds: admin_config.rbac.performance_cache_ttl_seconds,
            default_assignment_ttl_days: admin_config.rbac.default_assignment_ttl_days,
        };

        Ok(AppConfig {
            server: ServerConfig::from(config.server),
            jwt: jwt_config,
            rbac: rbac_config,
            rate_limit: rate_limit_config,
            security: security_config,
            create_default_admin: admin_config.create_default_admin,
            default_admin_username: admin_config.default_admin_username.clone(),
            default_admin_password: admin_config.default_admin_password.clone(),
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
