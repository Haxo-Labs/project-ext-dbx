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
    pub key_prefix: String,
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
            key_prefix: "dbx:rate_limit".to_string(),
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
pub struct HostValidationConfig {
    pub enabled: bool,
    pub allowed_hosts: Vec<String>,
    pub allow_localhost: bool,
    pub allow_private_ips: bool,
    pub allow_ipv6: bool,
    pub max_host_length: usize,
    pub strict_port_validation: bool,
    pub allowed_ports: Option<Vec<u16>>,
}

impl Default for HostValidationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allowed_hosts: vec![
                "localhost".to_string(),
                "127.0.0.1".to_string(),
                "::1".to_string(),
            ],
            allow_localhost: true,
            allow_private_ips: true,
            allow_ipv6: true,
            max_host_length: 253, // RFC 1035 limit
            strict_port_validation: true,
            allowed_ports: Some(vec![80, 443, 3000, 8080, 8443]),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub headers: SecurityHeadersConfig,
    pub cors: CorsConfig,
    pub host_validation: HostValidationConfig,
    pub development_mode: bool,
    pub strict_transport_security_enabled: bool,
}

impl SecurityConfig {
    /// Load security configuration from environment variables or use defaults
    pub fn from_env_or_default() -> Self {
        let mut config = Self::default();

        // Load development mode
        if let Ok(dev_mode) = std::env::var("DEVELOPMENT_MODE") {
            config.development_mode = dev_mode.parse().unwrap_or(false);
        }

        // Load HSTS setting
        if let Ok(hsts_str) = std::env::var("STRICT_TRANSPORT_SECURITY_ENABLED") {
            config.strict_transport_security_enabled = hsts_str.parse().unwrap_or(true);
        }

        // Load host validation settings
        if let Ok(enabled_str) = std::env::var("HOST_VALIDATION_ENABLED") {
            config.host_validation.enabled = enabled_str.parse().unwrap_or(true);
        }

        if let Ok(strict_port_str) = std::env::var("STRICT_PORT_VALIDATION") {
            config.host_validation.strict_port_validation = strict_port_str.parse().unwrap_or(true);
        }

        // Load allowed ports
        if let Ok(ports_str) = std::env::var("ALLOWED_PORTS") {
            let ports: Vec<u16> = ports_str
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            if !ports.is_empty() {
                config.host_validation.allowed_ports = Some(ports);
            }
        }

        // Load CORS configuration
        if let Ok(enabled_str) = std::env::var("CORS_ENABLED") {
            config.cors.enabled = enabled_str.parse().unwrap_or(true);
        }

        if let Ok(origins_str) = std::env::var("CORS_ALLOWED_ORIGINS") {
            config.cors.allowed_origins = origins_str
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();
        }

        if let Ok(methods_str) = std::env::var("CORS_ALLOWED_METHODS") {
            config.cors.allowed_methods = methods_str
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();
        }

        if let Ok(headers_str) = std::env::var("CORS_ALLOWED_HEADERS") {
            config.cors.allowed_headers = headers_str
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();
        }

        if let Ok(creds_str) = std::env::var("CORS_ALLOW_CREDENTIALS") {
            config.cors.allow_credentials = creds_str.parse().unwrap_or(true);
        }

        if let Ok(max_age_str) = std::env::var("CORS_MAX_AGE") {
            config.cors.max_age = max_age_str.parse().ok();
        }

        config
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            headers: SecurityHeadersConfig::default(),
            cors: CorsConfig::default(),
            host_validation: HostValidationConfig::default(),
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
    pub async fn from_env() -> Result<Self, ConfigError> {
        Self::from_env_async().await
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
                key_prefix: "dbx:rate_limit".to_string(),
                graceful_degradation: true,
            })
            .unwrap_or_default();

        // Load security configuration from environment variables or use defaults
        let security_config = SecurityConfig::from_env_or_default();

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
        env::remove_var("JWT_EXPIRATION_SECONDS");
        env::remove_var("JWT_ACCESS_TOKEN_EXPIRATION");
        env::remove_var("JWT_REFRESH_TOKEN_EXPIRATION");
        env::remove_var("JWT_ISSUER");
        env::remove_var("CREATE_DEFAULT_ADMIN");
        env::remove_var("DEFAULT_ADMIN_USERNAME");
        env::remove_var("DEFAULT_ADMIN_PASSWORD");

        // Clear backend configuration
        env::remove_var("DBX_BACKEND_1_URL");
        env::remove_var("DBX_BACKEND_1_PROVIDER");
        env::remove_var("DBX_BACKEND_1_NAME");
        env::remove_var("DBX_BACKEND_1_POOL_SIZE");
        env::remove_var("DBX_DEFAULT_BACKEND");

        // Clear environment variables that might interfere with test defaults
        env::remove_var("DEVELOPMENT_MODE");
        env::remove_var("LOG_LEVEL");
    }

    fn setup_test_env() {
        clear_env_vars(); // Clear any existing environment variables

        // Set up test environment with required variables
        env::set_var(
            "JWT_SECRET",
            "test-jwt-secret-that-is-at-least-32-characters-long",
        );
        env::set_var("DBX_BACKEND_1_URL", "mock://localhost:6379");
        env::set_var("DBX_BACKEND_1_PROVIDER", "mock");
        env::set_var("DBX_BACKEND_1_NAME", "test_backend");
        env::set_var("DBX_BACKEND_1_POOL_SIZE", "10");
        env::set_var("DBX_DEFAULT_BACKEND", "test_backend");
    }

    fn cleanup_test_env() {
        clear_env_vars();
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

    #[tokio::test]
    #[serial]
    async fn test_app_config_from_env_defaults() {
        setup_test_env();

        let config = AppConfig::from_env().await.unwrap();
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 3000);

        assert_eq!(config.jwt.access_token_expiration, 3600);
        assert_eq!(config.jwt.refresh_token_expiration, 25200);
        assert_eq!(config.jwt.issuer, "dbx");
        assert!(!config.create_default_admin);

        cleanup_test_env();
    }

    #[tokio::test]
    #[serial]
    async fn test_app_config_custom_values() {
        setup_test_env(); // Set up backend configuration first

        // Additional environment variables for this test
        env::set_var("HOST", "127.0.0.1");
        env::set_var("PORT", "8080");
        env::set_var("JWT_EXPIRATION_SECONDS", "1800");
        env::set_var("JWT_ISSUER", "test-issuer");
        env::set_var("CREATE_DEFAULT_ADMIN", "true");
        env::set_var("DEFAULT_ADMIN_USERNAME", "testadmin");
        env::set_var("DEFAULT_ADMIN_PASSWORD", "testpassword123");

        let config = AppConfig::from_env().await.unwrap();
        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 8080);

        assert_eq!(config.jwt.access_token_expiration, 1800);
        assert_eq!(config.jwt.refresh_token_expiration, 12600); // 1800 * 7
        assert_eq!(config.jwt.issuer, "test-issuer");
        assert!(config.create_default_admin);
        assert_eq!(config.default_admin_username, Some("testadmin".to_string()));
        assert_eq!(
            config.default_admin_password,
            Some("testpassword123".to_string())
        );

        cleanup_test_env();
    }

    #[tokio::test]
    #[serial]
    async fn test_app_config_missing_jwt_secret() {
        env::remove_var("JWT_SECRET");
        // Ensure backend config is still set
        env::set_var("DBX_BACKEND_1_URL", "mock://localhost:6379");
        env::set_var("DBX_BACKEND_1_PROVIDER", "mock");
        env::set_var("DBX_BACKEND_1_NAME", "test_backend");
        env::set_var("DBX_BACKEND_1_POOL_SIZE", "10");
        env::set_var("DBX_DEFAULT_BACKEND", "test_backend");

        let result = AppConfig::from_env().await;
        assert!(matches!(
            result,
            Err(ConfigError::MissingEnvironmentVariable(_))
        ));

        cleanup_test_env();
    }

    #[tokio::test]
    #[serial]
    async fn test_app_config_invalid_port() {
        setup_test_env();
        env::set_var("PORT", "invalid_port");

        let result = AppConfig::from_env().await;
        assert!(matches!(result, Err(ConfigError::DbxConfig(_))));

        cleanup_test_env();
    }

    #[tokio::test]
    #[serial]
    async fn test_app_config_create_admin_without_password() {
        setup_test_env();
        env::set_var("CREATE_DEFAULT_ADMIN", "true");
        env::set_var("DEFAULT_ADMIN_USERNAME", "admin");
        // Don't set DEFAULT_ADMIN_PASSWORD

        let result = AppConfig::from_env().await;
        assert!(matches!(
            result,
            Err(ConfigError::MissingDefaultAdminPassword)
        ));

        cleanup_test_env();
    }

    #[tokio::test]
    #[serial]
    async fn test_app_config_short_jwt_secret() {
        setup_test_env();
        env::set_var("JWT_SECRET", "short");

        let result = AppConfig::from_env().await;
        assert!(matches!(result, Err(ConfigError::InvalidJwtSecret)));

        cleanup_test_env();
    }
}
