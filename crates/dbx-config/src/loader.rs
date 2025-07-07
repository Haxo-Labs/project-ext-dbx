use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;

use crate::{BackendConfig, ConfigError, ConfigResult, ConfigValidator, DbxConfig};

/// Configuration loader
pub struct ConfigLoader;

impl ConfigLoader {
    /// Load configuration from a YAML file
    pub async fn load_from_file<P: AsRef<Path>>(path: P) -> ConfigResult<DbxConfig> {
        let path = path.as_ref();
        let content = fs::read_to_string(path).map_err(|e| {
            ConfigError::file_error(e.to_string(), Some(path.to_string_lossy().to_string()))
        })?;

        let config: DbxConfig = serde_yaml::from_str(&content)?;
        ConfigValidator::validate_config(&config)?;

        Ok(config)
    }

    /// Load configuration from environment variables
    pub async fn load_from_env() -> ConfigResult<DbxConfig> {
        let mut config = DbxConfig::default();

        // Load server configuration
        Self::load_server_config_from_env(&mut config)?;

        // Load backend configurations
        Self::load_backends_from_env(&mut config)?;

        // Load routing configuration
        Self::load_routing_from_env(&mut config)?;

        // Load performance configuration
        Self::load_performance_from_env(&mut config)?;

        // Load security configuration
        Self::load_security_from_env(&mut config)?;

        ConfigValidator::validate_config(&config)?;

        Ok(config)
    }

    /// Load configuration from file with environment variable overrides
    pub async fn load_with_env_overrides<P: AsRef<Path>>(path: P) -> ConfigResult<DbxConfig> {
        let mut config = Self::load_from_file(path).await?;

        // Apply environment variable overrides
        Self::apply_env_overrides(&mut config)?;

        ConfigValidator::validate_config(&config)?;

        Ok(config)
    }

    /// Load configuration with automatic discovery
    pub async fn load_auto() -> ConfigResult<DbxConfig> {
        // Try to load from files in order of preference
        let config_files = [
            "dbx.yaml",
            "dbx.yml",
            "config/dbx.yaml",
            "config/dbx.yml",
            "/etc/dbx/config.yaml",
            "/etc/dbx/config.yml",
        ];

        for file_path in &config_files {
            if Path::new(file_path).exists() {
                return Self::load_with_env_overrides(file_path).await;
            }
        }

        // Fall back to environment variables only
        Self::load_from_env().await
    }

    /// Save configuration to a YAML file
    pub async fn save_to_file<P: AsRef<Path>>(config: &DbxConfig, path: P) -> ConfigResult<()> {
        let path = path.as_ref();
        let content = serde_yaml::to_string(config)
            .map_err(|e| ConfigError::parse_error(format!("Failed to serialize config: {}", e)))?;

        fs::write(path, content).map_err(|e| {
            ConfigError::file_error(e.to_string(), Some(path.to_string_lossy().to_string()))
        })?;

        Ok(())
    }

    /// Load server configuration from environment variables
    fn load_server_config_from_env(config: &mut DbxConfig) -> ConfigResult<()> {
        if let Ok(host) = env::var("DBX_HOST") {
            config.server.host = host;
        } else if let Ok(host) = env::var("HOST") {
            config.server.host = host;
        }

        if let Ok(port_str) = env::var("DBX_PORT") {
            config.server.port = port_str.parse().map_err(|e| {
                ConfigError::environment_error(
                    format!("Invalid port value '{}': {}", port_str, e),
                    Some("DBX_PORT".to_string()),
                )
            })?;
        } else if let Ok(port_str) = env::var("PORT") {
            config.server.port = port_str.parse().map_err(|e| {
                ConfigError::environment_error(
                    format!("Invalid port value '{}': {}", port_str, e),
                    Some("PORT".to_string()),
                )
            })?;
        }

        if let Ok(workers_str) = env::var("DBX_WORKERS") {
            config.server.workers = Some(workers_str.parse().map_err(|e| {
                ConfigError::environment_error(
                    format!("Invalid workers value '{}': {}", workers_str, e),
                    Some("DBX_WORKERS".to_string()),
                )
            })?);
        }

        if let Ok(websocket_str) = env::var("DBX_WEBSOCKET_ENABLED") {
            config.server.websocket_enabled = websocket_str.parse().map_err(|e| {
                ConfigError::environment_error(
                    format!("Invalid websocket enabled value '{}': {}", websocket_str, e),
                    Some("DBX_WEBSOCKET_ENABLED".to_string()),
                )
            })?;
        }

        Ok(())
    }

    /// Load backend configurations from environment variables
    fn load_backends_from_env(config: &mut DbxConfig) -> ConfigResult<()> {
        // Primary backend configuration
        if let Ok(url) = env::var("DATABASE_URL") {
            let provider = Self::detect_provider_from_url(&url)?;
            let backend_config = BackendConfig {
                provider,
                url,
                pool_size: env::var("DBX_POOL_SIZE").ok().and_then(|s| s.parse().ok()),
                timeout_ms: env::var("DBX_TIMEOUT_MS").ok().and_then(|s| s.parse().ok()),
                retry_attempts: env::var("DBX_RETRY_ATTEMPTS")
                    .ok()
                    .and_then(|s| s.parse().ok()),
                retry_delay_ms: env::var("DBX_RETRY_DELAY_MS")
                    .ok()
                    .and_then(|s| s.parse().ok()),
                capabilities: None,
                additional_config: HashMap::new(),
            };

            config
                .backends
                .insert("default".to_string(), backend_config);
            config.routing.default_backend = "default".to_string();
        }

        // Redis-specific configuration (for backward compatibility)
        if let Ok(redis_url) = env::var("REDIS_URL") {
            let backend_config = BackendConfig {
                provider: "redis".to_string(),
                url: redis_url,
                pool_size: env::var("REDIS_POOL_SIZE")
                    .ok()
                    .and_then(|s| s.parse().ok()),
                timeout_ms: env::var("REDIS_TIMEOUT_MS")
                    .ok()
                    .and_then(|s| s.parse().ok()),
                retry_attempts: None,
                retry_delay_ms: None,
                capabilities: None,
                additional_config: HashMap::new(),
            };

            let backend_name = if config.backends.is_empty() {
                config.routing.default_backend = "redis".to_string();
                "redis".to_string()
            } else {
                "redis".to_string()
            };

            config.backends.insert(backend_name, backend_config);
        }

        // Load additional backends from numbered environment variables
        for i in 1..=10 {
            let url_var = format!("DBX_BACKEND_{}_URL", i);
            let provider_var = format!("DBX_BACKEND_{}_PROVIDER", i);
            let name_var = format!("DBX_BACKEND_{}_NAME", i);

            if let (Ok(url), Ok(provider)) = (env::var(&url_var), env::var(&provider_var)) {
                let name = env::var(&name_var).unwrap_or_else(|_| format!("backend_{}", i));

                let backend_config = BackendConfig {
                    provider,
                    url,
                    pool_size: env::var(&format!("DBX_BACKEND_{}_POOL_SIZE", i))
                        .ok()
                        .and_then(|s| s.parse().ok()),
                    timeout_ms: env::var(&format!("DBX_BACKEND_{}_TIMEOUT_MS", i))
                        .ok()
                        .and_then(|s| s.parse().ok()),
                    retry_attempts: None,
                    retry_delay_ms: None,
                    capabilities: None,
                    additional_config: HashMap::new(),
                };

                config.backends.insert(name, backend_config);
            }
        }

        Ok(())
    }

    /// Load routing configuration from environment variables
    fn load_routing_from_env(config: &mut DbxConfig) -> ConfigResult<()> {
        if let Ok(default_backend) = env::var("DBX_DEFAULT_BACKEND") {
            config.routing.default_backend = default_backend;
        }

        // Load operation routing
        for (key, value) in env::vars() {
            if let Some(operation) = key.strip_prefix("DBX_ROUTE_") {
                let operation = operation.to_lowercase();
                config.routing.operation_routing.insert(operation, value);
            }
        }

        Ok(())
    }

    /// Load performance configuration from environment variables
    fn load_performance_from_env(config: &mut DbxConfig) -> ConfigResult<()> {
        if let Ok(timeout_str) = env::var("DBX_QUERY_TIMEOUT_MS") {
            config.performance.query_timeout_ms = timeout_str.parse().map_err(|e| {
                ConfigError::environment_error(
                    format!("Invalid query timeout value '{}': {}", timeout_str, e),
                    Some("DBX_QUERY_TIMEOUT_MS".to_string()),
                )
            })?;
        }

        if let Ok(concurrent_str) = env::var("DBX_MAX_CONCURRENT_OPERATIONS") {
            config.performance.max_concurrent_operations = concurrent_str.parse().map_err(|e| {
                ConfigError::environment_error(
                    format!(
                        "Invalid concurrent operations value '{}': {}",
                        concurrent_str, e
                    ),
                    Some("DBX_MAX_CONCURRENT_OPERATIONS".to_string()),
                )
            })?;
        }

        if let Ok(cache_str) = env::var("DBX_CACHE_ENABLED") {
            config.performance.cache_enabled = cache_str.parse().map_err(|e| {
                ConfigError::environment_error(
                    format!("Invalid cache enabled value '{}': {}", cache_str, e),
                    Some("DBX_CACHE_ENABLED".to_string()),
                )
            })?;
        }

        if let Ok(metrics_str) = env::var("DBX_METRICS_ENABLED") {
            config.performance.metrics_enabled = metrics_str.parse().map_err(|e| {
                ConfigError::environment_error(
                    format!("Invalid metrics enabled value '{}': {}", metrics_str, e),
                    Some("DBX_METRICS_ENABLED".to_string()),
                )
            })?;
        }

        Ok(())
    }

    /// Load security configuration from environment variables
    fn load_security_from_env(config: &mut DbxConfig) -> ConfigResult<()> {
        if let Ok(auth_str) = env::var("DBX_AUTH_REQUIRED") {
            config.security.authentication_required = auth_str.parse().map_err(|e| {
                ConfigError::environment_error(
                    format!("Invalid auth required value '{}': {}", auth_str, e),
                    Some("DBX_AUTH_REQUIRED".to_string()),
                )
            })?;
        }

        if let Ok(tls_str) = env::var("DBX_TLS_ENABLED") {
            config.security.encryption_in_transit = tls_str.parse().map_err(|e| {
                ConfigError::environment_error(
                    format!("Invalid TLS enabled value '{}': {}", tls_str, e),
                    Some("DBX_TLS_ENABLED".to_string()),
                )
            })?;
        }

        // Load JWT configuration
        if let Ok(jwt_secret) = env::var("JWT_SECRET") {
            config.security.jwt = Some(crate::JwtConfig {
                secret: jwt_secret,
                expiration_seconds: env::var("JWT_EXPIRATION_SECONDS")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(3600),
                issuer: env::var("JWT_ISSUER").unwrap_or_else(|_| "dbx".to_string()),
                audience: env::var("JWT_AUDIENCE").ok(),
            });
        }

        Ok(())
    }

    /// Apply environment variable overrides to existing configuration
    fn apply_env_overrides(config: &mut DbxConfig) -> ConfigResult<()> {
        // Override server settings
        Self::load_server_config_from_env(config)?;

        // Override performance settings
        Self::load_performance_from_env(config)?;

        // Override security settings
        Self::load_security_from_env(config)?;

        Ok(())
    }

    /// Detect provider type from URL scheme
    fn detect_provider_from_url(url: &str) -> ConfigResult<String> {
        let parsed = url::Url::parse(url).map_err(|e| ConfigError::InvalidUrl {
            url: url.to_string(),
            error: e.to_string(),
        })?;

        let provider = match parsed.scheme() {
            "redis" | "rediss" => "redis",
            "postgres" | "postgresql" => "postgresql",
            "mongodb" | "mongodb+srv" => "mongodb",
            "mysql" => "mysql",
            "sqlite" => "sqlite",
            "mdbx" => "mdbx",
            _ => {
                return Err(ConfigError::InvalidUrl {
                    url: url.to_string(),
                    error: format!("Unknown provider scheme: {}", parsed.scheme()),
                });
            }
        };

        Ok(provider.to_string())
    }
}

/// Configuration builder for programmatic configuration
pub struct ConfigBuilder {
    config: DbxConfig,
}

impl ConfigBuilder {
    /// Create a new configuration builder
    pub fn new() -> Self {
        Self {
            config: DbxConfig::default(),
        }
    }

    /// Add a backend configuration
    pub fn add_backend<S: Into<String>>(mut self, name: S, config: BackendConfig) -> Self {
        self.config.backends.insert(name.into(), config);
        self
    }

    /// Set the default backend
    pub fn default_backend<S: Into<String>>(mut self, name: S) -> Self {
        self.config.routing.default_backend = name.into();
        self
    }

    /// Set server configuration
    pub fn server_config(mut self, config: crate::ServerConfig) -> Self {
        self.config.server = config;
        self
    }

    /// Set performance configuration
    pub fn performance_config(mut self, config: crate::PerformanceConfig) -> Self {
        self.config.performance = config;
        self
    }

    /// Set security configuration
    pub fn security_config(mut self, config: crate::SecurityConfig) -> Self {
        self.config.security = config;
        self
    }

    /// Build the configuration
    pub fn build(self) -> ConfigResult<DbxConfig> {
        ConfigValidator::validate_config(&self.config)?;
        Ok(self.config)
    }
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}
