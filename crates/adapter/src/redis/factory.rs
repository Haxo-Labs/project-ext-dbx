use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, info};

use dbx_config::BackendConfig;
use dbx_core::UniversalBackend;
use dbx_router::{BackendFactory, RouterError, RouterResult};

use super::backend::RedisBackend;

/// Factory for creating Redis backend instances
pub struct RedisBackendFactory;

impl RedisBackendFactory {
    /// Create a new Redis backend factory
    pub fn new() -> Self {
        Self
    }
}

impl Default for RedisBackendFactory {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BackendFactory for RedisBackendFactory {
    async fn create_backend(
        &self,
        name: &str,
        config: &BackendConfig,
    ) -> RouterResult<Arc<dyn UniversalBackend>> {
        debug!(backend = %name, provider = %config.provider, "Creating Redis backend");

        // Validate that this is a Redis configuration
        if config.provider != "redis" {
            return Err(RouterError::backend_initialization(
                name.to_string(),
                format!("Expected provider 'redis', got '{}'", config.provider),
            ));
        }

        // Create the Redis backend
        let backend = RedisBackend::from_url(&config.url, name.to_string()).map_err(|e| {
            RouterError::backend_initialization(
                name.to_string(),
                format!("Failed to create Redis backend: {}", e),
            )
        })?;

        info!(backend = %name, url = %config.url, "Redis backend created successfully");

        Ok(Arc::new(backend))
    }

    fn provider_name(&self) -> &str {
        "redis"
    }

    fn validate_config(&self, config: &BackendConfig) -> RouterResult<()> {
        // Check provider
        if config.provider != "redis" {
            return Err(RouterError::routing_configuration(format!(
                "Invalid provider '{}' for Redis factory",
                config.provider
            )));
        }

        // Check URL format
        if !config.url.starts_with("redis://") && !config.url.starts_with("rediss://") {
            return Err(RouterError::routing_configuration(format!(
                "Invalid Redis URL format: '{}'. Must start with 'redis://' or 'rediss://'",
                config.url
            )));
        }

        // Validate optional parameters
        if let Some(pool_size) = config.pool_size {
            if pool_size == 0 || pool_size > 1000 {
                return Err(RouterError::routing_configuration(
                    "Pool size must be between 1 and 1000".to_string(),
                ));
            }
        }

        if let Some(timeout_ms) = config.timeout_ms {
            if timeout_ms < 100 || timeout_ms > 60000 {
                return Err(RouterError::routing_configuration(
                    "Timeout must be between 100ms and 60s".to_string(),
                ));
            }
        }

        if let Some(retry_attempts) = config.retry_attempts {
            if retry_attempts > 10 {
                return Err(RouterError::routing_configuration(
                    "Retry attempts must not exceed 10".to_string(),
                ));
            }
        }

        if let Some(retry_delay_ms) = config.retry_delay_ms {
            if retry_delay_ms < 100 || retry_delay_ms > 30000 {
                return Err(RouterError::routing_configuration(
                    "Retry delay must be between 100ms and 30s".to_string(),
                ));
            }
        }

        debug!(provider = %config.provider, url = %config.url, "Redis configuration validated");
        Ok(())
    }
}

/// Helper function to create a Redis backend factory
pub fn create_redis_factory() -> RedisBackendFactory {
    RedisBackendFactory::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use dbx_config::BackendConfig;

    #[test]
    fn test_redis_factory_provider_name() {
        let factory = RedisBackendFactory::new();
        assert_eq!(factory.provider_name(), "redis");
    }

    #[tokio::test]
    async fn test_redis_factory_validate_config() {
        let factory = RedisBackendFactory::new();

        // Valid config
        let valid_config = BackendConfig {
            provider: "redis".to_string(),
            url: "redis://localhost:6379".to_string(),
            pool_size: Some(10),
            timeout_ms: Some(5000),
            retry_attempts: Some(3),
            retry_delay_ms: Some(1000),
            capabilities: None,
            additional_config: std::collections::HashMap::new(),
        };

        assert!(factory.validate_config(&valid_config).is_ok());

        // Invalid provider
        let invalid_provider = BackendConfig {
            provider: "postgresql".to_string(),
            url: "redis://localhost:6379".to_string(),
            pool_size: None,
            timeout_ms: None,
            retry_attempts: None,
            retry_delay_ms: None,
            capabilities: None,
            additional_config: std::collections::HashMap::new(),
        };

        assert!(factory.validate_config(&invalid_provider).is_err());

        // Invalid URL
        let invalid_url = BackendConfig {
            provider: "redis".to_string(),
            url: "http://localhost:6379".to_string(),
            pool_size: None,
            timeout_ms: None,
            retry_attempts: None,
            retry_delay_ms: None,
            capabilities: None,
            additional_config: std::collections::HashMap::new(),
        };

        assert!(factory.validate_config(&invalid_url).is_err());

        // Invalid pool size
        let invalid_pool_size = BackendConfig {
            provider: "redis".to_string(),
            url: "redis://localhost:6379".to_string(),
            pool_size: Some(0),
            timeout_ms: None,
            retry_attempts: None,
            retry_delay_ms: None,
            capabilities: None,
            additional_config: std::collections::HashMap::new(),
        };

        assert!(factory.validate_config(&invalid_pool_size).is_err());
    }
}
