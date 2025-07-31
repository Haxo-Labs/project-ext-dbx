//! PostgreSQL backend factory
//!
//! This module provides factory functions for creating PostgreSQL backends
//! with different configuration options.

use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, info};

use dbx_config::BackendConfig;
use dbx_core::UniversalBackend;
use dbx_router::registry::BackendFactory;
use dbx_router::{RouterError, RouterResult};

use super::backend::PostgresBackend;

/// Factory for creating PostgreSQL backend instances
pub struct PostgresBackendFactory;

impl PostgresBackendFactory {
    /// Create a new PostgreSQL backend factory
    pub fn new() -> Self {
        Self
    }
}

impl Default for PostgresBackendFactory {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BackendFactory for PostgresBackendFactory {
    async fn create_backend(
        &self,
        name: &str,
        config: &BackendConfig,
    ) -> RouterResult<Arc<dyn UniversalBackend>> {
        debug!(backend = %name, provider = %config.provider, "Creating PostgreSQL backend");

        // Validate that this is a PostgreSQL configuration
        if config.provider != "postgresql" && config.provider != "postgres" {
            return Err(RouterError::backend_initialization(
                name.to_string(),
                format!(
                    "Expected provider 'postgresql' or 'postgres', got '{}'",
                    config.provider
                ),
            ));
        }

        // Create the PostgreSQL backend
        let pool_size = config.pool_size.unwrap_or(10) as usize;
        let backend = PostgresBackend::from_url(&config.url, name.to_string(), pool_size)
            .await
            .map_err(|e| {
                RouterError::backend_initialization(
                    name.to_string(),
                    format!("Failed to create PostgreSQL backend: {}", e),
                )
            })?;

        info!(
            backend = %name,
            provider = %config.provider,
            url = %config.url,
            pool_size = %pool_size,
            "PostgreSQL backend created successfully"
        );

        Ok(Arc::new(backend))
    }

    fn provider_name(&self) -> &str {
        "postgresql"
    }

    fn validate_config(&self, config: &BackendConfig) -> RouterResult<()> {
        // Check provider
        if config.provider != "postgresql" && config.provider != "postgres" {
            return Err(RouterError::routing_configuration(format!(
                "Invalid provider '{}' for PostgreSQL factory",
                config.provider
            )));
        }

        // Check URL format
        if !config.url.starts_with("postgresql://") && !config.url.starts_with("postgres://") {
            return Err(RouterError::routing_configuration(format!(
                "Invalid PostgreSQL URL format: '{}'. Must start with 'postgresql://' or 'postgres://'",
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

        debug!(provider = %config.provider, url = %config.url, "PostgreSQL configuration validated");
        Ok(())
    }
}
