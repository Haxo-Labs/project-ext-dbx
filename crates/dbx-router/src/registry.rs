use async_trait::async_trait;
use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, info};

use dbx_config::{BackendConfig, DbxConfig};
use dbx_core::{DbxError, DbxResult, UniversalBackend};

use crate::RouterResult;

/// Registry for managing backend instances
pub struct BackendRegistry {
    backends: Arc<DashMap<String, Arc<dyn UniversalBackend>>>,
    factories: Arc<DashMap<String, Box<dyn BackendFactory>>>,
}

impl BackendRegistry {
    /// Create a new backend registry
    pub fn new() -> Self {
        Self {
            backends: Arc::new(DashMap::new()),
            factories: Arc::new(DashMap::new()),
        }
    }

    /// Register a backend factory for a specific provider
    pub fn register_factory<F>(&self, provider: &str, factory: F)
    where
        F: BackendFactory + 'static,
    {
        self.factories
            .insert(provider.to_string(), Box::new(factory));
        info!(provider = %provider, "Registered backend factory");
    }

    /// Initialize backends from configuration
    pub async fn initialize_backends(&self, config: &DbxConfig) -> DbxResult<()> {
        info!("Initializing backends from configuration");

        for (name, backend_config) in &config.backends {
            match self.create_backend(name, backend_config).await {
                Ok(backend) => {
                    self.backends.insert(name.clone(), backend);
                    info!(backend = %name, provider = %backend_config.provider, "Backend initialized successfully");
                }
                Err(e) => {
                    error!(
                        backend = %name,
                        provider = %backend_config.provider,
                        error = %e,
                        "Failed to initialize backend"
                    );
                    return Err(e);
                }
            }
        }

        let backend_count = self.backends.len();
        info!(
            backend_count = backend_count,
            "All backends initialized successfully"
        );

        Ok(())
    }

    /// Create a backend instance from configuration
    async fn create_backend(
        &self,
        name: &str,
        config: &BackendConfig,
    ) -> DbxResult<Arc<dyn UniversalBackend>> {
        debug!(backend = %name, provider = %config.provider, "Creating backend instance");

        let factory = self.factories.get(&config.provider).ok_or_else(|| {
            DbxError::configuration(format!(
                "No factory registered for provider '{}' (backend: '{}')",
                config.provider, name
            ))
        })?;

        let backend = factory.create_backend(name, config).await.map_err(|e| {
            DbxError::backend(name.to_string(), format!("Failed to create backend: {}", e))
        })?;

        // Test the connection
        backend.test_connection().await.map_err(|e| {
            DbxError::connection(
                name.to_string(),
                format!("Backend connection test failed: {}", e),
            )
        })?;

        debug!(backend = %name, "Backend created and connection tested successfully");

        Ok(backend)
    }

    /// Get a backend by name
    pub async fn get_backend(&self, name: &str) -> Option<Arc<dyn UniversalBackend>> {
        self.backends.get(name).map(|entry| entry.value().clone())
    }

    /// Check if a backend exists
    pub async fn has_backend(&self, name: &str) -> bool {
        self.backends.contains_key(name)
    }

    /// List all backend names
    pub async fn list_backends(&self) -> Vec<String> {
        self.backends
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Get backends that support a specific capability/operation
    pub async fn get_backends_with_capability(&self, operation_type: &str) -> Vec<String> {
        let mut capable_backends = Vec::new();

        // Convert operation type string to enum
        let operation_enum = match operation_type {
            "get" => Some(dbx_core::DataOperationType::Get),
            "set" => Some(dbx_core::DataOperationType::Set),
            "update" => Some(dbx_core::DataOperationType::Update),
            "delete" => Some(dbx_core::DataOperationType::Delete),
            "exists" => Some(dbx_core::DataOperationType::Exists),
            "get_ttl" => Some(dbx_core::DataOperationType::GetTtl),
            "set_ttl" => Some(dbx_core::DataOperationType::SetTtl),
            "batch" => Some(dbx_core::DataOperationType::Batch),
            _ => None,
        };

        if let Some(op_type) = operation_enum {
            for entry in self.backends.iter() {
                let backend_name = entry.key();
                let backend = entry.value();

                let capabilities = backend.capabilities();
                if capabilities.data_operations.contains(&op_type) {
                    capable_backends.push(backend_name.clone());
                }
            }
        }

        capable_backends
    }

    /// Get backends that support specific stream capabilities
    pub async fn get_backends_with_stream_capability(&self, operation_type: &str) -> Vec<String> {
        let mut capable_backends = Vec::new();

        for entry in self.backends.iter() {
            let backend_name = entry.key();
            let backend = entry.value();

            let capabilities = backend.capabilities();
            let supports_operation = match operation_type {
                "subscribe" | "unsubscribe" | "publish" => capabilities.stream_capabilities.pub_sub,
                "create_stream" | "stream_add" | "stream_read" => {
                    capabilities.stream_capabilities.streams
                }
                _ => false,
            };

            if supports_operation {
                capable_backends.push(backend_name.clone());
            }
        }

        capable_backends
    }

    /// Remove a backend
    pub async fn remove_backend(&self, name: &str) -> Option<Arc<dyn UniversalBackend>> {
        if let Some((_, backend)) = self.backends.remove(name) {
            info!(backend = %name, "Backend removed from registry");
            Some(backend)
        } else {
            None
        }
    }

    /// Perform health checks on all backends
    pub async fn health_check_all(&self) -> HashMap<String, DbxResult<dbx_core::BackendHealth>> {
        let mut results = HashMap::new();

        for entry in self.backends.iter() {
            let name = entry.key().clone();
            let backend = entry.value().clone();

            let result = backend.health_check().await;
            results.insert(name, result);
        }

        results
    }

    /// Get statistics for all backends
    pub async fn get_all_stats(&self) -> HashMap<String, DbxResult<dbx_core::BackendStats>> {
        let mut results = HashMap::new();

        for entry in self.backends.iter() {
            let name = entry.key().clone();
            let backend = entry.value().clone();

            let result = backend.get_stats().await;
            results.insert(name, result);
        }

        results
    }

    /// Reload a specific backend with new configuration
    pub async fn reload_backend(&self, name: &str, config: &BackendConfig) -> DbxResult<()> {
        info!(backend = %name, "Reloading backend with new configuration");

        // Create new backend instance
        let new_backend = self.create_backend(name, config).await?;

        // Replace the old backend
        self.backends.insert(name.to_string(), new_backend);

        info!(backend = %name, "Backend reloaded successfully");
        Ok(())
    }

    /// Get registry statistics
    pub async fn get_registry_stats(&self) -> RegistryStats {
        let total_backends = self.backends.len();
        let registered_providers: Vec<String> = self
            .factories
            .iter()
            .map(|entry| entry.key().clone())
            .collect();

        // Count backends by provider
        let mut provider_counts = HashMap::new();
        for entry in self.backends.iter() {
            let backend = entry.value();
            let provider = backend.name(); // Provider name from backend implementation
            *provider_counts.entry(provider.to_string()).or_insert(0) += 1;
        }

        RegistryStats {
            total_backends,
            registered_providers,
            provider_counts,
        }
    }

    /// Shutdown all backends gracefully
    pub async fn shutdown(&self) -> DbxResult<()> {
        info!("Shutting down all backends");

        let backend_names: Vec<String> = self
            .backends
            .iter()
            .map(|entry| entry.key().clone())
            .collect();

        for name in backend_names {
            if let Some(_backend) = self.remove_backend(&name).await {
                debug!(backend = %name, "Backend removed during shutdown");
            }
        }

        info!("All backends shut down");
        Ok(())
    }
}

impl Default for BackendRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Factory trait for creating backend instances
#[async_trait]
pub trait BackendFactory: Send + Sync {
    /// Create a new backend instance
    async fn create_backend(
        &self,
        name: &str,
        config: &BackendConfig,
    ) -> RouterResult<Arc<dyn UniversalBackend>>;

    /// Get the provider name this factory handles
    fn provider_name(&self) -> &str;

    /// Validate configuration for this provider
    fn validate_config(&self, config: &BackendConfig) -> RouterResult<()>;
}

/// Registry statistics
#[derive(Debug, Clone)]
pub struct RegistryStats {
    pub total_backends: usize,
    pub registered_providers: Vec<String>,
    pub provider_counts: HashMap<String, usize>,
}

/// Backend registry builder for easier configuration
pub struct BackendRegistryBuilder {
    registry: BackendRegistry,
}

impl BackendRegistryBuilder {
    /// Create a new registry builder
    pub fn new() -> Self {
        Self {
            registry: BackendRegistry::new(),
        }
    }

    /// Register a backend factory
    pub fn with_factory<F>(self, provider: &str, factory: F) -> Self
    where
        F: BackendFactory + 'static,
    {
        self.registry.register_factory(provider, factory);
        self
    }

    /// Build the registry
    pub fn build(self) -> BackendRegistry {
        self.registry
    }
}

impl Default for BackendRegistryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Macro for easier backend factory registration
#[macro_export]
macro_rules! register_backend_factories {
    ($registry:expr, $($provider:expr => $factory:expr),* $(,)?) => {
        $(
            $registry.register_factory($provider, $factory);
        )*
    };
}
