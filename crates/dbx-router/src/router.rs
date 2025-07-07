use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error};

use dbx_config::{DbxConfig, KeyRoutingRule};
use dbx_core::{DataOperation, DbxResult, QueryOperation, StreamOperation, UniversalBackend};

use crate::load_balancer::LoadBalancerStats;
use crate::matcher::MatcherStats;
use crate::{BackendRegistry, KeyMatcher, LoadBalancer};

/// Main router that orchestrates backend selection and operation dispatch
pub struct BackendRouter {
    registry: BackendRegistry,
    key_matcher: KeyMatcher,
    load_balancer: LoadBalancer,
    default_backend: Option<String>,
}

impl BackendRouter {
    /// Create a new backend router
    pub fn new(registry: BackendRegistry, config: &DbxConfig) -> DbxResult<Self> {
        let key_matcher = KeyMatcher::new(config.routing.key_routing.clone())?;
        let load_balancer =
            LoadBalancer::new(config.routing.load_balancing.clone().unwrap_or_default())?;

        Ok(Self {
            registry,
            key_matcher,
            load_balancer,
            default_backend: Some(config.routing.default_backend.clone()),
        })
    }

    /// Route a data operation to the appropriate backend
    pub async fn route_data_operation(
        &self,
        operation: &DataOperation,
    ) -> DbxResult<Arc<dyn UniversalBackend>> {
        // Try key-based routing first
        if let Some(key) = self.extract_key_from_data_operation(operation) {
            if let Some(backend_name) = self.key_matcher.match_key(key) {
                debug!(key = %key, backend = %backend_name, "Using key-based routing");

                if let Some(backend) = self.registry.get_backend(&backend_name).await {
                    return Ok(backend);
                }
            }
        }

        // Try operation-specific routing
        if let Some(backend) = self.route_by_operation_type(operation).await? {
            return Ok(backend);
        }

        // Use load balancer
        if let Some(backend) = self.load_balancer.select_backend().await? {
            debug!(backend = %backend, "Using load-balanced backend");

            if let Some(backend_instance) = self.registry.get_backend(&backend).await {
                return Ok(backend_instance);
            }
        }

        // Fall back to default backend
        if let Some(default_backend) = &self.default_backend {
            debug!(backend = %default_backend, "Using default backend");

            if let Some(backend) = self.registry.get_backend(default_backend).await {
                return Ok(backend);
            }
        }

        Err(dbx_core::DbxError::routing(
            "No suitable backend available".to_string(),
        ))
    }

    /// Route a query operation to the appropriate backend
    pub async fn route_query_operation(
        &self,
        _operation: &QueryOperation,
    ) -> DbxResult<Arc<dyn UniversalBackend>> {
        // For now, use the same routing logic as data operations
        // In the future, this could consider query complexity, read replicas, etc.

        // Use load balancer for queries
        if let Some(backend) = self.load_balancer.select_backend().await? {
            debug!(backend = %backend, "Using load-balanced backend for query");

            if let Some(backend_instance) = self.registry.get_backend(&backend).await {
                return Ok(backend_instance);
            }
        }

        // Fall back to default backend
        if let Some(default_backend) = &self.default_backend {
            debug!(backend = %default_backend, "Using default backend for query");

            if let Some(backend) = self.registry.get_backend(default_backend).await {
                return Ok(backend);
            }
        }

        Err(dbx_core::DbxError::routing(
            "No suitable backend available for query".to_string(),
        ))
    }

    /// Route a stream operation to the appropriate backend
    pub async fn route_stream_operation(
        &self,
        operation: &StreamOperation,
    ) -> DbxResult<Arc<dyn UniversalBackend>> {
        // Stream operations might require specific backends that support streaming
        // For now, use default backend or load balancer

        // If operation has a specific channel/topic, use key-based routing
        match operation {
            StreamOperation::Subscribe { channel, .. }
            | StreamOperation::Unsubscribe { channel, .. }
            | StreamOperation::Publish { channel, .. } => {
                if let Some(backend_name) = self.key_matcher.match_key(channel) {
                    debug!(channel = %channel, backend = %backend_name, "Using key-based routing for stream");

                    if let Some(backend) = self.registry.get_backend(&backend_name).await {
                        return Ok(backend);
                    }
                }
            }
            StreamOperation::CreateStream { name, .. } => {
                if let Some(backend_name) = self.key_matcher.match_key(name) {
                    debug!(stream = %name, backend = %backend_name, "Using key-based routing for stream");

                    if let Some(backend) = self.registry.get_backend(&backend_name).await {
                        return Ok(backend);
                    }
                }
            }
            StreamOperation::StreamAdd { stream, .. }
            | StreamOperation::StreamRead { stream, .. } => {
                if let Some(backend_name) = self.key_matcher.match_key(stream) {
                    debug!(stream = %stream, backend = %backend_name, "Using key-based routing for stream");

                    if let Some(backend) = self.registry.get_backend(&backend_name).await {
                        return Ok(backend);
                    }
                }
            }
        }

        // Fall back to default backend for streams
        if let Some(default_backend) = &self.default_backend {
            debug!(backend = %default_backend, "Using default backend for stream");

            if let Some(backend) = self.registry.get_backend(default_backend).await {
                return Ok(backend);
            }
        }

        Err(dbx_core::DbxError::routing(
            "No suitable backend available for stream".to_string(),
        ))
    }

    /// Get all backends for health checking
    pub async fn get_all_backends(&self) -> Vec<String> {
        self.registry.list_backends().await
    }

    /// Get backend by name
    pub async fn get_backend(&self, name: &str) -> Option<Arc<dyn UniversalBackend>> {
        self.registry.get_backend(name).await
    }

    /// Update load balancer with backend health
    pub async fn update_backend_health(&self, backend: &str, is_healthy: bool) {
        self.load_balancer
            .update_backend_health(backend, is_healthy)
            .await;
    }

    /// Get routing statistics
    pub async fn get_routing_stats(&self) -> RoutingStats {
        RoutingStats {
            total_backends: self.registry.list_backends().await.len(),
            load_balancer_stats: self.load_balancer.get_stats().await,
            key_matcher_stats: self.key_matcher.get_stats(),
        }
    }

    /// Extract key from data operation for routing
    fn extract_key_from_data_operation<'a>(&self, operation: &'a DataOperation) -> Option<&'a str> {
        match operation {
            DataOperation::Get { key, .. } => Some(key),
            DataOperation::Set { key, .. } => Some(key),
            DataOperation::Update { key, .. } => Some(key),
            DataOperation::Delete { key, .. } => Some(key),
            DataOperation::Exists { key, .. } => Some(key),
            DataOperation::SetTtl { key, .. } => Some(key),
            DataOperation::GetTtl { key } => Some(key),
            DataOperation::Batch { operations } => {
                // For batch operations, try to extract key from the first operation
                operations
                    .first()
                    .and_then(|op| self.extract_key_from_data_operation(op))
            }
        }
    }

    /// Route based on operation type
    async fn route_by_operation_type(
        &self,
        _operation: &DataOperation,
    ) -> DbxResult<Option<Arc<dyn UniversalBackend>>> {
        // This could be extended to route based on operation type
        // For example, reads could go to read replicas, writes to primary

        // For now, return None to fall through to load balancer
        Ok(None)
    }

    /// Add a backend to the load balancer
    pub async fn add_backend_to_load_balancer(&self, backend_name: String) {
        self.load_balancer.add_backend(backend_name).await;
    }

    /// Remove a backend from the load balancer
    pub async fn remove_backend_from_load_balancer(&self, backend_name: &str) {
        self.load_balancer.remove_backend(backend_name).await;
    }

    /// Perform health check on all backends
    pub async fn health_check_all(&self) -> HashMap<String, DbxResult<dbx_core::BackendHealth>> {
        self.registry.health_check_all().await
    }

    /// Try to get a backend by name with fallback logic
    async fn try_get_backend(&self, backend_name: &str) -> DbxResult<Arc<dyn UniversalBackend>> {
        // Try the specified backend first
        if let Some(backend) = self.registry.get_backend(backend_name).await {
            return Ok(backend);
        }

        // If specified backend is not available, try load balancer
        if let Some(fallback_backend) = self.load_balancer.select_backend().await? {
            if let Some(backend) = self.registry.get_backend(&fallback_backend).await {
                debug!(
                    requested = %backend_name,
                    fallback = %fallback_backend,
                    "Using fallback backend"
                );
                return Ok(backend);
            }
        }

        // Finally try default backend
        if let Some(default_backend) = &self.default_backend {
            match self.registry.get_backend(default_backend).await {
                Some(backend) => {
                    debug!(
                        requested = %backend_name,
                        default = %default_backend,
                        "Using default backend"
                    );
                    Ok(backend)
                }
                None => {
                    error!(
                        requested = %backend_name,
                        default = %default_backend,
                        "Default backend not available"
                    );
                    Err(dbx_core::DbxError::routing(format!(
                        "Backend '{}' not available and no fallback backends found",
                        backend_name
                    )))
                }
            }
        } else {
            Err(dbx_core::DbxError::routing(format!(
                "Backend '{}' not available and no default backend configured",
                backend_name
            )))
        }
    }
}

/// Routing statistics
#[derive(Debug, Clone)]
pub struct RoutingStats {
    pub total_backends: usize,
    pub load_balancer_stats: LoadBalancerStats,
    pub key_matcher_stats: MatcherStats,
}
