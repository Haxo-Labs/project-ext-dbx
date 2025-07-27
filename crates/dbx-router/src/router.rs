use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error};

use dbx_config::{DbxConfig, KeyRoutingRule};
use dbx_core::{DataOperation, DbxResult, QueryOperation, StreamOperation, UniversalBackend};

use crate::load_balancer::LoadBalancerStats;
use crate::matcher::{MatcherStats, OptimizedMatcherStats};
use crate::{BackendRegistry, KeyMatcher, LoadBalancer, OptimizedKeyMatcher};

/// Main router that orchestrates backend selection and operation dispatch
pub struct BackendRouter {
    registry: BackendRegistry,
    key_matcher: OptimizedKeyMatcher,
    load_balancer: LoadBalancer,
    default_backend: Option<String>,
}

impl BackendRouter {
    /// Create a new backend router with optimized routing
    pub fn new(registry: BackendRegistry, config: &DbxConfig) -> DbxResult<Self> {
        let key_matcher = OptimizedKeyMatcher::new(config.routing.key_routing.clone())?;
        let load_balancer =
            LoadBalancer::new(config.routing.load_balancing.clone().unwrap_or_default())?;

        Ok(Self {
            registry,
            key_matcher,
            load_balancer,
            default_backend: Some(config.routing.default_backend.clone()),
        })
    }

    /// Create a legacy router (for backwards compatibility)
    pub fn new_legacy(
        registry: BackendRegistry,
        config: &DbxConfig,
    ) -> DbxResult<LegacyBackendRouter> {
        let key_matcher = KeyMatcher::new(config.routing.key_routing.clone())?;
        let load_balancer =
            LoadBalancer::new(config.routing.load_balancing.clone().unwrap_or_default())?;

        Ok(LegacyBackendRouter {
            registry,
            key_matcher,
            load_balancer,
            default_backend: Some(config.routing.default_backend.clone()),
        })
    }

    /// Get optimized matcher performance statistics
    pub fn get_matcher_performance_stats(&self) -> OptimizedMatcherStats {
        self.key_matcher.get_performance_stats()
    }

    /// Benchmark router performance
    pub async fn benchmark_routing(
        &self,
        keys: &[String],
        iterations: usize,
    ) -> RouterBenchmarkResult {
        let start = std::time::Instant::now();
        let mut successful_routes = 0;

        for _ in 0..iterations {
            for key in keys {
                if self.key_matcher.match_key(key).is_some() {
                    successful_routes += 1;
                }
            }
        }

        let duration = start.elapsed();
        let total_operations = iterations * keys.len();

        RouterBenchmarkResult {
            total_operations,
            successful_routes,
            total_duration: duration,
            avg_duration_nanos: duration.as_nanos() as u64 / total_operations as u64,
            operations_per_second: (total_operations as f64 / duration.as_secs_f64()) as u64,
        }
    }

    /// Route a data operation to the appropriate backend
    pub async fn route_data_operation(
        &self,
        operation: &DataOperation,
    ) -> DbxResult<Arc<dyn UniversalBackend>> {
        // Get operation type for capability checking
        let operation_type = self.get_operation_type_from_data_operation(operation);

        // Try key-based routing first
        if let Some(key) = self.extract_key_from_data_operation(operation) {
            if let Some(backend_name) = self.key_matcher.match_key(key) {
                debug!(key = %key, backend = %backend_name, "Using key-based routing");

                if let Some(backend) = self.registry.get_backend(&backend_name).await {
                    // Check if backend supports this operation type
                    if self.backend_supports_operation(&backend, &operation_type) {
                        return Ok(backend);
                    } else {
                        debug!(backend = %backend_name, operation = %operation_type, "Backend doesn't support operation, trying alternatives");
                    }
                }
            }
        }

        // Try operation-specific routing with capability checking
        if let Some(backend) = self
            .route_by_operation_type_with_capabilities(operation)
            .await?
        {
            return Ok(backend);
        }

        // Use load balancer with capability filtering and key if available
        let key = self.extract_key_from_data_operation(operation);
        if let Some(backend_name) = self
            .load_balancer
            .select_backend_with_key(key.as_deref())
            .await?
        {
            debug!(backend = %backend_name, "Checking load-balanced backend capabilities");

            if let Some(backend) = self.registry.get_backend(&backend_name).await {
                if self.backend_supports_operation(&backend, &operation_type) {
                    return Ok(backend);
                } else {
                    // Try other backends from load balancer
                    for _ in 0..5 {
                        // Max 5 attempts
                        if let Some(alt_backend_name) = self
                            .load_balancer
                            .select_backend_with_key(key.as_deref())
                            .await?
                        {
                            if alt_backend_name != backend_name {
                                if let Some(alt_backend) =
                                    self.registry.get_backend(&alt_backend_name).await
                                {
                                    if self
                                        .backend_supports_operation(&alt_backend, &operation_type)
                                    {
                                        debug!(backend = %alt_backend_name, "Using alternative capable backend");
                                        return Ok(alt_backend);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Fall back to default backend with capability check
        if let Some(default_backend) = &self.default_backend {
            debug!(backend = %default_backend, "Checking default backend capabilities");

            if let Some(backend) = self.registry.get_backend(default_backend).await {
                if self.backend_supports_operation(&backend, &operation_type) {
                    return Ok(backend);
                } else {
                    return Err(dbx_core::DbxError::routing(format!(
                        "Default backend '{}' doesn't support operation type '{}'",
                        default_backend, operation_type
                    )));
                }
            }
        }

        Err(dbx_core::DbxError::routing(format!(
            "No backend available that supports operation type '{}'",
            operation_type
        )))
    }

    /// Route a query operation to the appropriate backend
    pub async fn route_query_operation(
        &self,
        _operation: &QueryOperation,
    ) -> DbxResult<Arc<dyn UniversalBackend>> {
        // Route queries based on operation type and complexity
        // Read-heavy operations can use read replicas if available

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
        // Get operation type for capability checking
        let operation_type = self.get_stream_operation_type(operation);

        // If operation has a specific channel/topic, use key-based routing with capability check
        let key = match operation {
            StreamOperation::Subscribe { channel, .. }
            | StreamOperation::Unsubscribe { channel, .. }
            | StreamOperation::Publish { channel, .. } => Some(channel.as_str()),
            StreamOperation::CreateStream { name, .. } => Some(name.as_str()),
            StreamOperation::StreamAdd { stream, .. }
            | StreamOperation::StreamRead { stream, .. } => Some(stream.as_str()),
        };

        if let Some(key_str) = key {
            if let Some(backend_name) = self.key_matcher.match_key(key_str) {
                debug!(key = %key_str, backend = %backend_name, "Using key-based routing for stream");

                if let Some(backend) = self.registry.get_backend(&backend_name).await {
                    // Check if backend supports stream operations
                    if self.backend_supports_stream_operation(&backend, &operation_type) {
                        return Ok(backend);
                    } else {
                        debug!(backend = %backend_name, operation = %operation_type, "Backend doesn't support stream operation, trying alternatives");
                    }
                }
            }
        }

        // Find backends that support streaming capabilities
        let stream_capable_backends = self
            .registry
            .get_backends_with_stream_capability(&operation_type)
            .await;

        if !stream_capable_backends.is_empty() {
            // Prefer the first capable backend
            if let Some(backend_name) = stream_capable_backends.first() {
                if let Some(backend) = self.registry.get_backend(backend_name).await {
                    debug!(backend = %backend_name, "Using stream-capable backend");
                    return Ok(backend);
                }
            }
        }

        // Fall back to default backend with capability check
        if let Some(default_backend) = &self.default_backend {
            debug!(backend = %default_backend, "Checking default backend for stream capabilities");

            if let Some(backend) = self.registry.get_backend(default_backend).await {
                if self.backend_supports_stream_operation(&backend, &operation_type) {
                    return Ok(backend);
                } else {
                    return Err(dbx_core::DbxError::routing(format!(
                        "Default backend '{}' doesn't support stream operation '{}'",
                        default_backend, operation_type
                    )));
                }
            }
        }

        Err(dbx_core::DbxError::routing(format!(
            "No backend available that supports stream operation '{}'",
            operation_type
        )))
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
            DataOperation::Delete { key, .. } => Some(key),
            DataOperation::Update { key, .. } => Some(key),
            DataOperation::Exists { key, .. } => Some(key),
            DataOperation::GetTtl { key } => Some(key),
            DataOperation::SetTtl { key, .. } => Some(key),
            DataOperation::Batch { operations } => {
                // Use the first operation's key for routing batch operations
                operations
                    .first()
                    .and_then(|op| self.extract_key_from_data_operation(op))
            }
        }
    }

    /// Route based on operation type with capability checking
    async fn route_by_operation_type_with_capabilities(
        &self,
        operation: &DataOperation,
    ) -> DbxResult<Option<Arc<dyn UniversalBackend>>> {
        use dbx_core::DataOperation::*;

        let operation_type = self.get_operation_type_from_data_operation(operation);

        // Find backends that support this operation type
        let capable_backends = self
            .registry
            .get_backends_with_capability(&operation_type)
            .await;

        if capable_backends.is_empty() {
            return Ok(None);
        }

        // Route based on operation characteristics
        match operation {
            Get { .. } | Exists { .. } | GetTtl { .. } => {
                // Read operations - prefer read replicas if available
                for backend_name in &capable_backends {
                    if let Some(backend) = self.registry.get_backend(backend_name).await {
                        // Check if this is a read replica (basic heuristic)
                        if backend_name.contains("read") || backend_name.contains("replica") {
                            debug!(backend = %backend_name, "Using read replica for read operation");
                            return Ok(Some(backend));
                        }
                    }
                }
                // Fall back to any capable backend
                if let Some(backend_name) = capable_backends.first() {
                    if let Some(backend) = self.registry.get_backend(backend_name).await {
                        return Ok(Some(backend));
                    }
                }
            }
            Set { .. } | Update { .. } | Delete { .. } | SetTtl { .. } => {
                // Write operations - prefer primary/master backends
                for backend_name in &capable_backends {
                    if let Some(backend) = self.registry.get_backend(backend_name).await {
                        // Check if this is a primary/master (basic heuristic)
                        if backend_name.contains("primary")
                            || backend_name.contains("master")
                            || backend_name.contains("write")
                        {
                            debug!(backend = %backend_name, "Using primary backend for write operation");
                            return Ok(Some(backend));
                        }
                    }
                }
                // Fall back to any capable backend
                if let Some(backend_name) = capable_backends.first() {
                    if let Some(backend) = self.registry.get_backend(backend_name).await {
                        return Ok(Some(backend));
                    }
                }
            }
            Batch { .. } => {
                // Batch operations - prefer backends with batch optimization
                for backend_name in &capable_backends {
                    if let Some(backend) = self.registry.get_backend(backend_name).await {
                        // Check if this backend supports efficient batching
                        if backend_name.contains("batch") || backend_name.contains("bulk") {
                            debug!(backend = %backend_name, "Using batch-optimized backend");
                            return Ok(Some(backend));
                        }
                    }
                }
                // Fall back to any capable backend
                if let Some(backend_name) = capable_backends.first() {
                    if let Some(backend) = self.registry.get_backend(backend_name).await {
                        return Ok(Some(backend));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Get operation type string from data operation
    fn get_operation_type_from_data_operation(&self, operation: &DataOperation) -> String {
        match operation {
            DataOperation::Get { .. } => "data:get".to_string(),
            DataOperation::Set { .. } => "data:set".to_string(),
            DataOperation::Update { .. } => "data:update".to_string(),
            DataOperation::Delete { .. } => "data:delete".to_string(),
            DataOperation::Exists { .. } => "data:exists".to_string(),
            DataOperation::SetTtl { .. } => "data:set_ttl".to_string(),
            DataOperation::GetTtl { .. } => "data:get_ttl".to_string(),
            DataOperation::Batch { .. } => "data:batch".to_string(),
        }
    }

    /// Check if backend supports the given operation type
    fn backend_supports_operation(
        &self,
        backend: &Arc<dyn UniversalBackend>,
        operation_type: &str,
    ) -> bool {
        let capabilities = backend.capabilities();
        capabilities.data_operations.iter().any(|op| match op {
            dbx_core::DataOperationType::Get => operation_type == "data:get",
            dbx_core::DataOperationType::Set => operation_type == "data:set",
            dbx_core::DataOperationType::Update => operation_type == "data:update",
            dbx_core::DataOperationType::Delete => operation_type == "data:delete",
            dbx_core::DataOperationType::Exists => operation_type == "data:exists",
            dbx_core::DataOperationType::GetTtl => operation_type == "data:get_ttl",
            dbx_core::DataOperationType::SetTtl => operation_type == "data:set_ttl",
            dbx_core::DataOperationType::Batch => operation_type == "data:batch",
        })
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

    /// Get stream operation type
    fn get_stream_operation_type(&self, operation: &StreamOperation) -> String {
        match operation {
            StreamOperation::Subscribe { .. } => "subscribe".to_string(),
            StreamOperation::Unsubscribe { .. } => "unsubscribe".to_string(),
            StreamOperation::Publish { .. } => "publish".to_string(),
            StreamOperation::CreateStream { .. } => "create_stream".to_string(),
            StreamOperation::StreamAdd { .. } => "stream_add".to_string(),
            StreamOperation::StreamRead { .. } => "stream_read".to_string(),
        }
    }

    /// Check if backend supports stream operations
    fn backend_supports_stream_operation(
        &self,
        backend: &Arc<dyn UniversalBackend>,
        operation_type: &str,
    ) -> bool {
        let capabilities = backend.capabilities();

        match operation_type {
            "subscribe" | "unsubscribe" | "publish" => capabilities.stream_capabilities.pub_sub,
            "create_stream" | "stream_add" | "stream_read" => {
                capabilities.stream_capabilities.streams
            }
            _ => false,
        }
    }
}

/// Legacy backend router for backwards compatibility
pub struct LegacyBackendRouter {
    registry: BackendRegistry,
    key_matcher: KeyMatcher,
    load_balancer: LoadBalancer,
    default_backend: Option<String>,
}

impl LegacyBackendRouter {
    /// Route a data operation to the appropriate backend
    pub async fn route_data_operation(
        &self,
        operation: &DataOperation,
    ) -> DbxResult<Arc<dyn UniversalBackend>> {
        // Get operation type for capability checking
        let operation_type = self.get_operation_type_from_data_operation(operation);

        // Try key-based routing first
        if let Some(key) = self.extract_key_from_data_operation(operation) {
            if let Some(backend_name) = self.key_matcher.match_key(key) {
                debug!(key = %key, backend = %backend_name, "Using key-based routing");

                if let Some(backend) = self.registry.get_backend(&backend_name).await {
                    // Check if backend supports this operation type
                    if self.backend_supports_operation(&backend, &operation_type) {
                        return Ok(backend);
                    } else {
                        debug!(backend = %backend_name, operation = %operation_type, "Backend doesn't support operation, trying alternatives");
                    }
                }
            }
        }

        // Fallback to load balancer
        let key = self.extract_key_from_data_operation(operation);
        let backend_name = self
            .load_balancer
            .select_backend_with_key(key.as_deref())
            .await?;

        match backend_name {
            Some(name) => {
                if let Some(backend) = self.registry.get_backend(&name).await {
                    Ok(backend)
                } else {
                    Err(crate::RouterError::BackendNotFound { backend: name }.into())
                }
            }
            None => Err(crate::RouterError::NoHealthyBackends.into()),
        }
    }

    /// Extract key from data operation for routing
    fn extract_key_from_data_operation<'a>(&self, operation: &'a DataOperation) -> Option<&'a str> {
        match operation {
            DataOperation::Get { key, .. } => Some(key),
            DataOperation::Set { key, .. } => Some(key),
            DataOperation::Delete { key, .. } => Some(key),
            DataOperation::Update { key, .. } => Some(key),
            DataOperation::Exists { key, .. } => Some(key),
            DataOperation::GetTtl { key } => Some(key),
            DataOperation::SetTtl { key, .. } => Some(key),
            DataOperation::Batch { operations } => {
                // Use the first operation's key for routing batch operations
                operations
                    .first()
                    .and_then(|op| self.extract_key_from_data_operation(op))
            }
        }
    }

    /// Get operation type from data operation
    fn get_operation_type_from_data_operation(&self, operation: &DataOperation) -> String {
        match operation {
            DataOperation::Get { .. } => "data:get".to_string(),
            DataOperation::Set { .. } => "data:set".to_string(),
            DataOperation::Update { .. } => "data:update".to_string(),
            DataOperation::Delete { .. } => "data:delete".to_string(),
            DataOperation::Exists { .. } => "data:exists".to_string(),
            DataOperation::GetTtl { .. } => "data:get_ttl".to_string(),
            DataOperation::SetTtl { .. } => "data:set_ttl".to_string(),
            DataOperation::Batch { .. } => "data:batch".to_string(),
        }
    }

    /// Check if backend supports operation
    fn backend_supports_operation(
        &self,
        backend: &Arc<dyn UniversalBackend>,
        operation_type: &str,
    ) -> bool {
        let capabilities = backend.capabilities();
        capabilities.data_operations.iter().any(|op| match op {
            dbx_core::DataOperationType::Get => operation_type == "data:get",
            dbx_core::DataOperationType::Set => operation_type == "data:set",
            dbx_core::DataOperationType::Update => operation_type == "data:update",
            dbx_core::DataOperationType::Delete => operation_type == "data:delete",
            dbx_core::DataOperationType::Exists => operation_type == "data:exists",
            dbx_core::DataOperationType::GetTtl => operation_type == "data:get_ttl",
            dbx_core::DataOperationType::SetTtl => operation_type == "data:set_ttl",
            dbx_core::DataOperationType::Batch => operation_type == "data:batch",
        })
    }

    /// Get statistics about the router
    pub async fn get_stats(&self) -> LegacyRouterStats {
        LegacyRouterStats {
            matcher_stats: self.key_matcher.get_stats(),
            load_balancer_stats: self.load_balancer.get_stats().await,
            registry_backend_stats: self.registry.get_all_stats().await,
        }
    }
}

/// Router benchmark results
#[derive(Debug, Clone)]
pub struct RouterBenchmarkResult {
    pub total_operations: usize,
    pub successful_routes: usize,
    pub total_duration: std::time::Duration,
    pub avg_duration_nanos: u64,
    pub operations_per_second: u64,
}

/// Router statistics
#[derive(Debug, Clone)]
pub struct RouterStats {
    pub matcher_stats: OptimizedMatcherStats,
    pub load_balancer_stats: LoadBalancerStats,
    pub registry_stats: crate::registry::RegistryStats,
}

/// Legacy router statistics
#[derive(Debug, Clone)]
pub struct LegacyRouterStats {
    pub matcher_stats: MatcherStats,
    pub load_balancer_stats: LoadBalancerStats,
    pub registry_backend_stats:
        std::collections::HashMap<String, Result<dbx_core::BackendStats, dbx_core::DbxError>>,
}

/// Routing statistics
#[derive(Debug, Clone)]
pub struct RoutingStats {
    pub total_backends: usize,
    pub load_balancer_stats: LoadBalancerStats,
    pub key_matcher_stats: MatcherStats,
}
