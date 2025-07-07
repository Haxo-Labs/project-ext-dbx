use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, warn};

use dbx_config::LoadBalancingConfig;
use dbx_core::{DbxResult, LoadBalancingStrategy};

use crate::RouterError;

/// Load balancer for distributing operations across multiple backends
pub struct LoadBalancer {
    strategy: LoadBalancingStrategy,
    backends: Vec<String>,
    weights: Option<HashMap<String, f64>>,
    health_tracker: Arc<HealthTracker>,
    round_robin_counter: AtomicUsize,
}

impl LoadBalancer {
    /// Create a new load balancer
    pub fn new(config: LoadBalancingConfig) -> DbxResult<Self> {
        let health_tracker = Arc::new(HealthTracker::new(config.backends.clone()));

        Ok(Self {
            strategy: config.strategy,
            backends: config.backends,
            weights: config.weights,
            health_tracker,
            round_robin_counter: AtomicUsize::new(0),
        })
    }

    /// Select a backend based on the load balancing strategy
    pub async fn select_backend(&self) -> DbxResult<Option<String>> {
        let healthy_backends = self.health_tracker.get_healthy_backends().await;

        if healthy_backends.is_empty() {
            warn!("No healthy backends available for load balancing");
            return Ok(None);
        }

        let selected = match self.strategy {
            LoadBalancingStrategy::RoundRobin => self.select_round_robin(&healthy_backends),
            LoadBalancingStrategy::Random => self.select_random(&healthy_backends),
            LoadBalancingStrategy::LeastConnections => {
                self.select_least_connections(&healthy_backends).await
            }
            LoadBalancingStrategy::WeightedRoundRobin => {
                self.select_weighted_round_robin(&healthy_backends)?
            }
            LoadBalancingStrategy::ConsistentHash => {
                // For consistent hash, we need a key, so fall back to round robin
                // In practice, this would be called with a key parameter
                self.select_round_robin(&healthy_backends)
            }
        };

        if let Some(ref backend) = selected {
            debug!(backend = %backend, strategy = ?self.strategy, "Selected backend");
        }

        Ok(selected)
    }

    /// Select a backend using consistent hashing with a key
    pub async fn select_backend_with_key(&self, key: &str) -> DbxResult<Option<String>> {
        let healthy_backends = self.health_tracker.get_healthy_backends().await;

        if healthy_backends.is_empty() {
            warn!("No healthy backends available for load balancing");
            return Ok(None);
        }

        let selected = match self.strategy {
            LoadBalancingStrategy::ConsistentHash => {
                self.select_consistent_hash(&healthy_backends, key)
            }
            _ => {
                // For other strategies, ignore the key
                return self.select_backend().await;
            }
        };

        if let Some(ref backend) = selected {
            debug!(backend = %backend, key = %key, strategy = ?self.strategy, "Selected backend with key");
        }

        Ok(selected)
    }

    /// Round robin selection
    fn select_round_robin(&self, backends: &[String]) -> Option<String> {
        if backends.is_empty() {
            return None;
        }

        let index = self.round_robin_counter.fetch_add(1, Ordering::Relaxed) % backends.len();
        Some(backends[index].clone())
    }

    /// Random selection
    fn select_random(&self, backends: &[String]) -> Option<String> {
        if backends.is_empty() {
            return None;
        }

        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        use std::time::{SystemTime, UNIX_EPOCH};

        // Simple random number generation
        let mut hasher = DefaultHasher::new();
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            .hash(&mut hasher);
        let hash = hasher.finish();

        let index = (hash as usize) % backends.len();
        Some(backends[index].clone())
    }

    /// Least connections selection
    async fn select_least_connections(&self, backends: &[String]) -> Option<String> {
        let mut min_connections = usize::MAX;
        let mut selected_backend = None;

        for backend in backends {
            let connections = self.health_tracker.get_connection_count(backend).await;
            if connections < min_connections {
                min_connections = connections;
                selected_backend = Some(backend.clone());
            }
        }

        selected_backend
    }

    /// Weighted round robin selection
    fn select_weighted_round_robin(&self, backends: &[String]) -> DbxResult<Option<String>> {
        let weights = self
            .weights
            .as_ref()
            .ok_or_else(|| RouterError::LoadBalancingError {
                message: "Weighted round robin requires weights configuration".to_string(),
            })?;

        if backends.is_empty() {
            return Ok(None);
        }

        // Calculate total weight for healthy backends
        let total_weight: f64 = backends.iter().filter_map(|b| weights.get(b)).sum();

        if total_weight <= 0.0 {
            return Ok(None);
        }

        // Generate a random value between 0 and total_weight
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        use std::time::{SystemTime, UNIX_EPOCH};

        let mut hasher = DefaultHasher::new();
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            .hash(&mut hasher);
        let hash = hasher.finish();
        let random_value = (hash as f64 / u64::MAX as f64) * total_weight;

        // Find the backend corresponding to this weight
        let mut cumulative_weight = 0.0;
        for backend in backends {
            if let Some(weight) = weights.get(backend) {
                cumulative_weight += weight;
                if random_value <= cumulative_weight {
                    return Ok(Some(backend.clone()));
                }
            }
        }

        // Fallback to first backend
        Ok(backends.first().cloned())
    }

    /// Consistent hash selection
    fn select_consistent_hash(&self, backends: &[String], key: &str) -> Option<String> {
        if backends.is_empty() {
            return None;
        }

        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let hash = hasher.finish();

        let index = (hash as usize) % backends.len();
        Some(backends[index].clone())
    }

    /// Mark a backend as healthy
    pub async fn mark_healthy(&self, backend: &str) {
        self.health_tracker.mark_healthy(backend).await;
    }

    /// Mark a backend as unhealthy
    pub async fn mark_unhealthy(&self, backend: &str) {
        self.health_tracker.mark_unhealthy(backend).await;
    }

    /// Record a new connection for a backend
    pub async fn record_connection(&self, backend: &str) {
        self.health_tracker.increment_connections(backend).await;
    }

    /// Record a closed connection for a backend
    pub async fn record_disconnection(&self, backend: &str) {
        self.health_tracker.decrement_connections(backend).await;
    }

    /// Update the health status of a backend
    pub async fn update_backend_health(&self, backend: &str, is_healthy: bool) {
        if is_healthy {
            self.health_tracker.mark_healthy(backend).await;
        } else {
            self.health_tracker.mark_unhealthy(backend).await;
        }
        debug!(backend = %backend, healthy = is_healthy, "Updated backend health status");
    }

    /// Add a backend to the load balancer
    pub async fn add_backend(&self, backend_name: String) {
        self.health_tracker.add_backend(backend_name).await;
        debug!(backend = %backend_name, "Added backend to load balancer");
    }

    /// Remove a backend from the load balancer
    pub async fn remove_backend(&self, backend_name: &str) {
        self.health_tracker.remove_backend(backend_name).await;
        debug!(backend = %backend_name, "Removed backend from load balancer");
    }

    /// Get load balancer statistics
    pub async fn get_stats(&self) -> LoadBalancerStats {
        let health_stats = self.health_tracker.get_stats().await;

        LoadBalancerStats {
            strategy: self.strategy.clone(),
            total_backends: self.backends.len(),
            healthy_backends: health_stats.healthy_backends.len(),
            unhealthy_backends: health_stats.unhealthy_backends.len(),
            total_connections: health_stats.total_connections,
            backend_connections: health_stats.backend_connections,
            current_index: self.round_robin_counter.load(Ordering::Relaxed),
        }
    }
}

/// Health tracker for monitoring backend health and connections
struct HealthTracker {
    backends: Vec<String>,
    healthy_backends: Arc<RwLock<Vec<String>>>,
    backend_connections: Arc<DashMap<String, usize>>,
}

impl HealthTracker {
    fn new(backends: Vec<String>) -> Self {
        let healthy_backends = Arc::new(RwLock::new(backends.clone()));
        let backend_connections = Arc::new(DashMap::new());

        // Initialize connection counts
        for backend in &backends {
            backend_connections.insert(backend.clone(), 0);
        }

        Self {
            backends,
            healthy_backends,
            backend_connections,
        }
    }

    async fn get_healthy_backends(&self) -> Vec<String> {
        self.healthy_backends.read().await.clone()
    }

    async fn mark_healthy(&self, backend: &str) {
        let mut healthy = self.healthy_backends.write().await;
        if !healthy.contains(&backend.to_string()) {
            healthy.push(backend.to_string());
            debug!(backend = %backend, "Marked backend as healthy");
        }
    }

    async fn mark_unhealthy(&self, backend: &str) {
        let mut healthy = self.healthy_backends.write().await;
        healthy.retain(|b| b != backend);
        warn!(backend = %backend, "Marked backend as unhealthy");
    }

    async fn get_connection_count(&self, backend: &str) -> usize {
        self.backend_connections
            .get(backend)
            .map(|count| *count)
            .unwrap_or(0)
    }

    async fn increment_connections(&self, backend: &str) {
        self.backend_connections
            .entry(backend.to_string())
            .and_modify(|count| *count += 1)
            .or_insert(1);
    }

    async fn decrement_connections(&self, backend: &str) {
        self.backend_connections
            .entry(backend.to_string())
            .and_modify(|count| *count = count.saturating_sub(1));
    }

    async fn get_stats(&self) -> HealthStats {
        let healthy_backends = self.get_healthy_backends().await;
        let unhealthy_backends: Vec<String> = self
            .backends
            .iter()
            .filter(|b| !healthy_backends.contains(b))
            .cloned()
            .collect();

        let backend_connections: HashMap<String, usize> = self
            .backend_connections
            .iter()
            .map(|entry| (entry.key().clone(), *entry.value()))
            .collect();

        let total_connections = backend_connections.values().sum();

        HealthStats {
            healthy_backends,
            unhealthy_backends,
            total_connections,
            backend_connections,
        }
    }

    async fn add_backend(&self, backend_name: String) {
        let mut healthy = self.healthy_backends.write().await;
        if !healthy.contains(&backend_name) {
            healthy.push(backend_name.clone());
            debug!(backend = %backend_name, "Marked backend as healthy");
        }
        self.backend_connections
            .write()
            .await
            .insert(backend_name.clone(), 0);
    }

    async fn remove_backend(&self, backend_name: &str) {
        let mut healthy = self.healthy_backends.write().await;
        healthy.retain(|b| b != backend_name);
        drop(healthy);

        self.backend_connections.write().await.remove(backend_name);
    }
}

/// Load balancer statistics
#[derive(Debug, Clone)]
pub struct LoadBalancerStats {
    pub total_backends: usize,
    pub healthy_backends: usize,
    pub current_index: usize,
    pub strategy: LoadBalancingStrategy,
    pub backend_connections: HashMap<String, usize>,
}

/// Health statistics
#[derive(Debug, Clone)]
struct HealthStats {
    pub healthy_backends: Vec<String>,
    pub unhealthy_backends: Vec<String>,
    pub total_connections: usize,
    pub backend_connections: HashMap<String, usize>,
}
