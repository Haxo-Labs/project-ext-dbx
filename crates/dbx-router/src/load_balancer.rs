use dashmap::DashMap;
use sha2::{Digest, Sha256};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, warn};

use dbx_config::LoadBalancingConfig;
use dbx_core::{DbxResult, LoadBalancingStrategy};

use crate::RouterError;

#[derive(Debug, Clone, PartialEq, Eq)]
struct BackendConnection {
    backend_name: String,
    connection_count: usize,
}

impl Ord for BackendConnection {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // For min-heap: lower connection count has higher priority
        other
            .connection_count
            .cmp(&self.connection_count)
            .then_with(|| self.backend_name.cmp(&other.backend_name))
    }
}

impl PartialOrd for BackendConnection {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone)]
struct BackendWeight {
    weight: i32,
    current_weight: i32,
    effective_weight: i32,
}

impl BackendWeight {
    fn new(weight: f64) -> Self {
        let weight_int = (weight * 100.0) as i32;
        Self {
            weight: weight_int,
            current_weight: 0,
            effective_weight: weight_int,
        }
    }
}

#[derive(Debug, Clone)]
struct ConsistentHashRing {
    ring: BTreeMap<u64, String>,
    virtual_nodes: u32,
}

impl ConsistentHashRing {
    fn new(backends: Vec<String>, virtual_nodes: u32) -> Self {
        let mut ring = BTreeMap::new();

        for backend in backends {
            for i in 0..virtual_nodes {
                let virtual_key = format!("{}:{}", backend, i);
                if let Ok(hash) = Self::hash_key(&virtual_key) {
                    ring.insert(hash, backend.clone());
                }
            }
        }

        Self {
            ring,
            virtual_nodes,
        }
    }

    fn get_backend(&self, key: &str) -> Option<&String> {
        if self.ring.is_empty() {
            return None;
        }

        let hash = match Self::hash_key(key) {
            Ok(h) => h,
            Err(_) => return None,
        };

        // Find the first backend with hash >= key hash, or wrap to the first backend
        self.ring
            .range(hash..)
            .next()
            .or_else(|| self.ring.iter().next())
            .map(|(_, backend)| backend)
    }

    fn hash_key(key: &str) -> Result<u64, RouterError> {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        let result = hasher.finalize();
        result[..8].try_into().map(u64::from_be_bytes).map_err(|e| {
            RouterError::LoadBalancingError {
                message: format!("Hash generation failed for key '{}': {}", key, e),
            }
        })
    }

    fn add_backend(&mut self, backend: String) {
        for i in 0..self.virtual_nodes {
            let virtual_key = format!("{}:{}", backend, i);
            if let Ok(hash) = Self::hash_key(&virtual_key) {
                self.ring.insert(hash, backend.clone());
            }
        }
    }

    fn remove_backend(&mut self, backend: &str) {
        let mut keys_to_remove = Vec::new();
        for (hash, ring_backend) in &self.ring {
            if ring_backend == backend {
                keys_to_remove.push(*hash);
            }
        }
        for key in keys_to_remove {
            self.ring.remove(&key);
        }
    }
}

/// Load balancer for distributing requests across backends
pub struct LoadBalancer {
    strategy: LoadBalancingStrategy,
    backend_list: Arc<RwLock<Vec<String>>>,
    current_index: Arc<AtomicUsize>,
    backend_connections: Arc<DashMap<String, usize>>,
    backend_weights: Arc<DashMap<String, f64>>,
    swrr_weights: Arc<RwLock<HashMap<String, BackendWeight>>>,
    consistent_hash_ring: Arc<RwLock<ConsistentHashRing>>,
    least_connections_heap: Arc<RwLock<BinaryHeap<BackendConnection>>>,
    heap_rebuild_counter: Arc<AtomicUsize>,
    healthy_backends: Arc<RwLock<std::collections::HashSet<String>>>,
    health_tracker: HealthTracker,
}

impl LoadBalancer {
    /// Create a new load balancer
    pub fn new(config: LoadBalancingConfig) -> DbxResult<Self> {
        let backend_list = Arc::new(RwLock::new(config.backends.clone()));
        let backend_connections = Arc::new(DashMap::new());
        let backend_weights = Arc::new(DashMap::new());
        let mut swrr_weights = HashMap::new();
        let consistent_hash_ring = Arc::new(RwLock::new(ConsistentHashRing::new(
            config.backends.clone(),
            100,
        )));
        let mut least_connections_heap = BinaryHeap::new();
        let healthy_backends = Arc::new(RwLock::new(std::collections::HashSet::new()));

        // Initialize backend connections and weights
        for backend in &config.backends {
            backend_connections.insert(backend.clone(), 0);
            backend_weights.insert(backend.clone(), 1.0);
            swrr_weights.insert(backend.clone(), BackendWeight::new(1.0));
            least_connections_heap.push(BackendConnection {
                backend_name: backend.clone(),
                connection_count: 0,
            });
        }

        // Initialize weights from config
        if let Some(weights) = &config.weights {
            for (backend, weight) in weights {
                backend_weights.insert(backend.clone(), *weight);
                swrr_weights.insert(backend.clone(), BackendWeight::new(*weight));
            }
        }

        let health_tracker = HealthTracker::new();

        Ok(Self {
            strategy: config.strategy,
            backend_list,
            current_index: Arc::new(AtomicUsize::new(0)),
            backend_connections,
            backend_weights,
            swrr_weights: Arc::new(RwLock::new(swrr_weights)),
            consistent_hash_ring,
            least_connections_heap: Arc::new(RwLock::new(least_connections_heap)),
            heap_rebuild_counter: Arc::new(AtomicUsize::new(0)),
            healthy_backends,
            health_tracker,
        })
    }

    /// Select a backend based on the configured strategy
    pub async fn select_backend(&self) -> DbxResult<Option<String>> {
        self.select_backend_with_key(None).await
    }

    /// Select a backend based on the configured strategy with optional key for consistent hashing
    pub async fn select_backend_with_key(&self, key: Option<&str>) -> DbxResult<Option<String>> {
        let healthy_backends = self.healthy_backends.read().await;
        if healthy_backends.is_empty() {
            warn!("No healthy backends available");
            return Ok(None);
        }

        let healthy_list: Vec<String> = healthy_backends.iter().cloned().collect();
        drop(healthy_backends);

        if healthy_list.is_empty() {
            return Ok(None);
        }

        match self.strategy {
            LoadBalancingStrategy::RoundRobin => {
                let index = self.current_index.fetch_add(1, Ordering::Relaxed) % healthy_list.len();
                Ok(Some(healthy_list[index].clone()))
            }
            LoadBalancingStrategy::Random => {
                use ring::rand::{SecureRandom, SystemRandom};
                let rng = SystemRandom::new();
                let mut random_bytes = [0u8; 4];
                rng.fill(&mut random_bytes).map_err(|_| {
                    dbx_core::DbxError::routing("Failed to generate random number".to_string())
                })?;
                let random_value = u32::from_be_bytes(random_bytes);
                let index = (random_value as usize) % healthy_list.len();
                Ok(Some(healthy_list[index].clone()))
            }
            LoadBalancingStrategy::LeastConnections => {
                self.select_backend_least_connections(&healthy_list).await
            }
            LoadBalancingStrategy::WeightedRoundRobin => {
                self.select_backend_swrr(&healthy_list).await
            }
            LoadBalancingStrategy::ConsistentHash => {
                self.select_backend_consistent_hash(key, &healthy_list)
                    .await
            }
        }
    }

    async fn select_backend_consistent_hash(
        &self,
        key: Option<&str>,
        healthy_list: &[String],
    ) -> DbxResult<Option<String>> {
        let key = key.unwrap_or("default_key");
        let ring = self.consistent_hash_ring.read().await;

        if let Some(backend) = ring.get_backend(key) {
            // Check if the selected backend is healthy
            if healthy_list.contains(backend) {
                Ok(Some(backend.clone()))
            } else {
                // Find the next healthy backend in the ring by traversing forward
                if let Ok(start_hash) = ConsistentHashRing::hash_key(key) {
                    // Find all backends in ring order starting from the hash position
                    let mut candidates: Vec<_> = ring
                        .ring
                        .range(start_hash..)
                        .chain(ring.ring.range(..start_hash))
                        .collect();

                    // Remove the unhealthy backend we already tried
                    candidates.retain(|(_, candidate_backend)| *candidate_backend != backend);

                    // Find the first healthy backend in ring order
                    for (_, candidate_backend) in candidates {
                        if healthy_list.contains(candidate_backend) {
                            return Ok(Some(candidate_backend.clone()));
                        }
                    }
                }

                // If no healthy backend found in ring traversal, use any healthy backend
                Ok(healthy_list.first().cloned())
            }
        } else {
            Ok(healthy_list.first().cloned())
        }
    }

    async fn select_backend_swrr(&self, healthy_list: &[String]) -> DbxResult<Option<String>> {
        let mut swrr_weights = self.swrr_weights.write().await;

        let mut best_backend = None;
        let mut best_current_weight = i32::MIN;
        let mut total_weight = 0;

        // Update current weights and find the best backend
        for backend in healthy_list {
            if let Some(backend_weight) = swrr_weights.get_mut(backend) {
                backend_weight.current_weight += backend_weight.effective_weight;
                total_weight += backend_weight.effective_weight;

                if backend_weight.current_weight > best_current_weight {
                    best_current_weight = backend_weight.current_weight;
                    best_backend = Some(backend.clone());
                }
            }
        }

        // Reduce the current weight of the selected backend by the total weight
        if let Some(ref selected_backend) = best_backend {
            if let Some(backend_weight) = swrr_weights.get_mut(selected_backend) {
                backend_weight.current_weight -= total_weight;
            }
        }

        Ok(best_backend)
    }

    async fn select_backend_least_connections(
        &self,
        healthy_list: &[String],
    ) -> DbxResult<Option<String>> {
        if healthy_list.is_empty() {
            return Ok(None);
        }

        // Direct linear scan approach for reliable production operation
        let mut min_connections = usize::MAX;
        let mut selected_backend = None;

        for backend in healthy_list {
            let connections = self
                .backend_connections
                .get(backend)
                .map(|v| *v)
                .unwrap_or(0);

            if connections < min_connections {
                min_connections = connections;
                selected_backend = Some(backend.clone());
            }
        }

        // Increment connection count for selected backend
        if let Some(ref backend) = selected_backend {
            self.backend_connections
                .entry(backend.clone())
                .and_modify(|count| *count += 1)
                .or_insert(1);
        }

        Ok(selected_backend)
    }

    /// Increment connection count for a backend
    pub async fn increment_connections(&self, backend: &str) {
        if let Some(mut entry) = self.backend_connections.get_mut(backend) {
            *entry += 1;
        }
    }

    /// Decrement connection count for a backend
    pub async fn decrement_connections(&self, backend: &str) {
        if let Some(mut entry) = self.backend_connections.get_mut(backend) {
            if *entry > 0 {
                *entry -= 1;
            }
        }
    }

    /// Update the health status of a backend
    pub async fn update_backend_health(&self, backend: &str, is_healthy: bool) {
        if is_healthy {
            self.healthy_backends
                .write()
                .await
                .insert(backend.to_string());
        } else {
            self.healthy_backends.write().await.remove(backend);
        }
        debug!(backend = %backend, healthy = is_healthy, "Updated backend health status");
    }

    /// Add a backend to the load balancer
    pub async fn add_backend(&self, backend_name: String) {
        self.backend_list.write().await.push(backend_name.clone());
        self.backend_connections.insert(backend_name.clone(), 0);
        self.backend_weights.insert(backend_name.clone(), 1.0);
        self.swrr_weights
            .write()
            .await
            .insert(backend_name.clone(), BackendWeight::new(1.0));
        self.consistent_hash_ring
            .write()
            .await
            .add_backend(backend_name.clone());
        self.least_connections_heap
            .write()
            .await
            .push(BackendConnection {
                backend_name: backend_name.clone(),
                connection_count: 0,
            });
        self.healthy_backends
            .write()
            .await
            .insert(backend_name.clone());
        self.health_tracker.add_backend(backend_name.clone()).await;
        debug!(backend = %backend_name, "Added backend to load balancer");
    }

    /// Remove a backend from the load balancer
    pub async fn remove_backend(&self, backend_name: &str) {
        self.backend_connections.remove(backend_name);
        self.backend_weights.remove(backend_name);
        self.swrr_weights.write().await.remove(backend_name);
        self.consistent_hash_ring
            .write()
            .await
            .remove_backend(backend_name);

        let healthy_backends = self.healthy_backends.read().await;
        let healthy_list: Vec<String> = healthy_backends.iter().cloned().collect();
        drop(healthy_backends);

        self.healthy_backends.write().await.remove(backend_name);
        self.health_tracker.remove_backend(backend_name).await;
    }

    /// Get load balancer statistics
    pub async fn get_stats(&self) -> LoadBalancerStats {
        let backend_list = self.backend_list.read().await;
        let healthy_backends = self.healthy_backends.read().await;
        let connections: HashMap<String, usize> = self
            .backend_connections
            .iter()
            .map(|entry| (entry.key().clone(), *entry.value()))
            .collect();

        LoadBalancerStats {
            total_backends: backend_list.len(),
            healthy_backends: healthy_backends.len(),
            current_index: self.current_index.load(Ordering::Relaxed),
            strategy: self.strategy.clone(),
            backend_connections: connections,
        }
    }
}

/// Statistics for load balancer performance monitoring
#[derive(Debug, Clone)]
pub struct LoadBalancerStats {
    pub total_backends: usize,
    pub healthy_backends: usize,
    pub current_index: usize,
    pub strategy: LoadBalancingStrategy,
    pub backend_connections: HashMap<String, usize>,
}

/// Health tracker for monitoring backend health
struct HealthTracker {
    backend_health: Arc<DashMap<String, BackendHealthStatus>>,
}

impl HealthTracker {
    fn new() -> Self {
        Self {
            backend_health: Arc::new(DashMap::new()),
        }
    }

    async fn add_backend(&self, backend_name: String) {
        self.backend_health.insert(
            backend_name,
            BackendHealthStatus {
                is_healthy: true,
                last_check: std::time::Instant::now(),
                consecutive_failures: 0,
            },
        );
    }

    async fn remove_backend(&self, backend_name: &str) {
        self.backend_health.remove(backend_name);
    }

    async fn update_health(&self, backend_name: &str, is_healthy: bool) {
        if let Some(mut entry) = self.backend_health.get_mut(backend_name) {
            entry.is_healthy = is_healthy;
            entry.last_check = std::time::Instant::now();
            if is_healthy {
                entry.consecutive_failures = 0;
            } else {
                entry.consecutive_failures += 1;
            }
        }
    }

    async fn get_stats(&self) -> HealthTrackerStats {
        let total_backends = self.backend_health.len();
        let healthy_backends = self
            .backend_health
            .iter()
            .filter(|entry| entry.value().is_healthy)
            .count();

        HealthTrackerStats {
            total_backends,
            healthy_backends,
        }
    }
}

/// Backend health status
#[derive(Debug, Clone)]
struct BackendHealthStatus {
    is_healthy: bool,
    last_check: std::time::Instant,
    consecutive_failures: usize,
}

/// Health tracker statistics
#[derive(Debug, Clone)]
struct HealthTrackerStats {
    total_backends: usize,
    healthy_backends: usize,
}
