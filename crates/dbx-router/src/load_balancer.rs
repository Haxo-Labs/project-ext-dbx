use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, warn};

use dbx_config::LoadBalancingConfig;
use dbx_core::{DbxResult, LoadBalancingStrategy};

use crate::RouterError;

/// Load balancer for distributing requests across backends
pub struct LoadBalancer {
    strategy: LoadBalancingStrategy,
    backend_list: Arc<RwLock<Vec<String>>>,
    current_index: Arc<AtomicUsize>,
    backend_connections: Arc<DashMap<String, usize>>,
    backend_weights: Arc<DashMap<String, f64>>,
    healthy_backends: Arc<RwLock<std::collections::HashSet<String>>>,
    health_tracker: HealthTracker,
}

impl LoadBalancer {
    /// Create a new load balancer
    pub fn new(config: LoadBalancingConfig) -> DbxResult<Self> {
        let backend_list = Arc::new(RwLock::new(config.backends.clone()));
        let backend_connections = Arc::new(DashMap::new());
        let backend_weights = Arc::new(DashMap::new());
        let healthy_backends = Arc::new(RwLock::new(std::collections::HashSet::new()));

        // Initialize backend connections and weights
        for backend in &config.backends {
            backend_connections.insert(backend.clone(), 0);
            backend_weights.insert(backend.clone(), 1.0); // Default weight as f64
        }

        // Initialize weights from config
        if let Some(weights) = &config.weights {
            for (backend, weight) in weights {
                backend_weights.insert(backend.clone(), *weight);
            }
        }

        let health_tracker = HealthTracker::new();

        Ok(Self {
            strategy: config.strategy,
            backend_list,
            current_index: Arc::new(AtomicUsize::new(0)),
            backend_connections,
            backend_weights,
            healthy_backends,
            health_tracker,
        })
    }

    /// Select a backend based on the configured strategy
    pub async fn select_backend(&self) -> DbxResult<Option<String>> {
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
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                let mut hasher = DefaultHasher::new();
                std::thread::current().id().hash(&mut hasher);
                let index = (hasher.finish() as usize) % healthy_list.len();
                Ok(Some(healthy_list[index].clone()))
            }
            LoadBalancingStrategy::LeastConnections => {
                let mut min_connections = usize::MAX;
                let mut selected_backend = None;

                for backend in &healthy_list {
                    if let Some(connections) = self.backend_connections.get(backend) {
                        if *connections < min_connections {
                            min_connections = *connections;
                            selected_backend = Some(backend.clone());
                        }
                    }
                }

                Ok(selected_backend)
            }
            LoadBalancingStrategy::WeightedRoundRobin => {
                // Simple weighted implementation - can be improved
                let mut total_weight = 0.0;
                for backend in &healthy_list {
                    if let Some(weight) = self.backend_weights.get(backend) {
                        total_weight += *weight;
                    }
                }

                if total_weight == 0.0 {
                    return Ok(healthy_list.first().cloned());
                }

                let target =
                    (self.current_index.fetch_add(1, Ordering::Relaxed) as f64) % total_weight;
                let mut current_weight = 0.0;

                for backend in &healthy_list {
                    if let Some(weight) = self.backend_weights.get(backend) {
                        current_weight += *weight;
                        if target < current_weight {
                            return Ok(Some(backend.clone()));
                        }
                    }
                }

                Ok(healthy_list.first().cloned())
            }
            LoadBalancingStrategy::ConsistentHash => {
                // Simple hash-based selection for now
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                let mut hasher = DefaultHasher::new();
                std::thread::current().id().hash(&mut hasher);
                let index = (hasher.finish() as usize) % healthy_list.len();
                Ok(Some(healthy_list[index].clone()))
            }
        }
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
        self.healthy_backends
            .write()
            .await
            .insert(backend_name.clone());
        self.health_tracker.add_backend(backend_name.clone()).await;
        debug!(backend = %backend_name, "Added backend to load balancer");
    }

    /// Remove a backend from the load balancer
    pub async fn remove_backend(&self, backend_name: &str) {
        let mut backend_list = self.backend_list.write().await;
        backend_list.retain(|b| b != backend_name);
        drop(backend_list);

        self.backend_connections.remove(backend_name);
        self.backend_weights.remove(backend_name);
        self.healthy_backends.write().await.remove(backend_name);
        self.health_tracker.remove_backend(backend_name).await;
        debug!(backend = %backend_name, "Removed backend from load balancer");
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
