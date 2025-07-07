use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error};

use dbx_core::{BackendHealth, BackendStats, HealthStatus};
use dbx_router::BackendRouter;

use crate::models::ApiResponse;

/// Universal health check response
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub backends: HashMap<String, BackendHealthInfo>,
    pub overall_healthy: bool,
    pub timestamp: u64,
    pub version: String,
}

/// Backend health information
#[derive(Debug, Serialize, Deserialize)]
pub struct BackendHealthInfo {
    pub status: String,
    pub last_check: Option<u64>,
    pub response_time_ms: Option<u64>,
    pub error_message: Option<String>,
    pub capabilities: Vec<String>,
}

/// Universal stats response
#[derive(Debug, Serialize, Deserialize)]
pub struct StatsResponse {
    pub backends: HashMap<String, BackendStatsInfo>,
    pub routing_stats: RoutingStatsInfo,
    pub timestamp: u64,
}

/// Backend statistics information
#[derive(Debug, Serialize, Deserialize)]
pub struct BackendStatsInfo {
    pub connections: ConnectionStatsInfo,
    pub operations: OperationStatsInfo,
    pub performance: PerformanceStatsInfo,
    pub storage: Option<StorageStatsInfo>,
}

/// Connection statistics
#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectionStatsInfo {
    pub active: u32,
    pub total: u64,
    pub errors: u64,
    pub pool_size: Option<u32>,
}

/// Operation statistics
#[derive(Debug, Serialize, Deserialize)]
pub struct OperationStatsInfo {
    pub total_operations: u64,
    pub data_operations: u64,
    pub query_operations: u64,
    pub stream_operations: u64,
    pub failed_operations: u64,
    pub average_latency_ms: f64,
}

/// Performance statistics
#[derive(Debug, Serialize, Deserialize)]
pub struct PerformanceStatsInfo {
    pub cpu_usage_percent: Option<f64>,
    pub memory_usage_bytes: Option<u64>,
    pub disk_usage_bytes: Option<u64>,
    pub network_io_bytes: Option<u64>,
}

/// Storage statistics
#[derive(Debug, Serialize, Deserialize)]
pub struct StorageStatsInfo {
    pub total_size_bytes: u64,
    pub used_size_bytes: u64,
    pub free_size_bytes: u64,
    pub key_count: u64,
}

/// Routing statistics information
#[derive(Debug, Serialize, Deserialize)]
pub struct RoutingStatsInfo {
    pub total_backends: usize,
    pub healthy_backends: usize,
    pub load_balancer_stats: LoadBalancerStatsInfo,
    pub key_matcher_stats: KeyMatcherStatsInfo,
}

/// Load balancer statistics
#[derive(Debug, Serialize, Deserialize)]
pub struct LoadBalancerStatsInfo {
    pub strategy: String,
    pub total_requests: u64,
    pub backend_distribution: HashMap<String, u64>,
    pub average_response_time_ms: f64,
}

/// Key matcher statistics
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyMatcherStatsInfo {
    pub total_patterns: usize,
    pub total_matches: u64,
    pub pattern_hit_rate: f64,
}

// =========================
// Universal Health Handlers
// =========================

/// GET /api/v1/health - Overall system health
pub async fn system_health(
    State(router): State<Arc<BackendRouter>>,
) -> Result<Json<ApiResponse<HealthResponse>>, StatusCode> {
    debug!("Universal HEALTH check");

    let health_results = router.health_check_all().await;
    let mut backends = HashMap::new();
    let mut overall_healthy = true;

    for (backend_name, health_result) in health_results {
        let backend_info = match health_result {
            Ok(health) => {
                let status_str = match health.status {
                    HealthStatus::Healthy => "healthy",
                    HealthStatus::Degraded => "degraded",
                    HealthStatus::Unhealthy => "unhealthy",
                };

                if health.status != HealthStatus::Healthy {
                    overall_healthy = false;
                }

                BackendHealthInfo {
                    status: status_str.to_string(),
                    last_check: health.last_check,
                    response_time_ms: health.response_time_ms,
                    error_message: health.error_message,
                    capabilities: health
                        .capabilities
                        .map(|caps| vec![format!("{:?}", caps)])
                        .unwrap_or_default(),
                }
            }
            Err(e) => {
                overall_healthy = false;
                BackendHealthInfo {
                    status: "error".to_string(),
                    last_check: None,
                    response_time_ms: None,
                    error_message: Some(e.to_string()),
                    capabilities: vec![],
                }
            }
        };

        backends.insert(backend_name, backend_info);
    }

    let response = HealthResponse {
        status: if overall_healthy {
            "healthy"
        } else {
            "degraded"
        }
        .to_string(),
        backends,
        overall_healthy,
        timestamp: chrono::Utc::now().timestamp_millis() as u64,
        version: env!("CARGO_PKG_VERSION").to_string(),
    };

    Ok(Json(ApiResponse::success(response)))
}

/// GET /api/v1/health/{backend} - Specific backend health
pub async fn backend_health(
    State(router): State<Arc<BackendRouter>>,
    Path(backend_name): Path<String>,
) -> Result<Json<ApiResponse<BackendHealthInfo>>, StatusCode> {
    debug!(backend = %backend_name, "Backend HEALTH check");

    if let Some(backend) = router.get_backend(&backend_name).await {
        match backend.health_check().await {
            Ok(health) => {
                let status_str = match health.status {
                    HealthStatus::Healthy => "healthy",
                    HealthStatus::Degraded => "degraded",
                    HealthStatus::Unhealthy => "unhealthy",
                };

                let info = BackendHealthInfo {
                    status: status_str.to_string(),
                    last_check: health.last_check,
                    response_time_ms: health.response_time_ms,
                    error_message: health.error_message,
                    capabilities: health
                        .capabilities
                        .map(|caps| vec![format!("{:?}", caps)])
                        .unwrap_or_default(),
                };

                Ok(Json(ApiResponse::success(info)))
            }
            Err(e) => {
                error!(backend = %backend_name, error = %e, "Backend health check failed");
                let info = BackendHealthInfo {
                    status: "error".to_string(),
                    last_check: None,
                    response_time_ms: None,
                    error_message: Some(e.to_string()),
                    capabilities: vec![],
                };
                Ok(Json(ApiResponse::success(info)))
            }
        }
    } else {
        Ok(Json(ApiResponse::error(format!(
            "Backend '{}' not found",
            backend_name
        ))))
    }
}

/// GET /api/v1/stats - Overall system statistics
pub async fn system_stats(
    State(router): State<Arc<BackendRouter>>,
) -> Result<Json<ApiResponse<StatsResponse>>, StatusCode> {
    debug!("Universal STATS request");

    let backend_names = router.get_all_backends().await;
    let mut backends = HashMap::new();

    // Collect stats from all backends
    for backend_name in &backend_names {
        if let Some(backend) = router.get_backend(backend_name).await {
            match backend.get_stats().await {
                Ok(stats) => {
                    let backend_info = BackendStatsInfo {
                        connections: ConnectionStatsInfo {
                            active: stats.connections.active,
                            total: stats.connections.total,
                            errors: stats.connections.errors,
                            pool_size: stats.connections.pool_size,
                        },
                        operations: OperationStatsInfo {
                            total_operations: stats.operations.total_operations,
                            data_operations: stats.operations.data_operations,
                            query_operations: stats.operations.query_operations,
                            stream_operations: stats.operations.stream_operations,
                            failed_operations: stats.operations.failed_operations,
                            average_latency_ms: stats.operations.average_latency_ms,
                        },
                        performance: PerformanceStatsInfo {
                            cpu_usage_percent: stats.performance.cpu_usage_percent,
                            memory_usage_bytes: stats.performance.memory_usage_bytes,
                            disk_usage_bytes: stats.performance.disk_usage_bytes,
                            network_io_bytes: stats.performance.network_io_bytes,
                        },
                        storage: stats.storage.map(|storage| StorageStatsInfo {
                            total_size_bytes: storage.total_size_bytes,
                            used_size_bytes: storage.used_size_bytes,
                            free_size_bytes: storage.free_size_bytes,
                            key_count: storage.key_count,
                        }),
                    };

                    backends.insert(backend_name.clone(), backend_info);
                }
                Err(e) => {
                    error!(backend = %backend_name, error = %e, "Failed to get backend stats");
                }
            }
        }
    }

    // Get routing statistics
    let routing_stats = router.get_routing_stats().await;
    let healthy_backends = backends.len(); // Simplified for now

    let routing_info = RoutingStatsInfo {
        total_backends: routing_stats.total_backends,
        healthy_backends,
        load_balancer_stats: LoadBalancerStatsInfo {
            strategy: "round_robin".to_string(), // TODO: Get actual strategy
            total_requests: routing_stats.load_balancer_stats.total_requests,
            backend_distribution: routing_stats.load_balancer_stats.backend_distribution,
            average_response_time_ms: routing_stats.load_balancer_stats.average_response_time_ms,
        },
        key_matcher_stats: KeyMatcherStatsInfo {
            total_patterns: routing_stats.key_matcher_stats.total_patterns,
            total_matches: routing_stats.key_matcher_stats.total_matches,
            pattern_hit_rate: routing_stats.key_matcher_stats.pattern_hit_rate,
        },
    };

    let response = StatsResponse {
        backends,
        routing_stats: routing_info,
        timestamp: chrono::Utc::now().timestamp_millis() as u64,
    };

    Ok(Json(ApiResponse::success(response)))
}

/// GET /api/v1/stats/{backend} - Specific backend statistics
pub async fn backend_stats(
    State(router): State<Arc<BackendRouter>>,
    Path(backend_name): Path<String>,
) -> Result<Json<ApiResponse<BackendStatsInfo>>, StatusCode> {
    debug!(backend = %backend_name, "Backend STATS request");

    if let Some(backend) = router.get_backend(&backend_name).await {
        match backend.get_stats().await {
            Ok(stats) => {
                let info = BackendStatsInfo {
                    connections: ConnectionStatsInfo {
                        active: stats.connections.active,
                        total: stats.connections.total,
                        errors: stats.connections.errors,
                        pool_size: stats.connections.pool_size,
                    },
                    operations: OperationStatsInfo {
                        total_operations: stats.operations.total_operations,
                        data_operations: stats.operations.data_operations,
                        query_operations: stats.operations.query_operations,
                        stream_operations: stats.operations.stream_operations,
                        failed_operations: stats.operations.failed_operations,
                        average_latency_ms: stats.operations.average_latency_ms,
                    },
                    performance: PerformanceStatsInfo {
                        cpu_usage_percent: stats.performance.cpu_usage_percent,
                        memory_usage_bytes: stats.performance.memory_usage_bytes,
                        disk_usage_bytes: stats.performance.disk_usage_bytes,
                        network_io_bytes: stats.performance.network_io_bytes,
                    },
                    storage: stats.storage.map(|storage| StorageStatsInfo {
                        total_size_bytes: storage.total_size_bytes,
                        used_size_bytes: storage.used_size_bytes,
                        free_size_bytes: storage.free_size_bytes,
                        key_count: storage.key_count,
                    }),
                };

                Ok(Json(ApiResponse::success(info)))
            }
            Err(e) => {
                error!(backend = %backend_name, error = %e, "Failed to get backend stats");
                Ok(Json(ApiResponse::error(format!(
                    "Failed to get stats for backend '{}': {}",
                    backend_name, e
                ))))
            }
        }
    } else {
        Ok(Json(ApiResponse::error(format!(
            "Backend '{}' not found",
            backend_name
        ))))
    }
}

/// Create universal health routes
pub fn create_universal_health_routes(router: Arc<BackendRouter>) -> Router {
    Router::new()
        .route("/health", get(system_health))
        .route("/health/:backend", get(backend_health))
        .route("/stats", get(system_stats))
        .route("/stats/:backend", get(backend_stats))
        .with_state(router)
}
