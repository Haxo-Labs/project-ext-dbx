use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::get,
    Router,
};
use serde::Serialize;
use std::sync::Arc;

use crate::models::ApiResponse;
use dbx_core::HealthStatus;
use dbx_router::BackendRouter;

#[derive(Debug, Serialize)]
pub struct SystemHealthResponse {
    pub status: HealthStatus,
    pub backends: Vec<BackendHealthInfo>,
    pub routing_stats: RoutingStatsInfo,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct BackendHealthInfo {
    pub name: String,
    pub status: HealthStatus,
    pub connection_count: u32,
    pub operations_count: u64,
    pub avg_response_time_ms: f64,
    pub last_check: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct BackendHealthResponse {
    pub name: String,
    pub status: HealthStatus,
    pub connection_count: u32,
    pub operations_count: u64,
    pub avg_response_time_ms: f64,
    pub last_check: chrono::DateTime<chrono::Utc>,
    pub details: BackendHealthDetails,
}

#[derive(Debug, Serialize)]
pub struct BackendHealthDetails {
    pub connections: ConnectionStats,
    pub operations: OperationStats,
    pub performance: PerformanceStats,
    pub storage: Option<StorageStats>,
}

#[derive(Debug, Serialize)]
pub struct ConnectionStats {
    pub active: u32,
    pub idle: u32,
    pub total: u32,
    pub max_pool_size: u32,
}

#[derive(Debug, Serialize)]
pub struct OperationStats {
    pub total_operations: u64,
    pub successful_operations: u64,
    pub failed_operations: u64,
    pub operations_per_second: f64,
}

#[derive(Debug, Serialize)]
pub struct PerformanceStats {
    pub avg_response_time_ms: f64,
    pub p95_response_time_ms: f64,
    pub p99_response_time_ms: f64,
}

#[derive(Debug, Serialize)]
pub struct StorageStats {
    pub used_memory_bytes: u64,
    pub total_memory_bytes: Option<u64>,
    pub key_count: u64,
    pub database_size_bytes: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct RoutingStatsInfo {
    pub total_backends: usize,
    pub load_balancer_stats: String, // Load balancer statistics
    pub key_matcher_stats: String,   // Key matcher statistics
}

pub fn create_health_routes() -> Router<Arc<BackendRouter>> {
    Router::new()
        .route("/system", get(get_system_health))
        .route("/backend/:name", get(get_backend_health))
}

async fn get_system_health(
    State(router): State<Arc<BackendRouter>>,
) -> Result<Json<ApiResponse<SystemHealthResponse>>, StatusCode> {
    // Get all configured backends
    let backend_names = router.get_all_backends().await;
    let mut backends = Vec::new();
    let mut overall_status = HealthStatus::Healthy;

    for backend_name in &backend_names {
        match router.get_backend(backend_name).await {
            Some(backend) => {
                // Get backend health status
                let health_status = match backend.health_check().await {
                    Ok(_) => HealthStatus::Healthy,
                    Err(_) => {
                        overall_status = HealthStatus::Unhealthy;
                        HealthStatus::Unhealthy
                    }
                };

                // Get backend stats if available
                let stats = backend.get_stats().await.unwrap_or_else(|_| {
                    // Create default stats if getting stats fails
                    dbx_core::BackendStats {
                        connections: dbx_core::ConnectionStats {
                            active: 0,
                            idle: 0,
                            total: 0,
                            max_pool_size: 0,
                        },
                        operations: dbx_core::OperationStats {
                            total_operations: 0,
                            successful_operations: 0,
                            failed_operations: 0,
                            operations_per_second: 0.0,
                        },
                        performance: dbx_core::PerformanceStats {
                            avg_response_time_ms: 0.0,
                            p95_response_time_ms: 0.0,
                            p99_response_time_ms: 0.0,
                        },
                        storage: None,
                    }
                });

                backends.push(BackendHealthInfo {
                    name: backend_name.clone(),
                    status: health_status,
                    connection_count: stats.connections.active,
                    operations_count: stats.operations.total_operations,
                    avg_response_time_ms: stats.performance.avg_response_time_ms,
                    last_check: chrono::Utc::now(),
                });
            }
            None => {
                overall_status = HealthStatus::Unhealthy;
                backends.push(BackendHealthInfo {
                    name: backend_name.clone(),
                    status: HealthStatus::Unhealthy,
                    connection_count: 0,
                    operations_count: 0,
                    avg_response_time_ms: 0.0,
                    last_check: chrono::Utc::now(),
                });
            }
        }
    }

    // Set overall status based on backend health
    if overall_status == HealthStatus::Healthy && !backends.is_empty() {
        overall_status = HealthStatus::Healthy;
    } else if backends.is_empty() {
        overall_status = HealthStatus::Unhealthy;
    }

    // Get routing stats
    let routing_stats = router.get_routing_stats().await;

    let response = SystemHealthResponse {
        status: overall_status,
        backends,
        routing_stats: RoutingStatsInfo {
            total_backends: routing_stats.total_backends,
            load_balancer_stats: format!("Load balancer stats available"),
            key_matcher_stats: format!("Key matcher stats available"),
        },
        timestamp: chrono::Utc::now(),
    };

    Ok(Json(ApiResponse::success(response)))
}

async fn get_backend_health(
    State(router): State<Arc<BackendRouter>>,
    Path(backend_name): Path<String>,
) -> Result<Json<ApiResponse<BackendHealthResponse>>, StatusCode> {
    match router.get_backend(&backend_name).await {
        Some(backend) => {
            // Get backend health status
            let health_status = match backend.health_check().await {
                Ok(_) => HealthStatus::Healthy,
                Err(_) => HealthStatus::Unhealthy,
            };

            // Get backend stats
            let stats = backend.get_stats().await.unwrap_or_else(|_| {
                // Create default stats if getting stats fails
                dbx_core::BackendStats {
                    connections: dbx_core::ConnectionStats {
                        active: 0,
                        idle: 0,
                        total: 0,
                        max_pool_size: 0,
                    },
                    operations: dbx_core::OperationStats {
                        total_operations: 0,
                        successful_operations: 0,
                        failed_operations: 0,
                        operations_per_second: 0.0,
                    },
                    performance: dbx_core::PerformanceStats {
                        avg_response_time_ms: 0.0,
                        p95_response_time_ms: 0.0,
                        p99_response_time_ms: 0.0,
                    },
                    storage: None,
                }
            });

            let response = BackendHealthResponse {
                name: backend_name,
                status: health_status,
                connection_count: stats.connections.active,
                operations_count: stats.operations.total_operations,
                avg_response_time_ms: stats.performance.avg_response_time_ms,
                last_check: chrono::Utc::now(),
                details: BackendHealthDetails {
                    connections: ConnectionStats {
                        active: stats.connections.active,
                        idle: stats.connections.idle,
                        total: stats.connections.total,
                        max_pool_size: stats.connections.max_pool_size,
                    },
                    operations: OperationStats {
                        total_operations: stats.operations.total_operations,
                        successful_operations: stats.operations.successful_operations,
                        failed_operations: stats.operations.failed_operations,
                        operations_per_second: stats.operations.operations_per_second,
                    },
                    performance: PerformanceStats {
                        avg_response_time_ms: stats.performance.avg_response_time_ms,
                        p95_response_time_ms: stats.performance.p95_response_time_ms,
                        p99_response_time_ms: stats.performance.p99_response_time_ms,
                    },
                    storage: stats.storage.map(|s| StorageStats {
                        used_memory_bytes: s.used_memory_bytes,
                        total_memory_bytes: s.total_memory_bytes,
                        key_count: s.key_count,
                        database_size_bytes: s.database_size_bytes,
                    }),
                },
            };

            Ok(Json(ApiResponse::success(response)))
        }
        None => Ok(Json(ApiResponse::error(format!(
            "Backend '{}' not found",
            backend_name
        )))),
    }
}
