use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
    response::Json as ResponseJson,
    routing::{delete, get, post, put},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, warn};

use dbx_core::{DataOperation, DataResult, DataValue, DbxResult};
use dbx_router::BackendRouter;

use crate::models::ApiResponse;

/// Universal data operation request
#[derive(Debug, Serialize, Deserialize)]
pub struct DataRequest {
    pub value: Option<DataValue>,
    pub fields: Option<Vec<String>>,
    pub ttl_seconds: Option<u64>,
    pub conditions: Option<HashMap<String, DataValue>>,
}

/// Universal data operation response
#[derive(Debug, Serialize, Deserialize)]
pub struct DataResponse {
    pub success: bool,
    pub data: Option<DataValue>,
    pub metadata: Option<ResponseMetadata>,
    pub error: Option<String>,
}

/// Response metadata
#[derive(Debug, Serialize, Deserialize)]
pub struct ResponseMetadata {
    pub backend_used: String,
    pub operation_time_ms: u64,
    pub cache_hit: Option<bool>,
}

/// Batch data operation request
#[derive(Debug, Serialize, Deserialize)]
pub struct BatchDataRequest {
    pub operations: Vec<BatchOperation>,
}

/// Single operation in a batch
#[derive(Debug, Serialize, Deserialize)]
pub struct BatchOperation {
    pub key: String,
    pub operation: String, // "get", "set", "update", "delete", "exists"
    pub value: Option<DataValue>,
    pub fields: Option<Vec<String>>,
    pub ttl_seconds: Option<u64>,
}

/// Batch data operation response
#[derive(Debug, Serialize, Deserialize)]
pub struct BatchDataResponse {
    pub success: bool,
    pub results: Vec<BatchResult>,
    pub metadata: Option<ResponseMetadata>,
}

/// Single result in a batch
#[derive(Debug, Serialize, Deserialize)]
pub struct BatchResult {
    pub key: String,
    pub success: bool,
    pub data: Option<DataValue>,
    pub error: Option<String>,
}

// =========================
// Universal Data Handlers
// =========================

/// GET /api/v1/data/{key} - Get data by key
pub async fn get_data(
    State(router): State<Arc<BackendRouter>>,
    Path(key): Path<String>,
) -> Result<ResponseJson<ApiResponse<DataResponse>>, StatusCode> {
    debug!(key = %key, "Universal GET operation");

    let operation = DataOperation::Get {
        key: key.clone(),
        fields: None,
    };

    match execute_data_operation(&router, operation).await {
        Ok((result, backend_name, duration)) => {
            let response = DataResponse {
                success: true,
                data: Some(result.value),
                metadata: Some(ResponseMetadata {
                    backend_used: backend_name,
                    operation_time_ms: duration,
                    cache_hit: None,
                }),
                error: None,
            };
            Ok(ResponseJson(ApiResponse::success(response)))
        }
        Err(e) => {
            error!(key = %key, error = %e, "GET operation failed");
            Ok(ResponseJson(ApiResponse::error(format!(
                "Failed to get data: {}",
                e
            ))))
        }
    }
}

/// GET /api/v1/data/{key}/fields/{field} - Get specific field from key
pub async fn get_data_field(
    State(router): State<Arc<BackendRouter>>,
    Path((key, field)): Path<(String, String)>,
) -> Result<ResponseJson<ApiResponse<DataResponse>>, StatusCode> {
    debug!(key = %key, field = %field, "Universal GET field operation");

    let operation = DataOperation::Get {
        key: key.clone(),
        fields: Some(vec![field]),
    };

    match execute_data_operation(&router, operation).await {
        Ok((result, backend_name, duration)) => {
            let response = DataResponse {
                success: true,
                data: Some(result.value),
                metadata: Some(ResponseMetadata {
                    backend_used: backend_name,
                    operation_time_ms: duration,
                    cache_hit: None,
                }),
                error: None,
            };
            Ok(ResponseJson(ApiResponse::success(response)))
        }
        Err(e) => {
            error!(key = %key, field = %field, error = %e, "GET field operation failed");
            Ok(ResponseJson(ApiResponse::error(format!(
                "Failed to get field: {}",
                e
            ))))
        }
    }
}

/// POST /api/v1/data/{key} - Set data by key
pub async fn set_data(
    State(router): State<Arc<BackendRouter>>,
    Path(key): Path<String>,
    Json(request): Json<DataRequest>,
) -> Result<ResponseJson<ApiResponse<DataResponse>>, StatusCode> {
    debug!(key = %key, "Universal SET operation");

    let value = request.value.ok_or_else(|| {
        warn!(key = %key, "SET operation missing value");
        StatusCode::BAD_REQUEST
    })?;

    let operation = DataOperation::Set {
        key: key.clone(),
        value,
        ttl_seconds: request.ttl_seconds,
        fields: request.fields,
    };

    match execute_data_operation(&router, operation).await {
        Ok((result, backend_name, duration)) => {
            let response = DataResponse {
                success: true,
                data: Some(result.value),
                metadata: Some(ResponseMetadata {
                    backend_used: backend_name,
                    operation_time_ms: duration,
                    cache_hit: None,
                }),
                error: None,
            };
            Ok(ResponseJson(ApiResponse::success(response)))
        }
        Err(e) => {
            error!(key = %key, error = %e, "SET operation failed");
            Ok(ResponseJson(ApiResponse::error(format!(
                "Failed to set data: {}",
                e
            ))))
        }
    }
}

/// PUT /api/v1/data/{key} - Update data by key
pub async fn update_data(
    State(router): State<Arc<BackendRouter>>,
    Path(key): Path<String>,
    Json(request): Json<DataRequest>,
) -> Result<ResponseJson<ApiResponse<DataResponse>>, StatusCode> {
    debug!(key = %key, "Universal UPDATE operation");

    let value = request.value.ok_or_else(|| {
        warn!(key = %key, "UPDATE operation missing value");
        StatusCode::BAD_REQUEST
    })?;

    let operation = DataOperation::Update {
        key: key.clone(),
        value,
        conditions: request.conditions,
        fields: request.fields,
    };

    match execute_data_operation(&router, operation).await {
        Ok((result, backend_name, duration)) => {
            let response = DataResponse {
                success: true,
                data: Some(result.value),
                metadata: Some(ResponseMetadata {
                    backend_used: backend_name,
                    operation_time_ms: duration,
                    cache_hit: None,
                }),
                error: None,
            };
            Ok(ResponseJson(ApiResponse::success(response)))
        }
        Err(e) => {
            error!(key = %key, error = %e, "UPDATE operation failed");
            Ok(ResponseJson(ApiResponse::error(format!(
                "Failed to update data: {}",
                e
            ))))
        }
    }
}

/// DELETE /api/v1/data/{key} - Delete data by key
pub async fn delete_data(
    State(router): State<Arc<BackendRouter>>,
    Path(key): Path<String>,
) -> Result<ResponseJson<ApiResponse<DataResponse>>, StatusCode> {
    debug!(key = %key, "Universal DELETE operation");

    let operation = DataOperation::Delete {
        key: key.clone(),
        fields: None,
    };

    match execute_data_operation(&router, operation).await {
        Ok((result, backend_name, duration)) => {
            let response = DataResponse {
                success: true,
                data: Some(result.value),
                metadata: Some(ResponseMetadata {
                    backend_used: backend_name,
                    operation_time_ms: duration,
                    cache_hit: None,
                }),
                error: None,
            };
            Ok(ResponseJson(ApiResponse::success(response)))
        }
        Err(e) => {
            error!(key = %key, error = %e, "DELETE operation failed");
            Ok(ResponseJson(ApiResponse::error(format!(
                "Failed to delete data: {}",
                e
            ))))
        }
    }
}

/// GET /api/v1/data/{key}/exists - Check if key exists
pub async fn check_exists(
    State(router): State<Arc<BackendRouter>>,
    Path(key): Path<String>,
) -> Result<ResponseJson<ApiResponse<DataResponse>>, StatusCode> {
    debug!(key = %key, "Universal EXISTS operation");

    let operation = DataOperation::Exists {
        key: key.clone(),
        fields: None,
    };

    match execute_data_operation(&router, operation).await {
        Ok((result, backend_name, duration)) => {
            let response = DataResponse {
                success: true,
                data: Some(result.value),
                metadata: Some(ResponseMetadata {
                    backend_used: backend_name,
                    operation_time_ms: duration,
                    cache_hit: None,
                }),
                error: None,
            };
            Ok(ResponseJson(ApiResponse::success(response)))
        }
        Err(e) => {
            error!(key = %key, error = %e, "EXISTS operation failed");
            Ok(ResponseJson(ApiResponse::error(format!(
                "Failed to check existence: {}",
                e
            ))))
        }
    }
}

/// POST /api/v1/data/batch - Execute batch operations
pub async fn batch_operations(
    State(router): State<Arc<BackendRouter>>,
    Json(request): Json<BatchDataRequest>,
) -> Result<ResponseJson<ApiResponse<BatchDataResponse>>, StatusCode> {
    debug!(
        operation_count = request.operations.len(),
        "Universal BATCH operation"
    );

    let mut results = Vec::new();
    let start_time = std::time::Instant::now();

    for batch_op in request.operations {
        let operation = match batch_op.operation.as_str() {
            "get" => DataOperation::Get {
                key: batch_op.key.clone(),
                fields: batch_op.fields,
            },
            "set" => {
                if let Some(value) = batch_op.value {
                    DataOperation::Set {
                        key: batch_op.key.clone(),
                        value,
                        ttl_seconds: batch_op.ttl_seconds,
                        fields: batch_op.fields,
                    }
                } else {
                    results.push(BatchResult {
                        key: batch_op.key,
                        success: false,
                        data: None,
                        error: Some("Missing value for set operation".to_string()),
                    });
                    continue;
                }
            }
            "update" => {
                if let Some(value) = batch_op.value {
                    DataOperation::Update {
                        key: batch_op.key.clone(),
                        value,
                        conditions: None,
                        fields: batch_op.fields,
                    }
                } else {
                    results.push(BatchResult {
                        key: batch_op.key,
                        success: false,
                        data: None,
                        error: Some("Missing value for update operation".to_string()),
                    });
                    continue;
                }
            }
            "delete" => DataOperation::Delete {
                key: batch_op.key.clone(),
                fields: batch_op.fields,
            },
            "exists" => DataOperation::Exists {
                key: batch_op.key.clone(),
                fields: batch_op.fields,
            },
            _ => {
                results.push(BatchResult {
                    key: batch_op.key,
                    success: false,
                    data: None,
                    error: Some(format!("Unknown operation: {}", batch_op.operation)),
                });
                continue;
            }
        };

        match execute_data_operation(&router, operation).await {
            Ok((result, _backend_name, _duration)) => {
                results.push(BatchResult {
                    key: batch_op.key,
                    success: true,
                    data: Some(result.value),
                    error: None,
                });
            }
            Err(e) => {
                results.push(BatchResult {
                    key: batch_op.key,
                    success: false,
                    data: None,
                    error: Some(e.to_string()),
                });
            }
        }
    }

    let duration = start_time.elapsed().as_millis() as u64;

    let response = BatchDataResponse {
        success: true,
        results,
        metadata: Some(ResponseMetadata {
            backend_used: "batch".to_string(),
            operation_time_ms: duration,
            cache_hit: None,
        }),
    };

    Ok(ResponseJson(ApiResponse::success(response)))
}

// =========================
// Helper Functions
// =========================

/// Execute a data operation and measure performance
async fn execute_data_operation(
    router: &BackendRouter,
    operation: DataOperation,
) -> DbxResult<(DataResult, String, u64)> {
    let start_time = std::time::Instant::now();

    // Route the operation to appropriate backend
    let backend = router.route_data_operation(&operation).await?;
    let backend_name = backend.name().to_string();

    // Execute the operation
    let result = backend.execute_data(operation).await?;

    let duration = start_time.elapsed().as_millis() as u64;

    Ok((result, backend_name, duration))
}

/// Create universal data routes
pub fn create_universal_data_routes(router: Arc<BackendRouter>) -> Router {
    Router::new()
        .route("/data/:key", get(get_data))
        .route("/data/:key", post(set_data))
        .route("/data/:key", put(update_data))
        .route("/data/:key", delete(delete_data))
        .route("/data/:key/exists", get(check_exists))
        .route("/data/:key/fields/:field", get(get_data_field))
        .route("/data/batch", post(batch_operations))
        .with_state(router)
}
