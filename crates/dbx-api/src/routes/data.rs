use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::models::ApiResponse;
use dbx_core::{DataOperation, DataValue};
use dbx_router::BackendRouter;

/// Request for setting data
#[derive(Debug, Deserialize)]
pub struct SetDataRequest {
    pub value: serde_json::Value,
    pub ttl: Option<u64>,
}

/// Request for updating data
#[derive(Debug, Deserialize)]
pub struct UpdateDataRequest {
    pub fields: HashMap<String, serde_json::Value>,
    pub ttl: Option<u64>,
}

/// Request for batch operations
#[derive(Debug, Deserialize)]
pub struct BatchDataRequest {
    pub operations: Vec<BatchDataOperation>,
}

/// Batch operation definition
#[derive(Debug, Deserialize)]
pub struct BatchDataOperation {
    pub operation_type: String,
    pub key: String,
    pub value: Option<serde_json::Value>,
    pub fields: Option<HashMap<String, serde_json::Value>>,
    pub ttl: Option<u64>,
}

/// Data response
#[derive(Debug, Serialize)]
pub struct DataResponse {
    pub operation_id: String,
    pub success: bool,
    pub data: Option<serde_json::Value>,
    pub execution_time_ms: Option<u64>,
    pub backend: Option<String>,
}

/// Get data by key
pub async fn get_data(
    Path(key): Path<String>,
    State(router): State<Arc<BackendRouter>>,
) -> Result<Json<ApiResponse<DataResponse>>, StatusCode> {
    let operation = DataOperation::Get {
        key: key.clone(),
        fields: None,
    };

    match router.route_data_operation(&operation).await {
        Ok(backend) => match backend.execute_data(operation).await {
            Ok(result) => {
                let response = DataResponse {
                    operation_id: result.operation_id.to_string(),
                    success: result.success,
                    data: result
                        .data
                        .map(|d| serde_json::to_value(d).unwrap_or(serde_json::Value::Null)),
                    execution_time_ms: result.metadata.as_ref().map(|m| m.execution_time_ms),
                    backend: result.metadata.as_ref().map(|m| m.backend.clone()),
                };

                Ok(Json(ApiResponse::success(response)))
            }
            Err(e) => {
                let error_response = DataResponse {
                    operation_id: Uuid::new_v4().to_string(),
                    success: false,
                    data: None,
                    execution_time_ms: None,
                    backend: Some(backend.name().to_string()),
                };

                Ok(Json(ApiResponse::error(format!(
                    "Failed to get data for key {}: {}",
                    key, e
                ))))
            }
        },
        Err(e) => Ok(Json(ApiResponse::error(format!(
            "Failed to route operation for key {}: {}",
            key, e
        )))),
    }
}

/// Set data by key
pub async fn set_data(
    Path(key): Path<String>,
    State(router): State<Arc<BackendRouter>>,
    Json(request): Json<SetDataRequest>,
) -> Result<Json<ApiResponse<DataResponse>>, StatusCode> {
    let data_value = json_to_data_value(request.value);

    let operation = DataOperation::Set {
        key: key.clone(),
        value: data_value,
        ttl: request.ttl,
    };

    match router.route_data_operation(&operation).await {
        Ok(backend) => match backend.execute_data(operation).await {
            Ok(result) => {
                let response = DataResponse {
                    operation_id: result.operation_id.to_string(),
                    success: result.success,
                    data: result
                        .data
                        .map(|d| serde_json::to_value(d).unwrap_or(serde_json::Value::Null)),
                    execution_time_ms: result.metadata.as_ref().map(|m| m.execution_time_ms),
                    backend: result.metadata.as_ref().map(|m| m.backend.clone()),
                };

                Ok(Json(ApiResponse::success(response)))
            }
            Err(e) => Ok(Json(ApiResponse::error(format!(
                "Failed to set data for key {}: {}",
                key, e
            )))),
        },
        Err(e) => Ok(Json(ApiResponse::error(format!(
            "Failed to route operation for key {}: {}",
            key, e
        )))),
    }
}

/// Update data by key
pub async fn update_data(
    Path(key): Path<String>,
    State(router): State<Arc<BackendRouter>>,
    Json(request): Json<UpdateDataRequest>,
) -> Result<Json<ApiResponse<DataResponse>>, StatusCode> {
    let fields: HashMap<String, DataValue> = request
        .fields
        .into_iter()
        .map(|(k, v)| (k, json_to_data_value(v)))
        .collect();

    let operation = DataOperation::Update {
        key: key.clone(),
        fields,
        ttl: request.ttl,
    };

    match router.route_data_operation(&operation).await {
        Ok(backend) => match backend.execute_data(operation).await {
            Ok(result) => {
                let response = DataResponse {
                    operation_id: result.operation_id.to_string(),
                    success: result.success,
                    data: result
                        .data
                        .map(|d| serde_json::to_value(d).unwrap_or(serde_json::Value::Null)),
                    execution_time_ms: result.metadata.as_ref().map(|m| m.execution_time_ms),
                    backend: result.metadata.as_ref().map(|m| m.backend.clone()),
                };

                Ok(Json(ApiResponse::success(response)))
            }
            Err(e) => Ok(Json(ApiResponse::error(format!(
                "Failed to update data for key {}: {}",
                key, e
            )))),
        },
        Err(e) => Ok(Json(ApiResponse::error(format!(
            "Failed to route operation for key {}: {}",
            key, e
        )))),
    }
}

/// Delete data by key
pub async fn delete_data(
    Path(key): Path<String>,
    State(router): State<Arc<BackendRouter>>,
) -> Result<Json<ApiResponse<DataResponse>>, StatusCode> {
    let operation = DataOperation::Delete {
        key: key.clone(),
        fields: None,
    };

    match router.route_data_operation(&operation).await {
        Ok(backend) => match backend.execute_data(operation).await {
            Ok(result) => {
                let response = DataResponse {
                    operation_id: result.operation_id.to_string(),
                    success: result.success,
                    data: result
                        .data
                        .map(|d| serde_json::to_value(d).unwrap_or(serde_json::Value::Null)),
                    execution_time_ms: result.metadata.as_ref().map(|m| m.execution_time_ms),
                    backend: result.metadata.as_ref().map(|m| m.backend.clone()),
                };

                Ok(Json(ApiResponse::success(response)))
            }
            Err(e) => Ok(Json(ApiResponse::error(format!(
                "Failed to delete data for key {}: {}",
                key, e
            )))),
        },
        Err(e) => Ok(Json(ApiResponse::error(format!(
            "Failed to route operation for key {}: {}",
            key, e
        )))),
    }
}

/// Check if data exists
pub async fn check_exists(
    Path(key): Path<String>,
    State(router): State<Arc<BackendRouter>>,
) -> Result<Json<ApiResponse<DataResponse>>, StatusCode> {
    let operation = DataOperation::Exists {
        key: key.clone(),
        fields: None,
    };

    match router.route_data_operation(&operation).await {
        Ok(backend) => match backend.execute_data(operation).await {
            Ok(result) => {
                let response = DataResponse {
                    operation_id: result.operation_id.to_string(),
                    success: result.success,
                    data: result
                        .data
                        .map(|d| serde_json::to_value(d).unwrap_or(serde_json::Value::Null)),
                    execution_time_ms: result.metadata.as_ref().map(|m| m.execution_time_ms),
                    backend: result.metadata.as_ref().map(|m| m.backend.clone()),
                };

                Ok(Json(ApiResponse::success(response)))
            }
            Err(e) => Ok(Json(ApiResponse::error(format!(
                "Failed to check existence for key {}: {}",
                key, e
            )))),
        },
        Err(e) => Ok(Json(ApiResponse::error(format!(
            "Failed to route operation for key {}: {}",
            key, e
        )))),
    }
}

/// Batch operations
pub async fn batch_operations(
    State(router): State<Arc<BackendRouter>>,
    Json(request): Json<BatchDataRequest>,
) -> Result<Json<ApiResponse<Vec<DataResponse>>>, StatusCode> {
    let mut operations = Vec::new();

    for batch_op in request.operations {
        let operation = match batch_op.operation_type.as_str() {
            "get" => DataOperation::Get {
                key: batch_op.key,
                fields: None,
            },
            "set" => {
                if let Some(value) = batch_op.value {
                    DataOperation::Set {
                        key: batch_op.key,
                        value: json_to_data_value(value),
                        ttl: batch_op.ttl,
                    }
                } else {
                    continue;
                }
            }
            "update" => {
                if let Some(fields_json) = batch_op.fields {
                    let fields: HashMap<String, DataValue> = fields_json
                        .into_iter()
                        .map(|(k, v)| (k, json_to_data_value(v)))
                        .collect();

                    DataOperation::Update {
                        key: batch_op.key,
                        fields,
                        ttl: batch_op.ttl,
                    }
                } else {
                    continue;
                }
            }
            "delete" => DataOperation::Delete {
                key: batch_op.key,
                fields: None,
            },
            "exists" => DataOperation::Exists {
                key: batch_op.key,
                fields: None,
            },
            _ => continue,
        };

        operations.push(operation);
    }

    let batch_operation = DataOperation::Batch { operations };

    match router.route_data_operation(&batch_operation).await {
        Ok(backend) => match backend.execute_data(batch_operation).await {
            Ok(result) => {
                let response = DataResponse {
                    operation_id: result.operation_id.to_string(),
                    success: result.success,
                    data: result
                        .data
                        .map(|d| serde_json::to_value(d).unwrap_or(serde_json::Value::Null)),
                    execution_time_ms: result.metadata.as_ref().map(|m| m.execution_time_ms),
                    backend: result.metadata.as_ref().map(|m| m.backend.clone()),
                };

                Ok(Json(ApiResponse::success(vec![response])))
            }
            Err(e) => Ok(Json(ApiResponse::error(format!(
                "Failed to execute batch operations: {}",
                e
            )))),
        },
        Err(e) => Ok(Json(ApiResponse::error(format!(
            "Failed to route batch operations: {}",
            e
        )))),
    }
}

/// Convert JSON value to DataValue
fn json_to_data_value(value: serde_json::Value) -> DataValue {
    match value {
        serde_json::Value::Null => DataValue::Null,
        serde_json::Value::Bool(b) => DataValue::Bool(b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                DataValue::Int(i)
            } else if let Some(f) = n.as_f64() {
                DataValue::Float(f)
            } else {
                DataValue::Null
            }
        }
        serde_json::Value::String(s) => DataValue::String(s),
        serde_json::Value::Array(arr) => {
            let data_values: Vec<DataValue> = arr.into_iter().map(json_to_data_value).collect();
            DataValue::Array(data_values)
        }
        serde_json::Value::Object(obj) => {
            let data_map: HashMap<String, DataValue> = obj
                .into_iter()
                .map(|(k, v)| (k, json_to_data_value(v)))
                .collect();
            DataValue::Object(data_map)
        }
    }
}

/// Create routes for universal data operations
pub fn create_universal_data_routes(router: Arc<BackendRouter>) -> Router {
    Router::new()
        .route("/:key", get(get_data))
        .route("/:key", post(set_data))
        .route("/:key", put(update_data))
        .route("/:key", delete(delete_data))
        .route("/:key/exists", get(check_exists))
        .route("/batch", post(batch_operations))
        .with_state(router)
}
