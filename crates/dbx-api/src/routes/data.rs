use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    Extension, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::permissions::PermissionType;
use crate::models::{ApiResponse, RbacContext};
use dbx_core::{DataOperation, DataValue};
use dbx_router::BackendRouter;

/// Request for setting data
#[derive(Debug, Deserialize)]
pub struct SetDataRequest {
    pub value: serde_json::Value,
    pub ttl: Option<u64>,
    pub if_not_exists: Option<bool>,
}

/// Request for updating data
#[derive(Debug, Deserialize)]
pub struct UpdateDataRequest {
    pub fields: HashMap<String, serde_json::Value>,
    pub ttl: Option<u64>,
}

/// Request for setting TTL
#[derive(Debug, Deserialize)]
pub struct SetTtlRequest {
    pub ttl: u64,
}

/// Request for increment operation
#[derive(Debug, Deserialize)]
pub struct IncrementRequest {
    pub amount: Option<i64>,
}

/// Request for decrement operation
#[derive(Debug, Deserialize)]
pub struct DecrementRequest {
    pub amount: Option<i64>,
}

/// Request for append operation
#[derive(Debug, Deserialize)]
pub struct AppendRequest {
    pub value: String,
}

/// Request for compare and swap operation
#[derive(Debug, Deserialize)]
pub struct CompareAndSwapRequest {
    pub expected_value: String,
    pub new_value: String,
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
    Extension(rbac_context): Extension<RbacContext>,
) -> Result<Json<ApiResponse<DataResponse>>, StatusCode> {
    // Check StringGet permission
    if let Err(_) = rbac_context
        .rbac_service
        .check_user_permission(
            &rbac_context.user_id,
            PermissionType::StringGet,
            rbac_context.clone(),
        )
        .await
    {
        return Err(StatusCode::FORBIDDEN);
    }

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
                let _error_response = DataResponse {
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
    Extension(rbac_context): Extension<RbacContext>,
    Json(request): Json<SetDataRequest>,
) -> Result<Json<ApiResponse<DataResponse>>, StatusCode> {
    // Check StringSet permission
    if let Err(_) = rbac_context
        .rbac_service
        .check_user_permission(
            &rbac_context.user_id,
            PermissionType::StringSet,
            rbac_context.clone(),
        )
        .await
    {
        return Err(StatusCode::FORBIDDEN);
    }

    let data_value = json_to_data_value(request.value);

    // Handle conditional set (set if not exists)
    if request.if_not_exists.unwrap_or(false) {
        // First check if key exists
        let exists_operation = DataOperation::Exists {
            key: key.clone(),
            fields: None,
        };

        match router.route_data_operation(&exists_operation).await {
            Ok(backend) => match backend.execute_data(exists_operation).await {
                Ok(exists_result) => {
                    if exists_result.success && exists_result.data == Some(DataValue::Bool(true)) {
                        // Key exists, return false to indicate set was not performed
                        let response = DataResponse {
                            operation_id: exists_result.operation_id.to_string(),
                            success: true,
                            data: Some(serde_json::Value::Bool(false)),
                            execution_time_ms: None,
                            backend: Some(backend.name().to_string()),
                        };
                        return Ok(Json(ApiResponse::success(response)));
                    }
                    // Key doesn't exist, proceed with set operation
                }
                Err(_) => {
                    // Error checking existence, proceed with set operation anyway
                }
            },
            Err(_) => {
                // Error routing exists operation, proceed with set operation anyway
            }
        }
    }

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
    Extension(rbac_context): Extension<RbacContext>,
    Json(request): Json<UpdateDataRequest>,
) -> Result<Json<ApiResponse<DataResponse>>, StatusCode> {
    // Check StringSet permission
    if let Err(_) = rbac_context
        .rbac_service
        .check_user_permission(
            &rbac_context.user_id,
            PermissionType::StringSet,
            rbac_context.clone(),
        )
        .await
    {
        return Err(StatusCode::FORBIDDEN);
    }

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
    Extension(rbac_context): Extension<RbacContext>,
) -> Result<Json<ApiResponse<DataResponse>>, StatusCode> {
    // Check StringSet permission (delete is a write operation)
    if let Err(_) = rbac_context
        .rbac_service
        .check_user_permission(
            &rbac_context.user_id,
            PermissionType::StringSet,
            rbac_context.clone(),
        )
        .await
    {
        return Err(StatusCode::FORBIDDEN);
    }

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

/// Check if data exists by key
pub async fn check_exists(
    Path(key): Path<String>,
    State(router): State<Arc<BackendRouter>>,
    Extension(rbac_context): Extension<RbacContext>,
) -> Result<Json<ApiResponse<DataResponse>>, StatusCode> {
    // Check StringGet permission (exists is a read operation)
    if let Err(_) = rbac_context
        .rbac_service
        .check_user_permission(
            &rbac_context.user_id,
            PermissionType::StringGet,
            rbac_context.clone(),
        )
        .await
    {
        return Err(StatusCode::FORBIDDEN);
    }

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

/// Get TTL for a key
pub async fn get_ttl(
    Path(key): Path<String>,
    State(router): State<Arc<BackendRouter>>,
    Extension(rbac_context): Extension<RbacContext>,
) -> Result<Json<ApiResponse<DataResponse>>, StatusCode> {
    // Check StringGet permission
    if let Err(_) = rbac_context
        .rbac_service
        .check_user_permission(
            &rbac_context.user_id,
            PermissionType::StringGet,
            rbac_context.clone(),
        )
        .await
    {
        return Err(StatusCode::FORBIDDEN);
    }

    let operation = DataOperation::GetTtl { key: key.clone() };

    match router.route_data_operation(&operation).await {
        Ok(backend) => match backend.execute_data(operation).await {
            Ok(result) => {
                let response = DataResponse {
                    operation_id: result.operation_id.to_string(),
                    success: result.success,
                    data: result
                        .data
                        .map(|d| serde_json::to_value(d).unwrap_or(serde_json::Value::Null)),
                    execution_time_ms: None,
                    backend: Some(backend.name().to_string()),
                };

                Ok(Json(ApiResponse::success(response)))
            }
            Err(e) => {
                let _response = DataResponse {
                    operation_id: Uuid::new_v4().to_string(),
                    success: false,
                    data: None,
                    execution_time_ms: None,
                    backend: Some(backend.name().to_string()),
                };

                Ok(Json(ApiResponse::error(format!(
                    "Failed to get TTL for key {}: {}",
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

/// Set TTL for a key
pub async fn set_ttl(
    Path(key): Path<String>,
    State(router): State<Arc<BackendRouter>>,
    Extension(rbac_context): Extension<RbacContext>,
    Json(request): Json<SetTtlRequest>,
) -> Result<Json<ApiResponse<DataResponse>>, StatusCode> {
    // Check StringSet permission
    if let Err(_) = rbac_context
        .rbac_service
        .check_user_permission(
            &rbac_context.user_id,
            PermissionType::StringSet,
            rbac_context.clone(),
        )
        .await
    {
        return Err(StatusCode::FORBIDDEN);
    }

    let operation = DataOperation::SetTtl {
        key: key.clone(),
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
                    execution_time_ms: None,
                    backend: Some(backend.name().to_string()),
                };

                Ok(Json(ApiResponse::success(response)))
            }
            Err(e) => {
                let _response = DataResponse {
                    operation_id: Uuid::new_v4().to_string(),
                    success: false,
                    data: None,
                    execution_time_ms: None,
                    backend: Some(backend.name().to_string()),
                };

                Ok(Json(ApiResponse::error(format!(
                    "Failed to set TTL for key {}: {}",
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

/// Increment a numeric value
pub async fn increment_data(
    Path(key): Path<String>,
    State(router): State<Arc<BackendRouter>>,
    Extension(rbac_context): Extension<RbacContext>,
    Json(request): Json<IncrementRequest>,
) -> Result<Json<ApiResponse<DataResponse>>, StatusCode> {
    // Check StringSet permission
    if let Err(_) = rbac_context
        .rbac_service
        .check_user_permission(
            &rbac_context.user_id,
            PermissionType::StringSet,
            rbac_context.clone(),
        )
        .await
    {
        return Err(StatusCode::FORBIDDEN);
    }

    let operation = DataOperation::Increment {
        key: key.clone(),
        amount: request.amount.unwrap_or(1),
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
                    execution_time_ms: None,
                    backend: Some(backend.name().to_string()),
                };

                Ok(Json(ApiResponse::success(response)))
            }
            Err(e) => {
                let _response = DataResponse {
                    operation_id: Uuid::new_v4().to_string(),
                    success: false,
                    data: None,
                    execution_time_ms: None,
                    backend: Some(backend.name().to_string()),
                };

                Ok(Json(ApiResponse::error(format!(
                    "Failed to increment key {}: {}",
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

/// Decrement a numeric value
pub async fn decrement_data(
    Path(key): Path<String>,
    State(router): State<Arc<BackendRouter>>,
    Extension(rbac_context): Extension<RbacContext>,
    Json(request): Json<DecrementRequest>,
) -> Result<Json<ApiResponse<DataResponse>>, StatusCode> {
    // Check StringSet permission
    if let Err(_) = rbac_context
        .rbac_service
        .check_user_permission(
            &rbac_context.user_id,
            PermissionType::StringSet,
            rbac_context.clone(),
        )
        .await
    {
        return Err(StatusCode::FORBIDDEN);
    }

    let operation = DataOperation::Decrement {
        key: key.clone(),
        amount: request.amount.unwrap_or(1),
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
                    execution_time_ms: None,
                    backend: Some(backend.name().to_string()),
                };

                Ok(Json(ApiResponse::success(response)))
            }
            Err(e) => {
                let _response = DataResponse {
                    operation_id: Uuid::new_v4().to_string(),
                    success: false,
                    data: None,
                    execution_time_ms: None,
                    backend: Some(backend.name().to_string()),
                };

                Ok(Json(ApiResponse::error(format!(
                    "Failed to decrement key {}: {}",
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

/// Append to a string value
pub async fn append_data(
    Path(key): Path<String>,
    State(router): State<Arc<BackendRouter>>,
    Extension(rbac_context): Extension<RbacContext>,
    Json(request): Json<AppendRequest>,
) -> Result<Json<ApiResponse<DataResponse>>, StatusCode> {
    // Check StringSet permission
    if let Err(_) = rbac_context
        .rbac_service
        .check_user_permission(
            &rbac_context.user_id,
            PermissionType::StringSet,
            rbac_context.clone(),
        )
        .await
    {
        return Err(StatusCode::FORBIDDEN);
    }

    let operation = DataOperation::Append {
        key: key.clone(),
        value: request.value,
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
                    execution_time_ms: None,
                    backend: Some(backend.name().to_string()),
                };

                Ok(Json(ApiResponse::success(response)))
            }
            Err(e) => Ok(Json(ApiResponse::error(format!(
                "Failed to append to key {}: {}",
                key, e
            )))),
        },
        Err(e) => Ok(Json(ApiResponse::error(format!(
            "Failed to route operation for key {}: {}",
            key, e
        )))),
    }
}

/// Compare and swap operation
pub async fn compare_and_swap_data(
    Path(key): Path<String>,
    State(router): State<Arc<BackendRouter>>,
    Extension(rbac_context): Extension<RbacContext>,
    Json(request): Json<CompareAndSwapRequest>,
) -> Result<Json<ApiResponse<DataResponse>>, StatusCode> {
    // Check StringSet permission
    if let Err(_) = rbac_context
        .rbac_service
        .check_user_permission(
            &rbac_context.user_id,
            PermissionType::StringSet,
            rbac_context.clone(),
        )
        .await
    {
        return Err(StatusCode::FORBIDDEN);
    }

    let operation = DataOperation::CompareAndSwap {
        key: key.clone(),
        expected_value: request.expected_value,
        new_value: request.new_value,
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
                    execution_time_ms: None,
                    backend: Some(backend.name().to_string()),
                };

                Ok(Json(ApiResponse::success(response)))
            }
            Err(e) => Ok(Json(ApiResponse::error(format!(
                "Failed to compare and swap key {}: {}",
                key, e
            )))),
        },
        Err(e) => Ok(Json(ApiResponse::error(format!(
            "Failed to route operation for key {}: {}",
            key, e
        )))),
    }
}

/// Get length of a value
pub async fn length_data(
    Path(key): Path<String>,
    State(router): State<Arc<BackendRouter>>,
    Extension(rbac_context): Extension<RbacContext>,
) -> Result<Json<ApiResponse<DataResponse>>, StatusCode> {
    // Check StringGet permission
    if let Err(_) = rbac_context
        .rbac_service
        .check_user_permission(
            &rbac_context.user_id,
            PermissionType::StringGet,
            rbac_context.clone(),
        )
        .await
    {
        return Err(StatusCode::FORBIDDEN);
    }

    let operation = DataOperation::Length { key: key.clone() };

    match router.route_data_operation(&operation).await {
        Ok(backend) => match backend.execute_data(operation).await {
            Ok(result) => {
                let response = DataResponse {
                    operation_id: result.operation_id.to_string(),
                    success: result.success,
                    data: result
                        .data
                        .map(|d| serde_json::to_value(d).unwrap_or(serde_json::Value::Null)),
                    execution_time_ms: None,
                    backend: Some(backend.name().to_string()),
                };

                Ok(Json(ApiResponse::success(response)))
            }
            Err(e) => Ok(Json(ApiResponse::error(format!(
                "Failed to get length for key {}: {}",
                key, e
            )))),
        },
        Err(e) => Ok(Json(ApiResponse::error(format!(
            "Failed to route operation for key {}: {}",
            key, e
        )))),
    }
}

/// Perform batch operations
pub async fn batch_operations(
    State(router): State<Arc<BackendRouter>>,
    Extension(rbac_context): Extension<RbacContext>,
    Json(request): Json<BatchDataRequest>,
) -> Result<Json<ApiResponse<Vec<DataResponse>>>, StatusCode> {
    // Check StringSet permission (batch operations are write operations)
    if let Err(_) = rbac_context
        .rbac_service
        .check_user_permission(
            &rbac_context.user_id,
            PermissionType::StringSet,
            rbac_context.clone(),
        )
        .await
    {
        return Err(StatusCode::FORBIDDEN);
    }

    let mut responses = Vec::new();

    for batch_op in request.operations {
        let operation = match batch_op.operation_type.as_str() {
            "get" => DataOperation::Get {
                key: batch_op.key,
                fields: None,
            },
            "set" => DataOperation::Set {
                key: batch_op.key,
                value: batch_op
                    .value
                    .map(json_to_data_value)
                    .unwrap_or(DataValue::Null),
                ttl: batch_op.ttl,
            },
            "delete" => DataOperation::Delete {
                key: batch_op.key,
                fields: None,
            },
            "update" => DataOperation::Update {
                key: batch_op.key,
                fields: batch_op
                    .fields
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(k, v)| (k, json_to_data_value(v)))
                    .collect(),
                ttl: batch_op.ttl,
            },
            _ => {
                return Err(StatusCode::BAD_REQUEST);
            }
        };

        responses.push(operation);
    }

    let batch_operation = DataOperation::Batch {
        operations: responses,
    };

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

/// Method not allowed handler
async fn method_not_allowed() -> (StatusCode, Json<ApiResponse<()>>) {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        Json(ApiResponse::error("Method not allowed".to_string())),
    )
}

/// Create routes for data operations
pub fn create_data_routes() -> Router<Arc<BackendRouter>> {
    use axum::routing::MethodRouter;

    Router::new()
        .route(
            "/:key",
            MethodRouter::new()
                .get(get_data)
                .post(set_data)
                .put(update_data)
                .delete(delete_data)
                .fallback(method_not_allowed),
        )
        .route(
            "/:key/exists",
            MethodRouter::new()
                .get(check_exists)
                .fallback(method_not_allowed),
        )
        .route(
            "/:key/ttl",
            MethodRouter::new()
                .get(get_ttl)
                .post(set_ttl)
                .fallback(method_not_allowed),
        )
        .route(
            "/:key/incr",
            MethodRouter::new()
                .post(increment_data)
                .fallback(method_not_allowed),
        )
        .route(
            "/:key/decr",
            MethodRouter::new()
                .post(decrement_data)
                .fallback(method_not_allowed),
        )
        .route(
            "/:key/append",
            MethodRouter::new()
                .post(append_data)
                .fallback(method_not_allowed),
        )
        .route(
            "/:key/length",
            MethodRouter::new()
                .get(length_data)
                .fallback(method_not_allowed),
        )
        .route(
            "/:key/cas",
            MethodRouter::new()
                .put(compare_and_swap_data)
                .fallback(method_not_allowed),
        )
        .route(
            "/batch",
            MethodRouter::new()
                .post(batch_operations)
                .fallback(method_not_allowed),
        )
}
