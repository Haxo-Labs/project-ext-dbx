use axum::{extract::State, http::StatusCode, response::Json, routing::post, Router};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::models::ApiResponse;
use dbx_core::{
    DataValue, FilterOperator, QueryFilter, QueryOperation, QueryResult, SortDirection, SortField,
};
use dbx_router::BackendRouter;

#[derive(Debug, Deserialize)]
pub struct ExecuteQueryRequest {
    pub filter: QueryFilter,
    pub projection: Option<Vec<String>>,
    pub sort: Option<Vec<SortField>>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct PatternSearchRequest {
    pub pattern: String,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct TextSearchRequest {
    pub query: String,
    pub fields: Option<Vec<String>>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct QueryResponse {
    pub query_id: String,
    pub success: bool,
    pub results: Vec<QueryResultItemResponse>,
    pub total_count: Option<usize>,
    pub execution_time_ms: Option<u64>,
    pub backend: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct QueryResultItemResponse {
    pub key: String,
    pub data: serde_json::Value,
    pub score: Option<f64>,
}

pub fn create_query_routes() -> Router<Arc<BackendRouter>> {
    Router::new()
        .route("/execute", post(execute_query))
        .route("/pattern", post(pattern_search))
        .route("/text", post(text_search))
}

async fn execute_query(
    State(router): State<Arc<BackendRouter>>,
    Json(request): Json<ExecuteQueryRequest>,
) -> Result<Json<ApiResponse<QueryResponse>>, StatusCode> {
    let operation = QueryOperation {
        id: uuid::Uuid::new_v4(),
        filter: request.filter,
        projection: request.projection,
        sort: request.sort,
        limit: request.limit,
        offset: request.offset,
    };

    match router.route_query_operation(&operation).await {
        Ok(backend) => match backend.execute_query(operation).await {
            Ok(result) => {
                let response = QueryResponse {
                    query_id: result.query_id.to_string(),
                    success: result.success,
                    results: result
                        .results
                        .into_iter()
                        .map(|item| QueryResultItemResponse {
                            key: item.key,
                            data: data_value_to_json(item.data),
                            score: item.score,
                        })
                        .collect(),
                    total_count: result.total_count,
                    execution_time_ms: result.metadata.as_ref().map(|m| m.execution_time_ms),
                    backend: result.metadata.as_ref().map(|m| m.backend.clone()),
                };
                Ok(Json(ApiResponse::success(response)))
            }
            Err(e) => Ok(Json(ApiResponse::error(format!(
                "Failed to execute query: {}",
                e
            )))),
        },
        Err(e) => Ok(Json(ApiResponse::error(format!(
            "Failed to route query: {}",
            e
        )))),
    }
}

async fn pattern_search(
    State(router): State<Arc<BackendRouter>>,
    Json(request): Json<PatternSearchRequest>,
) -> Result<Json<ApiResponse<QueryResponse>>, StatusCode> {
    let operation = QueryOperation {
        id: uuid::Uuid::new_v4(),
        filter: QueryFilter::KeyPattern {
            pattern: request.pattern,
        },
        projection: None,
        sort: None,
        limit: request.limit,
        offset: request.offset,
    };

    match router.route_query_operation(&operation).await {
        Ok(backend) => match backend.execute_query(operation).await {
            Ok(result) => {
                let response = QueryResponse {
                    query_id: result.query_id.to_string(),
                    success: result.success,
                    results: result
                        .results
                        .into_iter()
                        .map(|item| QueryResultItemResponse {
                            key: item.key,
                            data: data_value_to_json(item.data),
                            score: item.score,
                        })
                        .collect(),
                    total_count: result.total_count,
                    execution_time_ms: result.metadata.as_ref().map(|m| m.execution_time_ms),
                    backend: result.metadata.as_ref().map(|m| m.backend.clone()),
                };
                Ok(Json(ApiResponse::success(response)))
            }
            Err(e) => Ok(Json(ApiResponse::error(format!(
                "Failed to execute pattern search: {}",
                e
            )))),
        },
        Err(e) => Ok(Json(ApiResponse::error(format!(
            "Failed to route pattern search: {}",
            e
        )))),
    }
}

async fn text_search(
    State(router): State<Arc<BackendRouter>>,
    Json(request): Json<TextSearchRequest>,
) -> Result<Json<ApiResponse<QueryResponse>>, StatusCode> {
    let operation = QueryOperation {
        id: uuid::Uuid::new_v4(),
        filter: QueryFilter::TextSearch {
            query: request.query,
            fields: request.fields,
        },
        projection: None,
        sort: None,
        limit: request.limit,
        offset: request.offset,
    };

    match router.route_query_operation(&operation).await {
        Ok(backend) => match backend.execute_query(operation).await {
            Ok(result) => {
                let response = QueryResponse {
                    query_id: result.query_id.to_string(),
                    success: result.success,
                    results: result
                        .results
                        .into_iter()
                        .map(|item| QueryResultItemResponse {
                            key: item.key,
                            data: data_value_to_json(item.data),
                            score: item.score,
                        })
                        .collect(),
                    total_count: result.total_count,
                    execution_time_ms: result.metadata.as_ref().map(|m| m.execution_time_ms),
                    backend: result.metadata.as_ref().map(|m| m.backend.clone()),
                };
                Ok(Json(ApiResponse::success(response)))
            }
            Err(e) => Ok(Json(ApiResponse::error(format!(
                "Failed to execute text search: {}",
                e
            )))),
        },
        Err(e) => Ok(Json(ApiResponse::error(format!(
            "Failed to route text search: {}",
            e
        )))),
    }
}

fn data_value_to_json(value: DataValue) -> serde_json::Value {
    match value {
        DataValue::Null => serde_json::Value::Null,
        DataValue::Bool(b) => serde_json::Value::Bool(b),
        DataValue::Int(i) => serde_json::Value::Number(serde_json::Number::from(i)),
        DataValue::Float(f) => serde_json::Value::Number(
            serde_json::Number::from_f64(f).unwrap_or(serde_json::Number::from(0)),
        ),
        DataValue::String(s) => serde_json::Value::String(s),
        DataValue::Bytes(b) => {
            serde_json::Value::String(base64::prelude::BASE64_STANDARD.encode(b))
        }
        DataValue::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(data_value_to_json).collect())
        }
        DataValue::Object(obj) => serde_json::Value::Object(
            obj.into_iter()
                .map(|(k, v)| (k, data_value_to_json(v)))
                .collect(),
        ),
    }
}
