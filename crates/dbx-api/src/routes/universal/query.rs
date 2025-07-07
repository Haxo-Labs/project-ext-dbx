use axum::{
    extract::{Json, Query, State},
    http::StatusCode,
    response::Json as ResponseJson,
    routing::post,
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error};

use dbx_core::{
    DataValue, FilterCondition, FilterOperator, QueryOperation, QueryResult, SortDirection,
    SortOrder,
};
use dbx_router::BackendRouter;

use crate::models::ApiResponse;

/// Universal query request
#[derive(Debug, Serialize, Deserialize)]
pub struct QueryRequest {
    pub filters: Option<Vec<QueryFilter>>,
    pub sort: Option<Vec<QuerySort>>,
    pub limit: Option<u64>,
    pub offset: Option<u64>,
    pub projection: Option<Vec<String>>,
    pub aggregations: Option<Vec<QueryAggregation>>,
}

/// Query filter condition
#[derive(Debug, Serialize, Deserialize)]
pub struct QueryFilter {
    pub field: String,
    pub operator: String, // "eq", "ne", "gt", "gte", "lt", "lte", "in", "nin", "contains", "starts_with", "ends_with"
    pub value: DataValue,
}

/// Query sort order
#[derive(Debug, Serialize, Deserialize)]
pub struct QuerySort {
    pub field: String,
    pub direction: String, // "asc", "desc"
}

/// Query aggregation
#[derive(Debug, Serialize, Deserialize)]
pub struct QueryAggregation {
    pub operation: String, // "count", "sum", "avg", "min", "max"
    pub field: Option<String>,
    pub alias: Option<String>,
}

/// Universal query response
#[derive(Debug, Serialize, Deserialize)]
pub struct QueryResponse {
    pub success: bool,
    pub data: Vec<QueryResultItem>,
    pub total_count: Option<u64>,
    pub metadata: Option<QueryMetadata>,
    pub error: Option<String>,
}

/// Query result item
#[derive(Debug, Serialize, Deserialize)]
pub struct QueryResultItem {
    pub id: Option<String>,
    pub data: HashMap<String, DataValue>,
    pub score: Option<f64>,
}

/// Query response metadata
#[derive(Debug, Serialize, Deserialize)]
pub struct QueryMetadata {
    pub backend_used: String,
    pub execution_time_ms: u64,
    pub rows_examined: Option<u64>,
    pub index_used: Option<String>,
    pub query_plan: Option<String>,
}

/// Pattern search request
#[derive(Debug, Serialize, Deserialize)]
pub struct PatternSearchRequest {
    pub pattern: String,
    pub limit: Option<u64>,
    pub fields: Option<Vec<String>>,
}

/// Text search request
#[derive(Debug, Serialize, Deserialize)]
pub struct TextSearchRequest {
    pub query: String,
    pub fields: Option<Vec<String>>,
    pub fuzzy: Option<bool>,
    pub limit: Option<u64>,
    pub min_score: Option<f64>,
}

// =========================
// Universal Query Handlers
// =========================

/// POST /api/v1/query - Execute complex query
pub async fn execute_query(
    State(router): State<Arc<BackendRouter>>,
    Json(request): Json<QueryRequest>,
) -> Result<ResponseJson<ApiResponse<QueryResponse>>, StatusCode> {
    debug!("Universal QUERY operation");

    let operation = build_query_operation(request)?;

    match execute_query_operation(&router, operation).await {
        Ok((result, backend_name, duration)) => {
            let items = result
                .items
                .into_iter()
                .map(|item| QueryResultItem {
                    id: item.id,
                    data: item.data,
                    score: item.score,
                })
                .collect();

            let response = QueryResponse {
                success: true,
                data: items,
                total_count: result.total_count,
                metadata: Some(QueryMetadata {
                    backend_used: backend_name,
                    execution_time_ms: duration,
                    rows_examined: result.metadata.as_ref().and_then(|m| m.rows_examined),
                    index_used: result.metadata.as_ref().and_then(|m| m.index_used.clone()),
                    query_plan: result
                        .metadata
                        .as_ref()
                        .and_then(|m| m.execution_plan.clone()),
                }),
                error: None,
            };

            Ok(ResponseJson(ApiResponse::success(response)))
        }
        Err(e) => {
            error!(error = %e, "QUERY operation failed");
            Ok(ResponseJson(ApiResponse::error(format!(
                "Failed to execute query: {}",
                e
            ))))
        }
    }
}

/// POST /api/v1/query/pattern - Pattern-based search
pub async fn pattern_search(
    State(router): State<Arc<BackendRouter>>,
    Json(request): Json<PatternSearchRequest>,
) -> Result<ResponseJson<ApiResponse<QueryResponse>>, StatusCode> {
    debug!(pattern = %request.pattern, "Universal PATTERN search");

    let operation = QueryOperation::PatternSearch {
        pattern: request.pattern,
        limit: request.limit,
        projection: request.fields,
    };

    match execute_query_operation(&router, operation).await {
        Ok((result, backend_name, duration)) => {
            let items = result
                .items
                .into_iter()
                .map(|item| QueryResultItem {
                    id: item.id,
                    data: item.data,
                    score: item.score,
                })
                .collect();

            let response = QueryResponse {
                success: true,
                data: items,
                total_count: result.total_count,
                metadata: Some(QueryMetadata {
                    backend_used: backend_name,
                    execution_time_ms: duration,
                    rows_examined: result.metadata.as_ref().and_then(|m| m.rows_examined),
                    index_used: result.metadata.as_ref().and_then(|m| m.index_used.clone()),
                    query_plan: result
                        .metadata
                        .as_ref()
                        .and_then(|m| m.execution_plan.clone()),
                }),
                error: None,
            };

            Ok(ResponseJson(ApiResponse::success(response)))
        }
        Err(e) => {
            error!(pattern = %request.pattern, error = %e, "PATTERN search failed");
            Ok(ResponseJson(ApiResponse::error(format!(
                "Failed to execute pattern search: {}",
                e
            ))))
        }
    }
}

/// POST /api/v1/query/search - Text-based search
pub async fn text_search(
    State(router): State<Arc<BackendRouter>>,
    Json(request): Json<TextSearchRequest>,
) -> Result<ResponseJson<ApiResponse<QueryResponse>>, StatusCode> {
    debug!(query = %request.query, "Universal TEXT search");

    let operation = QueryOperation::TextSearch {
        query: request.query,
        fields: request.fields,
        fuzzy: request.fuzzy.unwrap_or(false),
        limit: request.limit,
        min_score: request.min_score,
    };

    match execute_query_operation(&router, operation).await {
        Ok((result, backend_name, duration)) => {
            let items = result
                .items
                .into_iter()
                .map(|item| QueryResultItem {
                    id: item.id,
                    data: item.data,
                    score: item.score,
                })
                .collect();

            let response = QueryResponse {
                success: true,
                data: items,
                total_count: result.total_count,
                metadata: Some(QueryMetadata {
                    backend_used: backend_name,
                    execution_time_ms: duration,
                    rows_examined: result.metadata.as_ref().and_then(|m| m.rows_examined),
                    index_used: result.metadata.as_ref().and_then(|m| m.index_used.clone()),
                    query_plan: result
                        .metadata
                        .as_ref()
                        .and_then(|m| m.execution_plan.clone()),
                }),
                error: None,
            };

            Ok(ResponseJson(ApiResponse::success(response)))
        }
        Err(e) => {
            error!(query = %request.query, error = %e, "TEXT search failed");
            Ok(ResponseJson(ApiResponse::error(format!(
                "Failed to execute text search: {}",
                e
            ))))
        }
    }
}

// =========================
// Helper Functions
// =========================

/// Build QueryOperation from request
fn build_query_operation(request: QueryRequest) -> Result<QueryOperation, StatusCode> {
    let filters = if let Some(filter_list) = request.filters {
        let mut conditions = Vec::new();
        for filter in filter_list {
            let operator = match filter.operator.as_str() {
                "eq" => FilterOperator::Equal,
                "ne" => FilterOperator::NotEqual,
                "gt" => FilterOperator::GreaterThan,
                "gte" => FilterOperator::GreaterThanOrEqual,
                "lt" => FilterOperator::LessThan,
                "lte" => FilterOperator::LessThanOrEqual,
                "in" => FilterOperator::In,
                "nin" => FilterOperator::NotIn,
                "contains" => FilterOperator::Contains,
                "starts_with" => FilterOperator::StartsWith,
                "ends_with" => FilterOperator::EndsWith,
                _ => return Err(StatusCode::BAD_REQUEST),
            };

            conditions.push(FilterCondition {
                field: filter.field,
                operator,
                value: filter.value,
            });
        }
        Some(conditions)
    } else {
        None
    };

    let sort = if let Some(sort_list) = request.sort {
        let mut orders = Vec::new();
        for sort_item in sort_list {
            let direction = match sort_item.direction.as_str() {
                "asc" => SortDirection::Ascending,
                "desc" => SortDirection::Descending,
                _ => return Err(StatusCode::BAD_REQUEST),
            };

            orders.push(SortOrder {
                field: sort_item.field,
                direction,
            });
        }
        Some(orders)
    } else {
        None
    };

    Ok(QueryOperation::StructuredQuery {
        filters,
        sort,
        limit: request.limit,
        offset: request.offset,
        projection: request.projection,
        aggregations: None, // TODO: Implement aggregations mapping
    })
}

/// Execute query operation and measure performance
async fn execute_query_operation(
    router: &BackendRouter,
    operation: QueryOperation,
) -> Result<(QueryResult, String, u64), dbx_core::DbxError> {
    let start_time = std::time::Instant::now();

    // Route the operation to appropriate backend
    let backend = router.route_query_operation(&operation).await?;
    let backend_name = backend.name().to_string();

    // Execute the operation
    let result = backend.execute_query(operation).await?;

    let duration = start_time.elapsed().as_millis() as u64;

    Ok((result, backend_name, duration))
}

/// Create universal query routes
pub fn create_universal_query_routes(router: Arc<BackendRouter>) -> Router {
    Router::new()
        .route("/query", post(execute_query))
        .route("/query/pattern", post(pattern_search))
        .route("/query/search", post(text_search))
        .with_state(router)
}
