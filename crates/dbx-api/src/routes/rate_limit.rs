use crate::{
    middleware::{RateLimitPolicy, RateLimitService},
    models::{ApiResponse, RbacContext},
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize)]
pub struct RateLimitInfo {
    pub identifier: String,
    pub endpoint: String,
    pub allowed: bool,
    pub limit: u32,
    pub remaining: u32,
    pub reset_time: chrono::DateTime<chrono::Utc>,
    pub retry_after: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SetRateLimitPolicyRequest {
    pub endpoint: String,
    pub requests: u32,
    pub window_seconds: u32,
    pub burst_allowance: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RateLimitPolicyResponse {
    pub endpoint: String,
    pub policy: RateLimitPolicyInfo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RateLimitPolicyInfo {
    pub requests: u32,
    pub window_seconds: u32,
    pub burst_allowance: Option<u32>,
}

impl From<RateLimitPolicy> for RateLimitPolicyInfo {
    fn from(policy: RateLimitPolicy) -> Self {
        Self {
            requests: policy.requests,
            window_seconds: policy.window_seconds,
            burst_allowance: policy.burst_allowance,
        }
    }
}

pub fn create_rate_limit_routes() -> Router<Arc<RateLimitService>> {
    Router::new()
        .route("/status/:identifier/:endpoint", get(get_rate_limit_status))
        .route("/policies", get(list_rate_limit_policies))
        .route("/policies", post(set_rate_limit_policy))
        .route("/policies/:endpoint", get(get_rate_limit_policy))
        .route("/policies/:endpoint", put(update_rate_limit_policy))
        .route("/policies/:endpoint", delete(delete_rate_limit_policy))
        .route("/reset/:identifier/:endpoint", post(reset_rate_limit))
        .route("/metrics", get(get_rate_limit_metrics))
}

/// Get current rate limit status for a specific identifier and endpoint
pub async fn get_rate_limit_status(
    State(rate_limit_service): State<Arc<RateLimitService>>,
    Path((identifier, endpoint)): Path<(String, String)>,
    _rbac_context: RbacContext,
) -> Result<Json<ApiResponse<RateLimitInfo>>, (StatusCode, Json<ApiResponse<()>>)> {
    let endpoint_path = format!("/{}", endpoint);

    match rate_limit_service
        .get_rate_limit_info(&identifier, &endpoint_path)
        .await
    {
        Ok(result) => {
            let info = RateLimitInfo {
                identifier,
                endpoint: endpoint_path,
                allowed: result.allowed,
                limit: result.limit,
                remaining: result.remaining,
                reset_time: result.reset_time,
                retry_after: result.retry_after,
            };

            Ok(Json(ApiResponse::success(info)))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::<()>::error(format!(
                "Failed to get rate limit status: {}",
                e
            ))),
        )),
    }
}

/// List all rate limit policies
pub async fn list_rate_limit_policies(
    State(rate_limit_service): State<Arc<RateLimitService>>,
    _rbac_context: RbacContext,
) -> Result<Json<ApiResponse<Vec<RateLimitPolicyResponse>>>, (StatusCode, Json<ApiResponse<()>>)> {
    let policies = rate_limit_service.get_all_policies().await;

    let policy_responses: Vec<RateLimitPolicyResponse> = policies
        .iter()
        .map(|(endpoint, policy)| RateLimitPolicyResponse {
            endpoint: endpoint.clone(),
            policy: RateLimitPolicyInfo {
                requests: policy.requests,
                window_seconds: policy.window_seconds,
                burst_allowance: policy.burst_allowance,
            },
        })
        .collect();

    Ok(Json(ApiResponse::success(policy_responses)))
}

/// Get rate limit policy for a specific endpoint
pub async fn get_rate_limit_policy(
    State(rate_limit_service): State<Arc<RateLimitService>>,
    Path(endpoint): Path<String>,
    _rbac_context: RbacContext,
) -> Result<Json<ApiResponse<RateLimitPolicyResponse>>, (StatusCode, Json<ApiResponse<()>>)> {
    let policy = rate_limit_service.get_policy_for_endpoint(&endpoint).await;

    match policy {
        Some(policy) => {
            let response = RateLimitPolicyResponse {
                endpoint,
                policy: RateLimitPolicyInfo {
                    requests: policy.requests,
                    window_seconds: policy.window_seconds,
                    burst_allowance: policy.burst_allowance,
                },
            };
            Ok(Json(ApiResponse::success(response)))
        }
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::<()>::error(format!(
                "No rate limit policy found for endpoint '{}'",
                endpoint
            ))),
        )),
    }
}

/// Set rate limit policy for an endpoint
pub async fn set_rate_limit_policy(
    State(rate_limit_service): State<Arc<RateLimitService>>,
    _rbac_context: RbacContext,
    Json(request): Json<SetRateLimitPolicyRequest>,
) -> Result<Json<ApiResponse<RateLimitPolicyResponse>>, (StatusCode, Json<ApiResponse<()>>)> {
    if request.requests == 0 || request.window_seconds == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<()>::error(
                "Requests and window_seconds must be greater than 0".to_string(),
            )),
        ));
    }

    let policy = RateLimitPolicy {
        requests: request.requests,
        window_seconds: request.window_seconds,
        burst_allowance: request.burst_allowance,
    };

    rate_limit_service
        .set_endpoint_policy(request.endpoint.clone(), policy.clone())
        .await;

    let response = RateLimitPolicyResponse {
        endpoint: request.endpoint,
        policy: RateLimitPolicyInfo {
            requests: policy.requests,
            window_seconds: policy.window_seconds,
            burst_allowance: policy.burst_allowance,
        },
    };

    Ok(Json(ApiResponse::success(response)))
}

/// Update rate limit policy for an endpoint
pub async fn update_rate_limit_policy(
    State(rate_limit_service): State<Arc<RateLimitService>>,
    Path(endpoint): Path<String>,
    _rbac_context: RbacContext,
    Json(request): Json<SetRateLimitPolicyRequest>,
) -> Result<Json<ApiResponse<RateLimitPolicyResponse>>, (StatusCode, Json<ApiResponse<()>>)> {
    if request.requests == 0 || request.window_seconds == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<()>::error(
                "Requests and window_seconds must be greater than 0".to_string(),
            )),
        ));
    }

    let policy = RateLimitPolicy {
        requests: request.requests,
        window_seconds: request.window_seconds,
        burst_allowance: request.burst_allowance,
    };

    rate_limit_service
        .set_endpoint_policy(endpoint.clone(), policy.clone())
        .await;

    let response = RateLimitPolicyResponse {
        endpoint,
        policy: RateLimitPolicyInfo {
            requests: policy.requests,
            window_seconds: policy.window_seconds,
            burst_allowance: policy.burst_allowance,
        },
    };

    Ok(Json(ApiResponse::success(response)))
}

/// Delete rate limit policy for an endpoint
pub async fn delete_rate_limit_policy(
    State(rate_limit_service): State<Arc<RateLimitService>>,
    Path(endpoint): Path<String>,
    _rbac_context: RbacContext,
) -> Result<Json<ApiResponse<String>>, (StatusCode, Json<ApiResponse<()>>)> {
    let removed = rate_limit_service.remove_endpoint_policy(&endpoint).await;

    if removed {
        Ok(Json(ApiResponse::success(format!(
            "Rate limit policy for endpoint '{}' deleted successfully",
            endpoint
        ))))
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::<()>::error(format!(
                "No rate limit policy found for endpoint '{}'",
                endpoint
            ))),
        ))
    }
}

/// Reset rate limit for a specific identifier and endpoint
pub async fn reset_rate_limit(
    State(rate_limit_service): State<Arc<RateLimitService>>,
    Path((identifier, endpoint)): Path<(String, String)>,
    _rbac_context: RbacContext,
) -> Result<Json<ApiResponse<String>>, (StatusCode, Json<ApiResponse<()>>)> {
    let endpoint_path = format!("/{}", endpoint);

    match rate_limit_service
        .reset_rate_limit(&identifier, &endpoint_path)
        .await
    {
        Ok(()) => Ok(Json(ApiResponse::success(
            "Rate limit reset successfully".to_string(),
        ))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::<()>::error(format!(
                "Failed to reset rate limit: {}",
                e
            ))),
        )),
    }
}

/// Get rate limiting metrics
pub async fn get_rate_limit_metrics(
    State(rate_limit_service): State<Arc<RateLimitService>>,
    _rbac_context: RbacContext,
) -> Result<Json<ApiResponse<RateLimitMetrics>>, (StatusCode, Json<ApiResponse<()>>)> {
    let policies = rate_limit_service.get_all_policies().await;
    let policies_count = policies.len() as u32;

    // Add global policy if exists
    let global_policy = rate_limit_service.global_policy.read().await;
    let total_policies = if global_policy.is_some() {
        policies_count + 1
    } else {
        policies_count
    };

    // Count active rate limiters by scanning Redis keys
    let active_limiters = match rate_limit_service.count_active_limiters().await {
        Ok(count) => count,
        Err(_) => 0, // Graceful degradation if Redis is unavailable
    };

    let metrics = RateLimitMetrics {
        total_requests: 0,        // Requires additional tracking infrastructure
        rate_limited_requests: 0, // Requires additional tracking infrastructure
        policies_count: total_policies,
        active_limiters,
    };

    Ok(Json(ApiResponse::success(metrics)))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RateLimitMetrics {
    pub total_requests: u64,
    pub rate_limited_requests: u64,
    pub policies_count: u32,
    pub active_limiters: u32,
}
