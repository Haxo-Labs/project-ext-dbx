use crate::models::{ApiResponse, RateLimitPolicy};
use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json},
};
use chrono::{DateTime, Utc};
use dbx_core::{DataOperation, DataValue, UniversalBackend};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};

#[derive(Debug, Clone, PartialEq)]
pub struct RateLimitResult {
    pub allowed: bool,
    pub limit: u32,
    pub remaining: u32,
    pub reset_time: DateTime<Utc>,
    pub retry_after: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct RateLimitContext {
    pub identifier: String,
    pub policy: RateLimitPolicy,
    pub endpoint: String,
}

#[derive(Clone)]
pub struct SlidingWindowRateLimiter {
    backend: Arc<dyn UniversalBackend>,
}

impl SlidingWindowRateLimiter {
    pub fn new(backend: Arc<dyn UniversalBackend>) -> Self {
        Self { backend }
    }

    pub async fn check_rate_limit(
        &self,
        context: &RateLimitContext,
    ) -> Result<RateLimitResult, String> {
        let now = Utc::now();
        let window_start = now - chrono::Duration::seconds(context.policy.window_seconds as i64);

        let key = format!("rate_limit:{}:{}", context.identifier, context.endpoint);

        // Get existing timestamps for this identifier/endpoint
        let existing_timestamps = self.get_request_timestamps(&key).await?;

        // Filter timestamps to only include those within the sliding window
        let valid_timestamps: Vec<i64> = existing_timestamps
            .into_iter()
            .filter(|&timestamp| timestamp >= window_start.timestamp())
            .collect();

        let current_request_count = valid_timestamps.len() as u32;
        let effective_limit = context
            .policy
            .burst_allowance
            .unwrap_or(context.policy.requests);

        // Check if we're at the limit
        if current_request_count >= effective_limit {
            // Find the oldest request in the window to determine reset time
            let now_timestamp = now.timestamp();
            let oldest_timestamp = valid_timestamps.iter().min().unwrap_or(&now_timestamp);
            let reset_time = DateTime::from_timestamp(
                oldest_timestamp + context.policy.window_seconds as i64,
                0,
            )
            .unwrap_or(now + chrono::Duration::seconds(context.policy.window_seconds as i64));

            let retry_after = (reset_time - now).num_seconds().max(1) as u32;

            return Ok(RateLimitResult {
                allowed: false,
                limit: context.policy.requests,
                remaining: 0,
                reset_time,
                retry_after: Some(retry_after),
            });
        }

        // Add current request timestamp
        let mut updated_timestamps = valid_timestamps;
        updated_timestamps.push(now.timestamp());

        // Store updated timestamps
        self.store_request_timestamps(&key, &updated_timestamps, context.policy.window_seconds)
            .await?;

        let remaining = context
            .policy
            .requests
            .saturating_sub(updated_timestamps.len() as u32);
        let reset_time = now + chrono::Duration::seconds(context.policy.window_seconds as i64);

        Ok(RateLimitResult {
            allowed: true,
            limit: context.policy.requests,
            remaining,
            reset_time,
            retry_after: None,
        })
    }

    pub async fn reset_rate_limit(&self, identifier: &str, endpoint: &str) -> Result<(), String> {
        let key = format!("rate_limit:{}:{}", identifier, endpoint);

        match self
            .backend
            .execute_data(DataOperation::Delete { key, fields: None })
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("Reset error: {}", e)),
        }
    }

    pub async fn get_rate_limit_info(
        &self,
        identifier: &str,
        endpoint: &str,
        policy: &RateLimitPolicy,
    ) -> Result<RateLimitResult, String> {
        let context = RateLimitContext {
            identifier: identifier.to_string(),
            policy: policy.clone(),
            endpoint: endpoint.to_string(),
        };

        // Get current status without incrementing (read-only check)
        let now = Utc::now();
        let window_start = now - chrono::Duration::seconds(policy.window_seconds as i64);
        let key = format!("rate_limit:{}:{}", identifier, endpoint);

        let existing_timestamps = self.get_request_timestamps(&key).await?;

        let valid_timestamps: Vec<i64> = existing_timestamps
            .into_iter()
            .filter(|&timestamp| timestamp >= window_start.timestamp())
            .collect();

        let current_request_count = valid_timestamps.len() as u32;
        let remaining = policy.requests.saturating_sub(current_request_count);

        let reset_time = if let Some(&oldest) = valid_timestamps.iter().min() {
            DateTime::from_timestamp(oldest + policy.window_seconds as i64, 0)
                .unwrap_or(now + chrono::Duration::seconds(policy.window_seconds as i64))
        } else {
            now + chrono::Duration::seconds(policy.window_seconds as i64)
        };

        Ok(RateLimitResult {
            allowed: current_request_count < policy.requests,
            limit: policy.requests,
            remaining,
            reset_time,
            retry_after: None,
        })
    }

    async fn get_request_timestamps(&self, key: &str) -> Result<Vec<i64>, String> {
        match self
            .backend
            .execute_data(DataOperation::Get {
                key: key.to_string(),
                fields: None,
            })
            .await
        {
            Ok(result) => {
                if result.success {
                    if let Some(DataValue::String(timestamps_str)) = result.data {
                        // Parse comma-separated timestamps
                        if timestamps_str.is_empty() {
                            Ok(Vec::new())
                        } else {
                            timestamps_str
                                .split(',')
                                .map(|s| {
                                    s.parse::<i64>().map_err(|e| format!("Parse error: {}", e))
                                })
                                .collect()
                        }
                    } else {
                        Ok(Vec::new())
                    }
                } else {
                    Ok(Vec::new())
                }
            }
            Err(e) => Err(format!("Backend error: {}", e)),
        }
    }

    async fn store_request_timestamps(
        &self,
        key: &str,
        timestamps: &[i64],
        window_seconds: u32,
    ) -> Result<(), String> {
        let timestamps_str = timestamps
            .iter()
            .map(|t| t.to_string())
            .collect::<Vec<_>>()
            .join(",");

        match self
            .backend
            .execute_data(DataOperation::Set {
                key: key.to_string(),
                value: DataValue::String(timestamps_str),
                ttl: Some(window_seconds as u64 * 2), // Keep data longer than window for safety
            })
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("Storage error: {}", e)),
        }
    }

    pub async fn increment_active_limiters(&self) -> Result<(), String> {
        let key = "rate_limit:active_count".to_string();
        match self
            .backend
            .execute_data(DataOperation::Get {
                key: key.clone(),
                fields: None,
            })
            .await
        {
            Ok(result) => {
                let current_count = if result.success {
                    if let Some(DataValue::String(count_str)) = result.data {
                        count_str.parse::<i64>().unwrap_or(0)
                    } else if let Some(DataValue::Int(count)) = result.data {
                        count
                    } else {
                        0
                    }
                } else {
                    0
                };

                self.backend
                    .execute_data(DataOperation::Set {
                        key,
                        value: DataValue::Int(current_count + 1),
                        ttl: None,
                    })
                    .await
                    .map_err(|e| format!("Increment error: {}", e))?;

                Ok(())
            }
            Err(e) => Err(format!("Get count error: {}", e)),
        }
    }

    pub async fn decrement_active_limiters(&self) -> Result<(), String> {
        let key = "rate_limit:active_count".to_string();
        match self
            .backend
            .execute_data(DataOperation::Get {
                key: key.clone(),
                fields: None,
            })
            .await
        {
            Ok(result) => {
                let current_count = if result.success {
                    if let Some(DataValue::String(count_str)) = result.data {
                        count_str.parse::<i64>().unwrap_or(0)
                    } else if let Some(DataValue::Int(count)) = result.data {
                        count
                    } else {
                        0
                    }
                } else {
                    0
                };

                let new_count = (current_count - 1).max(0);

                self.backend
                    .execute_data(DataOperation::Set {
                        key,
                        value: DataValue::Int(new_count),
                        ttl: None,
                    })
                    .await
                    .map_err(|e| format!("Decrement error: {}", e))?;

                Ok(())
            }
            Err(e) => Err(format!("Get count error: {}", e)),
        }
    }

    pub async fn count_active_limiters(&self) -> Result<i64, String> {
        let key = "rate_limit:active_count".to_string();
        match self
            .backend
            .execute_data(DataOperation::Get { key, fields: None })
            .await
        {
            Ok(result) => {
                if result.success {
                    if let Some(DataValue::String(count_str)) = result.data {
                        Ok(count_str.parse::<i64>().unwrap_or(0))
                    } else if let Some(DataValue::Int(count)) = result.data {
                        Ok(count)
                    } else {
                        Ok(0)
                    }
                } else {
                    Ok(0)
                }
            }
            Err(e) => Err(format!("Count error: {}", e)),
        }
    }
}

#[derive(Clone)]
pub struct RateLimitService {
    limiter: SlidingWindowRateLimiter,
    policies: Arc<std::sync::RwLock<HashMap<String, RateLimitPolicy>>>,
    pub global_policy: Arc<std::sync::RwLock<Option<RateLimitPolicy>>>,
}

impl RateLimitService {
    pub fn new(backend: Arc<dyn UniversalBackend>) -> Self {
        Self {
            limiter: SlidingWindowRateLimiter::new(backend),
            policies: Arc::new(std::sync::RwLock::new(HashMap::new())),
            global_policy: Arc::new(std::sync::RwLock::new(None)),
        }
    }

    pub async fn set_global_policy(&self, policy: RateLimitPolicy) {
        *self.global_policy.write().unwrap() = Some(policy);
    }

    pub async fn set_endpoint_policy(&self, endpoint: &str, policy: RateLimitPolicy) {
        self.policies
            .write()
            .unwrap()
            .insert(endpoint.to_string(), policy);
    }

    pub async fn remove_endpoint_policy(&self, endpoint: &str) -> bool {
        self.policies.write().unwrap().remove(endpoint).is_some()
    }

    pub async fn increment_total_requests(&self) -> Result<(), String> {
        let key = "rate_limit:metrics:total_requests";
        let current = self.get_counter_value(key).await.unwrap_or(0);
        let _ = self
            .limiter
            .backend
            .execute_data(DataOperation::Set {
                key: key.to_string(),
                value: DataValue::Int(current + 1),
                ttl: None,
            })
            .await;
        Ok(())
    }

    pub async fn increment_rate_limited_requests(&self) -> Result<(), String> {
        let key = "rate_limit:metrics:rate_limited_requests";
        let current = self.get_counter_value(key).await.unwrap_or(0);
        let _ = self
            .limiter
            .backend
            .execute_data(DataOperation::Set {
                key: key.to_string(),
                value: DataValue::Int(current + 1),
                ttl: None,
            })
            .await;
        Ok(())
    }

    async fn get_counter_value(&self, key: &str) -> Result<i64, String> {
        match self
            .limiter
            .backend
            .execute_data(DataOperation::Get {
                key: key.to_string(),
                fields: None,
            })
            .await
        {
            Ok(result) => {
                if result.success {
                    if let Some(DataValue::Int(count)) = result.data {
                        Ok(count)
                    } else if let Some(DataValue::String(s)) = result.data {
                        s.parse().map_err(|e| format!("Parse error: {}", e))
                    } else {
                        Ok(0)
                    }
                } else {
                    Err(format!("Failed to get counter value for key: {}", key))
                }
            }
            Err(e) => Err(e.to_string()),
        }
    }

    pub async fn get_total_requests(&self) -> Result<u64, String> {
        let count = self
            .get_counter_value("rate_limit:metrics:total_requests")
            .await?;
        Ok(count.max(0) as u64)
    }

    pub async fn get_rate_limited_requests(&self) -> Result<u64, String> {
        let count = self
            .get_counter_value("rate_limit:metrics:rate_limited_requests")
            .await?;
        Ok(count.max(0) as u64)
    }

    pub async fn reset_metrics(&self) -> Result<(), String> {
        let _ = self
            .limiter
            .backend
            .execute_data(DataOperation::Delete {
                key: "rate_limit:metrics:total_requests".to_string(),
                fields: None,
            })
            .await;
        let _ = self
            .limiter
            .backend
            .execute_data(DataOperation::Delete {
                key: "rate_limit:metrics:rate_limited_requests".to_string(),
                fields: None,
            })
            .await;
        Ok(())
    }

    pub async fn get_policy_for_endpoint(&self, endpoint: &str) -> Option<RateLimitPolicy> {
        let policies = self.policies.read().unwrap();
        if let Some(policy) = policies.get(endpoint) {
            Some(policy.clone())
        } else {
            let global = self.global_policy.read().unwrap();
            global.clone()
        }
    }

    pub async fn get_all_policies(&self) -> HashMap<String, RateLimitPolicy> {
        self.policies.read().unwrap().clone()
    }

    pub async fn check_rate_limit(
        &self,
        identifier: &str,
        endpoint: &str,
    ) -> Result<RateLimitResult, String> {
        let policy = self
            .get_policy_for_endpoint(endpoint)
            .await
            .ok_or_else(|| "No rate limit policy configured".to_string())?;

        let context = RateLimitContext {
            identifier: identifier.to_string(),
            policy: policy.clone(),
            endpoint: endpoint.to_string(),
        };

        self.limiter.check_rate_limit(&context).await
    }

    pub async fn reset_rate_limit(&self, identifier: &str, endpoint: &str) -> Result<(), String> {
        self.limiter.reset_rate_limit(identifier, endpoint).await
    }

    pub async fn get_rate_limit_info(
        &self,
        identifier: &str,
        endpoint: &str,
    ) -> Result<RateLimitResult, String> {
        let policy = self
            .get_policy_for_endpoint(endpoint)
            .await
            .ok_or_else(|| "No rate limit policy configured".to_string())?;

        self.limiter
            .get_rate_limit_info(identifier, endpoint, &policy)
            .await
    }

    pub async fn count_active_limiters(&self) -> Result<u32, String> {
        // Track active limiters by maintaining a count in the backend
        let active_count = self
            .get_counter_value("rate_limit:metrics:active_limiters")
            .await?;
        Ok(active_count.max(0) as u32)
    }

    pub async fn increment_active_limiters(&self) -> Result<(), String> {
        let key = "rate_limit:metrics:active_limiters";
        let current = self.get_counter_value(key).await.unwrap_or(0);
        let _ = self
            .limiter
            .backend
            .execute_data(DataOperation::Set {
                key: key.to_string(),
                value: DataValue::Int(current + 1),
                ttl: None,
            })
            .await;
        Ok(())
    }

    pub async fn decrement_active_limiters(&self) -> Result<(), String> {
        let key = "rate_limit:metrics:active_limiters";
        let current = self.get_counter_value(key).await.unwrap_or(0);
        let new_count = (current - 1).max(0);
        let _ = self
            .limiter
            .backend
            .execute_data(DataOperation::Set {
                key: key.to_string(),
                value: DataValue::Int(new_count),
                ttl: None,
            })
            .await;
        Ok(())
    }
}

fn extract_identifier_from_request(
    headers: &HeaderMap,
    connect_info: Option<&std::net::SocketAddr>,
    auth_context: Option<&str>,
) -> String {
    // Priority: authenticated user > API key > IP address > unknown
    if let Some(auth_type) = auth_context {
        match auth_type {
            "user" => {
                // Extract user ID from JWT token in Authorization header
                if let Some(auth_header) = headers.get("authorization") {
                    if let Ok(auth_str) = auth_header.to_str() {
                        if auth_str.starts_with("Bearer ") {
                            return format!("user:{}", &auth_str[7..15]); // Use first 8 chars as identifier
                        }
                    }
                }
                "user:unknown".to_string()
            }
            "api_key" => {
                // Extract API key ID from Authorization header
                if let Some(auth_header) = headers.get("authorization") {
                    if let Ok(auth_str) = auth_header.to_str() {
                        if auth_str.starts_with("ApiKey ") {
                            return format!("api_key:{}", &auth_str[7..15]); // Use first 8 chars as identifier
                        }
                    }
                }
                "api_key:unknown".to_string()
            }
            _ => "unknown".to_string(),
        }
    } else if let Some(connect_info) = connect_info {
        // Use IP address as fallback
        format!("ip:{}", connect_info.ip())
    } else {
        "unknown".to_string()
    }
}

pub fn add_rate_limit_headers(response: &mut axum::response::Response, result: &RateLimitResult) {
    let headers = response.headers_mut();

    if let Ok(value) = axum::http::HeaderValue::from_str(&result.limit.to_string()) {
        headers.insert("X-RateLimit-Limit", value);
    }

    if let Ok(value) = axum::http::HeaderValue::from_str(&result.remaining.to_string()) {
        headers.insert("X-RateLimit-Remaining", value);
    }

    if let Ok(value) = axum::http::HeaderValue::from_str(&result.reset_time.timestamp().to_string())
    {
        headers.insert("X-RateLimit-Reset", value);
    }

    if let Some(retry_after) = result.retry_after {
        if let Ok(value) = axum::http::HeaderValue::from_str(&retry_after.to_string()) {
            headers.insert("Retry-After", value);
        }
    }
}

pub async fn rate_limit_middleware(
    State(rate_limit_service): State<Arc<RateLimitService>>,
    connect_info: Option<std::net::SocketAddr>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    let endpoint = request.uri().path().to_string();

    // Track total requests
    let _ = rate_limit_service.increment_total_requests().await;

    // Extract user/API key ID from auth headers
    let auth_identifier = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|auth_header| {
            if auth_header.starts_with("Bearer ") {
                Some("user") // JWT token - would extract user ID from token
            } else if auth_header.starts_with("ApiKey ") {
                Some("api_key") // API Key - would extract API key ID
            } else {
                None
            }
        });

    let identifier =
        extract_identifier_from_request(&headers, connect_info.as_ref(), auth_identifier);

    let rate_limit_result = rate_limit_service
        .check_rate_limit(&identifier, &endpoint)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<()>::error(format!(
                    "Rate limiting error: {}",
                    e
                ))),
            )
        })?;

    if !rate_limit_result.allowed {
        // Track rate-limited requests
        let _ = rate_limit_service.increment_rate_limited_requests().await;

        let mut response = (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ApiResponse::<()>::error("Rate limit exceeded".to_string())),
        )
            .into_response();

        add_rate_limit_headers(&mut response, &rate_limit_result);
        return Ok(response);
    }

    let mut response = next.run(request).await;
    add_rate_limit_headers(&mut response, &rate_limit_result);

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::time::Duration;
    use tokio::time::sleep;

    fn create_test_policy() -> RateLimitPolicy {
        RateLimitPolicy {
            requests: 5,
            window_seconds: 10,
            burst_allowance: Some(7),
        }
    }

    fn create_redis_pool() -> Arc<dyn UniversalBackend> {
        use dbx_adapter::redis::factory::RedisBackendFactory;
        use dbx_config::BackendConfig;
        use dbx_router::BackendFactory;

        let config = BackendConfig {
            provider: "redis".to_string(),
            url: std::env::var("DBX_BACKEND_1_URL")
                .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string()),
            pool_size: Some(1),
            timeout_ms: Some(5000),
            retry_attempts: Some(3),
            retry_delay_ms: Some(1000),
            capabilities: None,
            additional_config: std::collections::HashMap::new(),
        };

        let factory = RedisBackendFactory::new();
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async { factory.create_backend("test", &config).await })
            .unwrap()
    }

    #[tokio::test]
    async fn test_sliding_window_rate_limiter_basic() {
        let redis_pool = create_redis_pool();
        let limiter = SlidingWindowRateLimiter::new(redis_pool.clone());

        let test_prefix = format!(
            "test_basic_{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        );
        let context = RateLimitContext {
            identifier: format!("test_user_basic_{}", test_prefix),
            policy: create_test_policy(),
            endpoint: format!("/api/test_{}", test_prefix),
        };

        // Clean up any existing keys using backend abstraction
        let key = format!("rate_limit:{}:{}", context.identifier, context.endpoint);
        let _ = redis_pool
            .execute_data(DataOperation::Delete {
                key: key.clone(),
                fields: None,
            })
            .await;

        // First few requests should be allowed
        for i in 1..=5 {
            let result = limiter.check_rate_limit(&context).await.unwrap();
            assert!(result.allowed, "Request {} should be allowed", i);
            assert_eq!(result.limit, 5);
            assert_eq!(result.remaining, 5 - i);
        }

        // 6th and 7th requests should be allowed due to burst
        for i in 6..=7 {
            let result = limiter.check_rate_limit(&context).await.unwrap();
            assert!(result.allowed, "Burst request {} should be allowed", i);
        }

        // 8th request should be denied
        let result = limiter.check_rate_limit(&context).await.unwrap();
        assert!(!result.allowed, "Request beyond burst should be denied");
        assert!(result.retry_after.is_some());

        // Cleanup
        let _ = redis_pool
            .execute_data(DataOperation::Delete { key, fields: None })
            .await;
    }

    #[tokio::test]
    async fn test_rate_limit_reset() {
        let redis_pool = create_redis_pool();
        let limiter = SlidingWindowRateLimiter::new(redis_pool.clone());

        let test_prefix = format!("test_reset_{}", chrono::Utc::now().timestamp_nanos());
        let context = RateLimitContext {
            identifier: format!("test_user_reset_{}", test_prefix),
            policy: RateLimitPolicy {
                requests: 2,
                window_seconds: 60,
                burst_allowance: None,
            },
            endpoint: format!("/api/reset_test_{}", test_prefix),
        };

        // Clean up any existing keys
        let key = format!("rate_limit:{}:{}", context.identifier, context.endpoint);
        let _ = redis_pool
            .execute_data(DataOperation::Delete { key, fields: None })
            .await;

        // Use up the rate limit
        for i in 1..=2 {
            let result = limiter.check_rate_limit(&context).await.unwrap();
            assert!(result.allowed, "Request {} should be allowed", i);
        }

        // Next request should be denied
        let result = limiter.check_rate_limit(&context).await.unwrap();
        assert!(
            !result.allowed,
            "Request should be denied after limit reached"
        );

        // Reset the rate limit
        limiter
            .reset_rate_limit(&context.identifier, &context.endpoint)
            .await
            .unwrap();

        // Next request should be allowed again
        let result = limiter.check_rate_limit(&context).await.unwrap();
        assert!(result.allowed, "Request should be allowed after reset");

        // Cleanup
        let _ = redis_pool
            .execute_data(DataOperation::Delete { key, fields: None })
            .await;
    }

    #[tokio::test]
    async fn test_rate_limit_service_global_policy() {
        let redis_pool = create_redis_pool();
        let service = RateLimitService::new(redis_pool.clone());

        service.set_global_policy(create_test_policy()).await;

        let test_prefix = format!("test_global_{}", chrono::Utc::now().timestamp_nanos());
        let endpoint = format!("/api/general_{}", test_prefix);
        let user_id = format!("user1_{}", test_prefix);

        // Clean up any existing keys
        let key = format!("rate_limit:{}:{}", user_id, endpoint);
        let _ = redis_pool
            .execute_data(DataOperation::Delete { key, fields: None })
            .await;

        // Test global policy
        let result = service.check_rate_limit(&user_id, &endpoint).await.unwrap();
        assert!(result.allowed);
        assert_eq!(result.limit, 5);

        // Cleanup
        let _ = redis_pool
            .execute_data(DataOperation::Delete { key, fields: None })
            .await;
    }

    #[tokio::test]
    async fn test_rate_limit_service_endpoint_specific_policy() {
        let redis_pool = create_redis_pool();
        let service = RateLimitService::new(redis_pool.clone());

        service.set_global_policy(create_test_policy()).await;

        let test_prefix = format!("test_endpoint_{}", chrono::Utc::now().timestamp_nanos());
        let general_endpoint = format!("/api/general_{}", test_prefix);
        let special_endpoint = format!("/api/special_{}", test_prefix);
        let user_id = format!("user1_{}", test_prefix);

        rate_limit_service
            .set_endpoint_policy(
                &special_endpoint,
                RateLimitPolicy {
                    requests: 2,
                    window_seconds: 10,
                    burst_allowance: None,
                },
            )
            .await;

        // Clean up any existing keys
        let key1 = format!("rate_limit:{}:{}", user_id, general_endpoint);
        let key2 = format!("rate_limit:{}:{}", user_id, special_endpoint);
        let _ = redis_pool
            .execute_data(DataOperation::Delete {
                key: key1.clone(),
                fields: None,
            })
            .await;
        let _ = redis_pool
            .execute_data(DataOperation::Delete {
                key: key2.clone(),
                fields: None,
            })
            .await;

        // Test global policy
        let result = service
            .check_rate_limit(&user_id, &general_endpoint)
            .await
            .unwrap();
        assert!(result.allowed);
        assert_eq!(result.limit, 5);

        // Test endpoint-specific policy
        let result = service
            .check_rate_limit(&user_id, &special_endpoint)
            .await
            .unwrap();
        assert!(result.allowed);
        assert_eq!(result.limit, 2);

        // Cleanup
        let _ = redis_pool
            .execute_data(DataOperation::Delete {
                key: key1,
                fields: None,
            })
            .await;
        let _ = redis_pool
            .execute_data(DataOperation::Delete {
                key: key2,
                fields: None,
            })
            .await;
    }

    #[tokio::test]
    async fn test_different_users_separate_limits() {
        let redis_pool = create_redis_pool();
        let service = RateLimitService::new(redis_pool.clone());

        // Use unique test prefix to avoid conflicts with other tests
        let test_prefix = format!("test_separation_{}", chrono::Utc::now().timestamp_nanos());
        let endpoint = format!("/api/{}", test_prefix);

        let policy = RateLimitPolicy {
            requests: 3,
            window_seconds: 60,
            burst_allowance: None,
        };
        service.set_global_policy(policy).await;

        let user1_id = format!("user1_{}", test_prefix);
        let user2_id = format!("user2_{}", test_prefix);

        // Clean up any existing keys for this test
        let key1 = format!("rate_limit:{}:{}", user1_id, endpoint);
        let key2 = format!("rate_limit:{}:{}", user2_id, endpoint);
        let _ = redis_pool
            .execute_data(DataOperation::Delete {
                key: key1.clone(),
                fields: None,
            })
            .await;
        let _ = redis_pool
            .execute_data(DataOperation::Delete {
                key: key2.clone(),
                fields: None,
            })
            .await;

        // User 1 uses up their limit
        for i in 1..=3 {
            let result = service
                .check_rate_limit(&user1_id, &endpoint)
                .await
                .unwrap();
            assert!(result.allowed, "User1 request {} should be allowed", i);
        }

        // User 1's next request should be denied
        let result = service
            .check_rate_limit(&user1_id, &endpoint)
            .await
            .unwrap();
        assert!(
            !result.allowed,
            "User1's request should be denied after limit reached"
        );

        // User 2 should still have their full limit available
        let result = service
            .check_rate_limit(&user2_id, &endpoint)
            .await
            .unwrap();
        assert!(result.allowed, "User2's first request should be allowed");
        assert_eq!(result.remaining, 2);

        // Cleanup
        let _ = redis_pool
            .execute_data(DataOperation::Delete {
                key: key1,
                fields: None,
            })
            .await;
        let _ = redis_pool
            .execute_data(DataOperation::Delete {
                key: key2,
                fields: None,
            })
            .await;
    }

    #[tokio::test]
    async fn test_get_rate_limit_info_without_incrementing() {
        let redis_pool = create_redis_pool();
        let limiter = SlidingWindowRateLimiter::new(redis_pool.clone());

        let policy = RateLimitPolicy {
            requests: 5,
            window_seconds: 60,
            burst_allowance: None,
        };

        let test_prefix = format!("test_info_{}", chrono::Utc::now().timestamp_nanos());
        let identifier = format!("test_user_info_{}", test_prefix);
        let endpoint = format!("/api/info_test_{}", test_prefix);

        // Clean up any existing keys
        let key = format!("rate_limit:{}:{}", identifier, endpoint);
        let _ = redis_pool
            .execute_data(DataOperation::Delete { key, fields: None })
            .await;

        // Get initial info
        let info = limiter
            .get_rate_limit_info(&identifier, &endpoint, &policy)
            .await
            .unwrap();
        assert_eq!(info.remaining, 5);
        assert!(info.allowed);

        // Check that getting info doesn't increment the counter
        let info2 = limiter
            .get_rate_limit_info(&identifier, &endpoint, &policy)
            .await
            .unwrap();
        assert_eq!(info2.remaining, 5);
        assert!(info2.allowed);

        // Make an actual request to increment
        let context = RateLimitContext {
            identifier: identifier.clone(),
            policy,
            endpoint: endpoint.clone(),
        };
        let result = limiter.check_rate_limit(&context).await.unwrap();
        assert!(result.allowed);
        assert_eq!(result.remaining, 4);

        // Now info should show the updated count
        let info3 = limiter
            .get_rate_limit_info(&identifier, &endpoint, &context.policy)
            .await
            .unwrap();
        assert_eq!(info3.remaining, 4);

        // Cleanup
        let _ = redis_pool
            .execute_data(DataOperation::Delete { key, fields: None })
            .await;
    }

    #[tokio::test]
    async fn test_burst_allowance_behavior() {
        let redis_pool = create_redis_pool();
        let limiter = SlidingWindowRateLimiter::new(redis_pool.clone());

        let test_prefix = format!("test_burst_{}", chrono::Utc::now().timestamp_nanos());
        let context = RateLimitContext {
            identifier: format!("test_burst_user_{}", test_prefix),
            policy: RateLimitPolicy {
                requests: 3,
                window_seconds: 60,
                burst_allowance: Some(5),
            },
            endpoint: format!("/api/burst_test_{}", test_prefix),
        };

        // Clean up any existing keys
        let key = format!("rate_limit:{}:{}", context.identifier, context.endpoint);
        let _ = redis_pool
            .execute_data(DataOperation::Delete { key, fields: None })
            .await;

        // First 3 requests should be allowed (normal limit)
        for i in 1..=3 {
            let result = limiter.check_rate_limit(&context).await.unwrap();
            assert!(result.allowed, "Normal request {} should be allowed", i);
        }

        // Next 2 requests should be allowed due to burst allowance
        for i in 4..=5 {
            let result = limiter.check_rate_limit(&context).await.unwrap();
            assert!(result.allowed, "Burst request {} should be allowed", i);
        }

        // 6th request should be denied
        let result = limiter.check_rate_limit(&context).await.unwrap();
        assert!(
            !result.allowed,
            "Request beyond burst allowance should be denied"
        );

        // Cleanup
        let _ = redis_pool
            .execute_data(DataOperation::Delete { key, fields: None })
            .await;
    }

    #[test]
    fn test_extract_identifier_from_request_priority() {
        use std::net::{IpAddr, Ipv4Addr};

        let mut headers = HeaderMap::new();
        let socket_addr =
            std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let connect_info = Some(socket_addr);

        // Test priority: auth context with header > IP address
        headers.insert("authorization", "Bearer abcd1234token".parse().unwrap());
        let identifier =
            extract_identifier_from_request(&headers, connect_info.as_ref(), Some("user"));
        assert_eq!(identifier, "user:abcd1234");

        // Test API key auth
        headers.clear();
        headers.insert("authorization", "ApiKey xyz98765key".parse().unwrap());
        let identifier =
            extract_identifier_from_request(&headers, connect_info.as_ref(), Some("api_key"));
        assert_eq!(identifier, "api_key:xyz98765");

        // Test IP fallback when no auth
        headers.clear();
        let identifier = extract_identifier_from_request(&headers, connect_info.as_ref(), None);
        assert_eq!(identifier, "ip:192.168.1.1");

        // Test unknown fallback when no connect info
        let identifier = extract_identifier_from_request(&headers, None, None);
        assert_eq!(identifier, "unknown");
    }

    #[test]
    fn test_rate_limit_policy_creation() {
        let policy = RateLimitPolicy {
            requests: 100,
            window_seconds: 60,
            burst_allowance: Some(150),
        };

        assert_eq!(policy.requests, 100);
        assert_eq!(policy.window_seconds, 60);
        assert_eq!(policy.burst_allowance, Some(150));
    }

    #[test]
    fn test_rate_limit_result_creation() {
        let reset_time = chrono::Utc::now();
        let result = RateLimitResult {
            allowed: true,
            limit: 100,
            remaining: 95,
            reset_time,
            retry_after: None,
        };

        assert!(result.allowed);
        assert_eq!(result.limit, 100);
        assert_eq!(result.remaining, 95);
        assert_eq!(result.reset_time, reset_time);
        assert!(result.retry_after.is_none());
    }
}
