use crate::models::ApiResponse;
use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use chrono::{DateTime, Utc};
use dbx_adapter::redis::client::RedisPool;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};

#[derive(Debug, Clone, PartialEq)]
pub struct RateLimitResult {
    pub allowed: bool,
    pub limit: u32,
    pub remaining: u32,
    pub reset_time: DateTime<Utc>,
    pub retry_after: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct RateLimitPolicy {
    pub requests: u32,
    pub window_seconds: u32,
    pub burst_allowance: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct RateLimitContext {
    pub identifier: String,
    pub policy: RateLimitPolicy,
    pub endpoint: String,
}

#[derive(Clone)]
pub struct SlidingWindowRateLimiter {
    redis_pool: Arc<RedisPool>,
}

impl SlidingWindowRateLimiter {
    pub fn new(redis_pool: Arc<RedisPool>) -> Self {
        Self { redis_pool }
    }

    pub async fn check_rate_limit(
        &self,
        context: &RateLimitContext,
    ) -> Result<RateLimitResult, String> {
        let now = Utc::now();
        let window_start = now - chrono::Duration::seconds(context.policy.window_seconds as i64);

        let key = format!("rate_limit:{}:{}", context.identifier, context.endpoint);

        // Use Redis ZREMRANGEBYSCORE to remove expired entries and ZCARD to count current entries
        let script = r#"
            local key = KEYS[1]
            local window_start = ARGV[1]
            local now = ARGV[2] 
            local limit = tonumber(ARGV[3])
            local burst = tonumber(ARGV[4]) or limit
            local window_seconds = tonumber(ARGV[5])
            
            -- Remove expired entries
            redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)
            
            -- Count current entries
            local current_count = redis.call('ZCARD', key)
            
            -- Check if within limits (considering burst)
            local effective_limit = math.max(limit, burst)
            
            if current_count >= effective_limit then
                local oldest_entry = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
                local retry_after = 0
                if #oldest_entry > 0 then
                    local oldest_time = tonumber(oldest_entry[2])
                    retry_after = math.ceil(oldest_time + window_seconds - tonumber(now))
                end
                
                return {0, current_count, limit, retry_after}
            end
            
            -- Add current request
            local request_id = now .. ':' .. math.random(1000000)
            redis.call('ZADD', key, now, request_id)
            redis.call('EXPIRE', key, window_seconds * 2)
            
            local new_count = current_count + 1
            local remaining = math.max(0, limit - new_count)
            
            return {1, new_count, remaining, 0}
        "#;

        let conn = self
            .redis_pool
            .get_connection()
            .map_err(|e| format!("Failed to get Redis connection: {}", e))?;
        let conn_arc = Arc::new(std::sync::Mutex::new(conn));

        let now_timestamp = now.timestamp().to_string();
        let window_start_timestamp = window_start.timestamp().to_string();
        let limit_str = context.policy.requests.to_string();
        let burst_str = context
            .policy
            .burst_allowance
            .unwrap_or(context.policy.requests)
            .to_string();
        let window_str = context.policy.window_seconds.to_string();

        let result: Vec<i64> = redis::Script::new(script)
            .key(&key)
            .arg(&window_start_timestamp)
            .arg(&now_timestamp)
            .arg(&limit_str)
            .arg(&burst_str)
            .arg(&window_str)
            .invoke(&mut *conn_arc.lock().unwrap())
            .map_err(|e| format!("Redis script execution failed: {}", e))?;

        let allowed = result[0] == 1;
        let current_count = result[1] as u32;
        let remaining = result[2] as u32;
        let retry_after_seconds = if result[3] > 0 {
            Some(result[3] as u32)
        } else {
            None
        };

        let reset_time = now + chrono::Duration::seconds(context.policy.window_seconds as i64);

        Ok(RateLimitResult {
            allowed,
            limit: context.policy.requests,
            remaining,
            reset_time,
            retry_after: retry_after_seconds,
        })
    }

    pub async fn reset_rate_limit(&self, identifier: &str, endpoint: &str) -> Result<(), String> {
        let key = format!("rate_limit:{}:{}", identifier, endpoint);

        let conn = self
            .redis_pool
            .get_connection()
            .map_err(|e| format!("Failed to get Redis connection: {}", e))?;
        let conn_arc = Arc::new(std::sync::Mutex::new(conn));

        dbx_adapter::redis::primitives::string::RedisString::new(conn_arc)
            .del(&key)
            .map_err(|e| format!("Failed to reset rate limit: {}", e))?;

        Ok(())
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

        // Get current status without incrementing
        let now = Utc::now();
        let window_start = now - chrono::Duration::seconds(policy.window_seconds as i64);
        let key = format!("rate_limit:{}:{}", identifier, endpoint);

        let script = r#"
            local key = KEYS[1]
            local window_start = ARGV[1]
            local limit = tonumber(ARGV[2])
            
            -- Remove expired entries
            redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)
            
            -- Count current entries
            local current_count = redis.call('ZCARD', key)
            local remaining = math.max(0, limit - current_count)
            
            return {current_count, remaining}
        "#;

        let conn = self
            .redis_pool
            .get_connection()
            .map_err(|e| format!("Failed to get Redis connection: {}", e))?;
        let conn_arc = Arc::new(std::sync::Mutex::new(conn));

        let window_start_timestamp = window_start.timestamp().to_string();
        let limit_str = policy.requests.to_string();

        let result: Vec<i64> = redis::Script::new(script)
            .key(&key)
            .arg(&window_start_timestamp)
            .arg(&limit_str)
            .invoke(&mut *conn_arc.lock().unwrap())
            .map_err(|e| format!("Redis script execution failed: {}", e))?;

        let current_count = result[0] as u32;
        let remaining = result[1] as u32;
        let reset_time = now + chrono::Duration::seconds(policy.window_seconds as i64);

        Ok(RateLimitResult {
            allowed: remaining > 0,
            limit: policy.requests,
            remaining,
            reset_time,
            retry_after: None,
        })
    }
}

#[derive(Clone)]
pub struct RateLimitService {
    limiter: SlidingWindowRateLimiter,
    policies: HashMap<String, RateLimitPolicy>,
    global_policy: Option<RateLimitPolicy>,
}

impl RateLimitService {
    pub fn new(redis_pool: Arc<RedisPool>) -> Self {
        Self {
            limiter: SlidingWindowRateLimiter::new(redis_pool),
            policies: HashMap::new(),
            global_policy: None,
        }
    }

    pub fn set_global_policy(&mut self, policy: RateLimitPolicy) {
        self.global_policy = Some(policy);
    }

    pub fn set_endpoint_policy(&mut self, endpoint: String, policy: RateLimitPolicy) {
        self.policies.insert(endpoint, policy);
    }

    pub fn get_policy_for_endpoint(&self, endpoint: &str) -> Option<&RateLimitPolicy> {
        self.policies.get(endpoint).or(self.global_policy.as_ref())
    }

    pub fn get_all_policies(&self) -> &HashMap<String, RateLimitPolicy> {
        &self.policies
    }

    pub async fn check_rate_limit(
        &self,
        identifier: &str,
        endpoint: &str,
    ) -> Result<RateLimitResult, String> {
        let policy = self
            .get_policy_for_endpoint(endpoint)
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
            .ok_or_else(|| "No rate limit policy configured".to_string())?;

        self.limiter
            .get_rate_limit_info(identifier, endpoint, policy)
            .await
    }
}

pub fn extract_identifier_from_request(
    headers: &HeaderMap,
    connect_info: Option<&ConnectInfo<SocketAddr>>,
    auth_context: Option<&str>,
) -> String {
    // Priority: API key > JWT user ID > IP address
    if let Some(auth_id) = auth_context {
        return format!("user:{}", auth_id);
    }

    if let Some(connect_info) = connect_info {
        return format!("ip:{}", connect_info.0.ip());
    }

    // Fallback to a default identifier
    "unknown".to_string()
}

pub fn add_rate_limit_headers(response: &mut Response, result: &RateLimitResult) {
    let headers = response.headers_mut();

    if let Ok(value) = HeaderValue::from_str(&result.limit.to_string()) {
        headers.insert("X-RateLimit-Limit", value);
    }

    if let Ok(value) = HeaderValue::from_str(&result.remaining.to_string()) {
        headers.insert("X-RateLimit-Remaining", value);
    }

    if let Ok(value) = HeaderValue::from_str(&result.reset_time.timestamp().to_string()) {
        headers.insert("X-RateLimit-Reset", value);
    }

    if let Some(retry_after) = result.retry_after {
        if let Ok(value) = HeaderValue::from_str(&retry_after.to_string()) {
            headers.insert("Retry-After", value);
        }
    }
}

pub async fn rate_limit_middleware(
    State(rate_limit_service): State<Arc<RateLimitService>>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    mut request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    let endpoint = request.uri().path().to_string();

    // Extract identifier (user ID, API key ID, or IP)
    let identifier = extract_identifier_from_request(
        request.headers(),
        connect_info.as_ref(),
        None, // TODO: Extract from auth context
    );

    // Check rate limit
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
        let mut response = (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ApiResponse::<()>::error("Rate limit exceeded".to_string())),
        )
            .into_response();

        add_rate_limit_headers(&mut response, &rate_limit_result);
        return Ok(response);
    }

    // Continue with request
    let mut response = next.run(request).await;
    add_rate_limit_headers(&mut response, &rate_limit_result);

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::sleep;

    fn create_test_policy() -> RateLimitPolicy {
        RateLimitPolicy {
            requests: 5,
            window_seconds: 10,
            burst_allowance: Some(7),
        }
    }

    fn create_redis_pool() -> Arc<RedisPool> {
        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        Arc::new(RedisPool::new(&redis_url, 1).unwrap())
    }

    #[tokio::test]
    async fn test_sliding_window_rate_limiter_basic() {
        let redis_pool = create_redis_pool();
        let limiter = SlidingWindowRateLimiter::new(redis_pool);

        let context = RateLimitContext {
            identifier: "test_user_basic".to_string(),
            policy: create_test_policy(),
            endpoint: "/api/test".to_string(),
        };

        // Reset any existing state
        let _ = limiter
            .reset_rate_limit(&context.identifier, &context.endpoint)
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
    }

    #[tokio::test]
    async fn test_rate_limit_reset() {
        let redis_pool = create_redis_pool();
        let limiter = SlidingWindowRateLimiter::new(redis_pool);

        let context = RateLimitContext {
            identifier: "test_user_reset".to_string(),
            policy: RateLimitPolicy {
                requests: 2,
                window_seconds: 60,
                burst_allowance: None,
            },
            endpoint: "/api/reset_test".to_string(),
        };

        // Reset any existing state
        let _ = limiter
            .reset_rate_limit(&context.identifier, &context.endpoint)
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
    }

    #[tokio::test]
    async fn test_rate_limit_service_global_policy() {
        let redis_pool = create_redis_pool();
        let mut service = RateLimitService::new(redis_pool);

        service.set_global_policy(create_test_policy());

        // Test global policy
        let result = service
            .check_rate_limit("user1", "/api/general")
            .await
            .unwrap();
        assert!(result.allowed);
        assert_eq!(result.limit, 5);
    }

    #[tokio::test]
    async fn test_rate_limit_service_endpoint_specific_policy() {
        let redis_pool = create_redis_pool();
        let mut service = RateLimitService::new(redis_pool);

        service.set_global_policy(create_test_policy());
        service.set_endpoint_policy(
            "/api/special".to_string(),
            RateLimitPolicy {
                requests: 2,
                window_seconds: 5,
                burst_allowance: None,
            },
        );

        // Test global policy
        let result = service
            .check_rate_limit("user1", "/api/general")
            .await
            .unwrap();
        assert!(result.allowed);
        assert_eq!(result.limit, 5);

        // Test endpoint-specific policy
        let result = service
            .check_rate_limit("user1", "/api/special")
            .await
            .unwrap();
        assert!(result.allowed);
        assert_eq!(result.limit, 2);
    }

    #[tokio::test]
    async fn test_different_users_separate_limits() {
        let redis_pool = match std::panic::catch_unwind(|| create_redis_pool()) {
            Ok(pool) => pool,
            Err(_) => {
                // Skip test if Redis is not available
                eprintln!("Skipping test_different_users_separate_limits: Redis not available");
                return;
            }
        };

        // Test Redis connectivity by trying to create a limiter
        let test_limiter = match std::panic::catch_unwind(|| {
            SlidingWindowRateLimiter::new(redis_pool.clone())
        }) {
            Ok(limiter) => limiter,
            Err(_) => {
                eprintln!(
                    "Skipping test_different_users_separate_limits: Cannot create Redis limiter"
                );
                return;
            }
        };

        let mut service = RateLimitService::new(redis_pool);

        let policy = RateLimitPolicy {
            requests: 3,
            window_seconds: 60,
            burst_allowance: None,
        };
        service.set_global_policy(policy);

        let endpoint = "/api/test_separation";

        // User 1 uses up their limit
        for i in 1..=3 {
            let result = service.check_rate_limit("user1", endpoint).await;
            match result {
                Ok(res) => assert!(res.allowed, "User1 request {} should be allowed", i),
                Err(e) => {
                    eprintln!("Redis error in test: {}", e);
                    return; // Skip test on Redis errors
                }
            }
        }

        // User 1's next request should be denied
        let result = service.check_rate_limit("user1", endpoint).await;
        match result {
            Ok(res) => assert!(
                !res.allowed,
                "User1's request should be denied after limit reached"
            ),
            Err(_) => return, // Skip test on Redis errors
        }

        // User 2 should still have their full limit available
        let result = service.check_rate_limit("user2", endpoint).await;
        match result {
            Ok(res) => {
                assert!(res.allowed, "User2's first request should be allowed");
                assert_eq!(res.remaining, 2);
            }
            Err(_) => return, // Skip test on Redis errors
        }
    }

    #[tokio::test]
    async fn test_get_rate_limit_info_without_incrementing() {
        let redis_pool = create_redis_pool();
        let limiter = SlidingWindowRateLimiter::new(redis_pool);

        let policy = RateLimitPolicy {
            requests: 5,
            window_seconds: 60,
            burst_allowance: None,
        };

        let identifier = "test_user_info";
        let endpoint = "/api/info_test";

        // Reset any existing state
        let _ = limiter.reset_rate_limit(identifier, endpoint).await;

        // Get initial info
        let info = limiter
            .get_rate_limit_info(identifier, endpoint, &policy)
            .await
            .unwrap();
        assert_eq!(info.remaining, 5);
        assert!(info.allowed);

        // Check that getting info doesn't increment the counter
        let info2 = limiter
            .get_rate_limit_info(identifier, endpoint, &policy)
            .await
            .unwrap();
        assert_eq!(info2.remaining, 5);
        assert!(info2.allowed);

        // Make an actual request to increment
        let context = RateLimitContext {
            identifier: identifier.to_string(),
            policy,
            endpoint: endpoint.to_string(),
        };
        let result = limiter.check_rate_limit(&context).await.unwrap();
        assert!(result.allowed);
        assert_eq!(result.remaining, 4);

        // Now info should show the updated count
        let info3 = limiter
            .get_rate_limit_info(identifier, endpoint, &context.policy)
            .await
            .unwrap();
        assert_eq!(info3.remaining, 4);
    }

    #[tokio::test]
    async fn test_burst_allowance_behavior() {
        let redis_pool = create_redis_pool();
        let limiter = SlidingWindowRateLimiter::new(redis_pool);

        let context = RateLimitContext {
            identifier: "test_burst_user".to_string(),
            policy: RateLimitPolicy {
                requests: 3,
                window_seconds: 60,
                burst_allowance: Some(5),
            },
            endpoint: "/api/burst_test".to_string(),
        };

        // Reset any existing state
        let _ = limiter
            .reset_rate_limit(&context.identifier, &context.endpoint)
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
    }

    #[test]
    fn test_extract_identifier_from_request_priority() {
        use std::net::{IpAddr, Ipv4Addr};

        let headers = HeaderMap::new();
        let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let connect_info = ConnectInfo(socket_addr);

        // Test priority: auth context > IP address
        let identifier =
            extract_identifier_from_request(&headers, Some(&connect_info), Some("user123"));
        assert_eq!(identifier, "user:user123");

        // Test IP fallback when no auth
        let identifier = extract_identifier_from_request(&headers, Some(&connect_info), None);
        assert_eq!(identifier, "ip:192.168.1.1");

        // Test unknown fallback when no info available
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
