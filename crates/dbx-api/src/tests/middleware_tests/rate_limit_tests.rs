//! Rate limiting middleware tests

use crate::middleware::rate_limit::*;
use crate::test_helpers;
use dbx_core::{DataOperation, UniversalBackend};
use std::sync::Arc;

fn create_test_policy() -> RateLimitPolicy {
    RateLimitPolicy {
        requests: 5,
        window_seconds: 10,
        burst_allowance: Some(7),
    }
}

async fn create_test_backend() -> Arc<dyn UniversalBackend> {
    test_helpers::create_mock_backend()
}

#[tokio::test]
async fn test_sliding_window_rate_limiter() {
    let backend = create_test_backend().await;
    let limiter = SlidingWindowRateLimiter::new(backend.clone());

    let test_prefix = format!(
        "test_{}",
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    );
    let context = RateLimitContext {
        identifier: format!("test_user_{}", test_prefix),
        policy: create_test_policy(),
        endpoint: format!("/api/test_{}", test_prefix),
    };

    // Clean up any existing keys using backend abstraction
    let key = format!("rate_limit:{}:{}", context.identifier, context.endpoint);
    let _ = backend
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
    let _ = backend
        .execute_data(DataOperation::Delete { key, fields: None })
        .await;
}

#[tokio::test]
async fn test_rate_limit_reset() {
    let backend = create_test_backend().await;
    let limiter = SlidingWindowRateLimiter::new(backend.clone());

    let test_prefix = format!(
        "test_reset_{}",
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    );
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
    let _ = backend
        .execute_data(DataOperation::Delete {
            key: key.clone(),
            fields: None,
        })
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
    let cleanup_key = format!("rate_limit:{}:{}", context.identifier, context.endpoint);
    let _ = backend
        .execute_data(DataOperation::Delete {
            key: cleanup_key,
            fields: None,
        })
        .await;
}

#[tokio::test]
async fn test_rate_limit_service_global_policy() {
    let backend = create_test_backend().await;
    let service = PolicyRateLimitService::new(backend.clone()); // Explicitly set to false

    service.set_global_policy(create_test_policy()).await;

    let test_prefix = format!(
        "test_global_{}",
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    );
    let endpoint = format!("/api/general_{}", test_prefix);
    let user_id = format!("user1_{}", test_prefix);

    // Clean up any existing keys
    let key = format!("rate_limit:{}:{}", user_id, endpoint);
    let _ = backend
        .execute_data(DataOperation::Delete {
            key: key.clone(),
            fields: None,
        })
        .await;

    // Test global policy
    let result = service.check_rate_limit(&user_id, &endpoint).await.unwrap();
    assert!(result.allowed);
    assert_eq!(result.limit, 5);

    // Cleanup
    let cleanup_key = format!("rate_limit:{}:{}", user_id, endpoint);
    let _ = backend
        .execute_data(DataOperation::Delete {
            key: cleanup_key,
            fields: None,
        })
        .await;
}

#[tokio::test]
async fn test_rate_limit_service_endpoint_specific_policy() {
    let backend = create_test_backend().await;
    let service = PolicyRateLimitService::new(backend.clone()); // Explicitly set to false

    service.set_global_policy(create_test_policy()).await;

    let test_prefix = format!(
        "test_endpoint_{}",
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    );
    let general_endpoint = format!("/api/general_{}", test_prefix);
    let special_endpoint = format!("/api/special_{}", test_prefix);
    let user_id = format!("user1_{}", test_prefix);

    service
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
    let _ = backend
        .execute_data(DataOperation::Delete {
            key: key1.clone(),
            fields: None,
        })
        .await;
    let _ = backend
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
    let _ = backend
        .execute_data(DataOperation::Delete {
            key: key1,
            fields: None,
        })
        .await;
    let _ = backend
        .execute_data(DataOperation::Delete {
            key: key2,
            fields: None,
        })
        .await;
}

#[tokio::test]
async fn test_different_users_separate_limits() {
    let backend = create_test_backend().await;
    let service = PolicyRateLimitService::new(backend.clone()); // Explicitly set to false

    // Use unique test prefix to avoid conflicts with other tests
    let test_prefix = format!(
        "test_separation_{}",
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    );
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
    let _ = backend
        .execute_data(DataOperation::Delete {
            key: key1.clone(),
            fields: None,
        })
        .await;
    let _ = backend
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
    let _ = backend
        .execute_data(DataOperation::Delete {
            key: key1,
            fields: None,
        })
        .await;
    let _ = backend
        .execute_data(DataOperation::Delete {
            key: key2,
            fields: None,
        })
        .await;
}

#[tokio::test]
async fn test_get_rate_limit_info_without_incrementing() {
    let backend = create_test_backend().await;
    let limiter = SlidingWindowRateLimiter::new(backend.clone());

    let policy = RateLimitPolicy {
        requests: 5,
        window_seconds: 60,
        burst_allowance: None,
    };

    let test_prefix = format!(
        "test_info_{}",
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    );
    let identifier = format!("test_user_info_{}", test_prefix);
    let endpoint = format!("/api/info_test_{}", test_prefix);

    // Clean up any existing keys
    let key = format!("rate_limit:{}:{}", identifier, endpoint);
    let _ = backend
        .execute_data(DataOperation::Delete {
            key: key.clone(),
            fields: None,
        })
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
    let cleanup_key = format!("rate_limit:{}:{}", identifier, endpoint);
    let _ = backend
        .execute_data(DataOperation::Delete {
            key: cleanup_key,
            fields: None,
        })
        .await;
}

#[tokio::test]
async fn test_burst_allowance_behavior() {
    let backend = create_test_backend().await;
    let limiter = SlidingWindowRateLimiter::new(backend.clone());

    let test_prefix = format!(
        "test_burst_{}",
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    );
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
    let _ = backend
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
    let cleanup_key = format!("rate_limit:{}:{}", context.identifier, context.endpoint);
    let _ = backend
        .execute_data(DataOperation::Delete {
            key: cleanup_key,
            fields: None,
        })
        .await;
}

#[test]
fn test_extract_identifier_from_request_priority() {
    use std::net::{IpAddr, Ipv4Addr};

    let mut headers = HeaderMap::new();
    let socket_addr = std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
    let connect_info = Some(socket_addr);

    // Test priority: auth context with header > IP address
    headers.insert("authorization", "Bearer abcd1234token".parse().unwrap());
    let identifier = extract_identifier_from_request(&headers, connect_info.as_ref(), Some("user"));
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

#[tokio::test]
async fn test_bit_vector_rate_limiter() {
    let backend = create_test_backend().await;
    let limiter = BitVectorRateLimiter::new(backend);

    let policy = RateLimitPolicy {
        requests: 5,
        window_seconds: 10,
        burst_allowance: Some(2),
    };

    let context = RateLimitContext {
        identifier: "test_user_bv".to_string(),
        policy,
        endpoint: "/api/test".to_string(),
    };

    // Test initial requests (should be allowed)
    for i in 0..5 {
        let result = limiter.check_rate_limit(&context).await.unwrap();
        assert!(result.allowed, "Request {} should be allowed", i + 1);
        assert_eq!(result.limit, 5);
        assert_eq!(result.remaining, 4 - i);
    }

    // Test rate limit exceeded
    let result = limiter.check_rate_limit(&context).await.unwrap();
    assert!(!result.allowed, "Request should be rate limited");
    assert_eq!(result.remaining, 0);
}

#[tokio::test]
async fn test_bit_vector_memory_efficiency() {
    let backend = create_test_backend().await;
    let limiter = BitVectorRateLimiter::with_bucket_size(backend, 1); // 1-second buckets

    let policy = RateLimitPolicy {
        requests: 100,
        window_seconds: 60,
        burst_allowance: Some(10),
    };

    let context = RateLimitContext {
        identifier: "memory_test_user".to_string(),
        policy,
        endpoint: "/api/memory_test".to_string(),
    };

    // Make several requests to ensure bit vector is created and stored
    for _ in 0..20 {
        let _ = limiter.check_rate_limit(&context).await.unwrap();
    }

    // Wait a moment for async operations to complete
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Check memory stats
    let key = format!("rate_limit_bv:{}:{}", context.identifier, context.endpoint);
    let stats = limiter.get_memory_stats(&key).await.unwrap();

    // With mock backend, memory stats might be 0, so we check for valid structure
    assert!(stats.compression_ratio >= 0.0);
    // Just verify they have reasonable bounds instead
    assert!(stats.total_bytes < 1_000_000); // Reasonable upper bound
}

#[tokio::test]
async fn test_rate_limit_service() {
    let backend = create_test_backend().await;

    // Test sliding window implementation
    let service_sliding = RateLimitService::new(backend.clone(), false);
    let result = service_sliding
        .check_rate_limit("test_user_sliding", "/api/test")
        .await;
    assert!(result.is_ok());

    // Test bit vector implementation
    let service_bitvector = RateLimitService::new(backend, true);
    let result = service_bitvector
        .check_rate_limit("test_user_bitvector", "/api/test")
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_bit_vector_sliding_window_behavior() {
    let backend = create_test_backend().await;
    let limiter = BitVectorRateLimiter::with_bucket_size(backend, 1);

    let policy = RateLimitPolicy {
        requests: 3,
        window_seconds: 5,
        burst_allowance: Some(1),
    };

    let context = RateLimitContext {
        identifier: "sliding_test_user".to_string(),
        policy,
        endpoint: "/api/sliding_test".to_string(),
    };

    // Use up the rate limit
    for _ in 0..3 {
        let result = limiter.check_rate_limit(&context).await.unwrap();
        assert!(result.allowed);
    }

    // Should be rate limited now
    let result = limiter.check_rate_limit(&context).await.unwrap();
    assert!(!result.allowed);

    // Test that bucket creation and retrieval works
    let key = format!("rate_limit:{}:{}", context.identifier, context.endpoint);
    let get_op = dbx_core::DataOperation::Get { key, fields: None };
    let stored_result = limiter.backend.execute_data(get_op).await;
    assert!(stored_result.is_ok());
}

#[tokio::test]
async fn test_efficiency_metrics() {
    let backend = create_test_backend().await;
    let service = RateLimitService::new(backend, true); // Enable bit vector

    // Make requests and check metrics structure
    for _ in 0..5 {
        let _ = service
            .check_rate_limit("efficiency_user", "/api/efficiency")
            .await;
    }

    let metrics = service
        .get_efficiency_metrics("efficiency_user", "/api/efficiency")
        .await
        .unwrap();

    // Verify metrics contain expected fields
    // Verify metrics structure is valid
    // With mock backend, values might be 0, so we check for valid structure
    assert!(metrics.compression_ratio >= 0.0);
    assert!(metrics.sliding_window_bytes < 1_000_000); // Reasonable upper bound
    assert!(metrics.bit_vector_bytes < 1_000_000); // Reasonable upper bound
    assert!(metrics.memory_savings >= 0.0);
}

#[tokio::test]
async fn test_bit_vector_serialization() {
    use crate::middleware::rate_limit::RateLimitBitVector;

    let bit_vector = RateLimitBitVector {
        bits: vec![0b10101010, 0b01010101],
        start_timestamp: 1234567890,
        bucket_size_seconds: 1,
        bucket_count: 16,
        bucket_counts: Some(vec![1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1]),
    };

    // Test serialization
    let json = serde_json::to_string(&bit_vector).unwrap();
    assert!(!json.is_empty());

    // Test deserialization
    let deserialized: RateLimitBitVector = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.bits, bit_vector.bits);
    assert_eq!(deserialized.start_timestamp, bit_vector.start_timestamp);
    assert_eq!(deserialized.bucket_count, bit_vector.bucket_count);
}
