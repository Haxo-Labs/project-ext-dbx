//! Multi-Backend Integration Tests
//!
//! These tests verify the BackendRouter routing operations between
//! PostgreSQL and Redis database instances, demonstrating production-level
//! cross-backend routing, load balancing, and data consistency.

use dbx_adapter::postgres::factory::PostgresBackendFactory;
use dbx_adapter::redis::factory::RedisBackendFactory;
use dbx_config::{config::RoutingConfig, BackendConfig, KeyRoutingRule, PatternType};
use dbx_core::{
    DataOperation, DataValue, LoadBalancingStrategy, QueryFilter, QueryOperation, StreamOperation,
};
use dbx_router::{registry::BackendRegistryBuilder, BackendRouter};
use std::collections::HashMap;
use std::env;
use std::time::Instant;
use tokio;
use uuid::Uuid;

/// Get test PostgreSQL URL from environment or use default
fn get_test_postgres_url() -> String {
    env::var("TEST_POSTGRES_URL")
        .unwrap_or_else(|_| "postgresql://postgres:postgres@localhost:5432/postgres".to_string())
}

/// Get test Redis URL from environment or use default  
fn get_test_redis_url() -> String {
    env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string())
}

/// Check if PostgreSQL is available for testing
async fn is_postgres_available() -> bool {
    use tokio_postgres::connect;
    let url = get_test_postgres_url();
    println!("Testing PostgreSQL connection with URL: {}", url);
    match connect(&url, tokio_postgres::NoTls).await {
        Ok((client, connection)) => {
            println!("PostgreSQL connection established");
            tokio::spawn(connection);
            match client.simple_query("SELECT 1").await {
                Ok(_) => {
                    println!("PostgreSQL query successful");
                    true
                }
                Err(e) => {
                    println!("PostgreSQL query failed: {}", e);
                    false
                }
            }
        }
        Err(e) => {
            println!("PostgreSQL connection failed: {}", e);
            false
        }
    }
}

/// Check if Redis is available for testing
async fn is_redis_available() -> bool {
    use redis::Client;
    let url = get_test_redis_url();
    println!("Testing Redis connection with URL: {}", url);
    match Client::open(url) {
        Ok(client) => {
            println!("Redis client created");
            match client.get_connection() {
                Ok(mut conn) => {
                    println!("Redis connection established");
                    match redis::cmd("PING").query::<String>(&mut conn) {
                        Ok(response) => {
                            println!("Redis PING successful: {}", response);
                            true
                        }
                        Err(e) => {
                            println!("Redis PING failed: {}", e);
                            false
                        }
                    }
                }
                Err(e) => {
                    println!("Redis connection failed: {}", e);
                    false
                }
            }
        }
        Err(e) => {
            println!("Redis client creation failed: {}", e);
            false
        }
    }
}

/// Skip test if required backends are not available
macro_rules! skip_if_backends_unavailable {
    () => {
        if !is_postgres_available().await {
            println!("Skipping test: PostgreSQL not available");
            return;
        }
        if !is_redis_available().await {
            println!("Skipping test: Redis not available");
            return;
        }
    };
}

/// Create a production-ready router with optimized routing configuration
async fn create_production_router() -> BackendRouter {
    // Create registry with factories
    let mut registry_builder = BackendRegistryBuilder::new();
    registry_builder = registry_builder.with_factory("postgresql", PostgresBackendFactory::new());
    registry_builder = registry_builder.with_factory("redis", RedisBackendFactory::new());
    let registry = registry_builder.build();

    // Create optimized backend configurations
    let mut backends = HashMap::new();

    // High-speed cache for frequently accessed data
    backends.insert(
        "redis_cache".to_string(),
        BackendConfig {
            provider: "redis".to_string(),
            url: get_test_redis_url(),
            pool_size: Some(10),
            timeout_ms: Some(3000),
            retry_attempts: Some(2),
            retry_delay_ms: Some(500),
            capabilities: None,
            additional_config: HashMap::new(),
        },
    );

    // Session store with different pool configuration
    backends.insert(
        "redis_sessions".to_string(),
        BackendConfig {
            provider: "redis".to_string(),
            url: get_test_redis_url(),
            pool_size: Some(5),
            timeout_ms: Some(5000),
            retry_attempts: Some(3),
            retry_delay_ms: Some(1000),
            capabilities: None,
            additional_config: HashMap::new(),
        },
    );

    // Analytics and persistent data
    backends.insert(
        "postgres_analytics".to_string(),
        BackendConfig {
            provider: "postgresql".to_string(),
            url: get_test_postgres_url(),
            pool_size: Some(8),
            timeout_ms: Some(15000),
            retry_attempts: Some(3),
            retry_delay_ms: Some(2000),
            capabilities: None,
            additional_config: HashMap::new(),
        },
    );

    // User data store
    backends.insert(
        "postgres_users".to_string(),
        BackendConfig {
            provider: "postgresql".to_string(),
            url: get_test_postgres_url(),
            pool_size: Some(6),
            timeout_ms: Some(10000),
            retry_attempts: Some(3),
            retry_delay_ms: Some(1500),
            capabilities: None,
            additional_config: HashMap::new(),
        },
    );

    // Create comprehensive routing configuration
    let config = dbx_config::DbxConfig {
        backends,
        routing: RoutingConfig {
            default_backend: "redis_cache".to_string(),
            operation_routing: HashMap::new(),
            key_routing: vec![
                // Cache patterns (highest priority)
                KeyRoutingRule {
                    pattern: "cache:*".to_string(),
                    pattern_type: PatternType::Prefix,
                    backend: "redis_cache".to_string(),
                    priority: 100,
                },
                // Session patterns
                KeyRoutingRule {
                    pattern: "session:*".to_string(),
                    pattern_type: PatternType::Prefix,
                    backend: "redis_sessions".to_string(),
                    priority: 90,
                },
                KeyRoutingRule {
                    pattern: "auth:*".to_string(),
                    pattern_type: PatternType::Prefix,
                    backend: "redis_sessions".to_string(),
                    priority: 90,
                },
                // Analytics patterns
                KeyRoutingRule {
                    pattern: "analytics:*".to_string(),
                    pattern_type: PatternType::Prefix,
                    backend: "postgres_analytics".to_string(),
                    priority: 80,
                },
                KeyRoutingRule {
                    pattern: "metrics:*".to_string(),
                    pattern_type: PatternType::Prefix,
                    backend: "postgres_analytics".to_string(),
                    priority: 80,
                },
                // User data patterns
                KeyRoutingRule {
                    pattern: "user:*".to_string(),
                    pattern_type: PatternType::Prefix,
                    backend: "postgres_users".to_string(),
                    priority: 70,
                },
                KeyRoutingRule {
                    pattern: "profile:*".to_string(),
                    pattern_type: PatternType::Prefix,
                    backend: "postgres_users".to_string(),
                    priority: 70,
                },
            ],
            load_balancing: Some(dbx_config::config::LoadBalancingConfig {
                strategy: LoadBalancingStrategy::RoundRobin,
                backends: vec![
                    "redis_cache".to_string(),
                    "redis_sessions".to_string(),
                    "postgres_analytics".to_string(),
                    "postgres_users".to_string(),
                ],
                health_check_interval_ms: 30000,
                weights: None,
            }),
        },
        consistency: dbx_config::config::ConsistencyConfig {
            level: dbx_core::ConsistencyLevel::Eventual,
            cross_backend: dbx_core::CrossBackendConsistency::BestEffort,
            transaction_timeout_ms: 10000,
            read_after_write: false,
            staleness_tolerance_ms: Some(2000),
        },
        performance: dbx_config::config::PerformanceConfig {
            query_timeout_ms: 30000,
            connection_timeout_ms: 5000,
            max_concurrent_operations: 200,
            cache_enabled: true,
            cache_ttl_ms: 300000,
            metrics_enabled: true,
            tracing_enabled: false,
            batch_size: 100,
        },
        security: dbx_config::config::SecurityConfig {
            authentication_required: false,
            authorization_enabled: false,
            encryption_at_rest: false,
            encryption_in_transit: false,
            audit_logging: false,
            rate_limiting: None,
            jwt: None,
            tls: None,
        },
        server: dbx_config::config::ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 8080,
            workers: Some(4),
            websocket_enabled: false,
            websocket_ping_interval: Some(30),
            max_body_size: 1024 * 1024,
            cors_enabled: false,
            cors_origins: vec![],
            request_timeout_ms: 30000,
        },
        admin: dbx_config::config::AdminConfig {
            create_default_admin: false,
            default_admin_username: None,
            default_admin_password: None,
            rbac: dbx_config::config::RbacConfig {
                audit_enabled: false,
                audit_retention_days: 30,
                max_role_inheritance_depth: 3,
                performance_cache_ttl_seconds: 300,
                default_assignment_ttl_days: None,
            },
        },
    };

    // Initialize all backends
    registry.initialize_backends(&config).await.unwrap();

    // Create and return the router
    BackendRouter::new(registry, &config).unwrap()
}

/// Test data cleanup helper
async fn cleanup_test_data(router: &BackendRouter, keys: &[String]) {
    for key in keys {
        let delete_op = DataOperation::Delete {
            key: key.clone(),
            fields: None,
        };

        if let Ok(backend) = router.route_data_operation(&delete_op).await {
            let _ = backend.execute_data(delete_op).await;
        }
    }
}

#[tokio::test]
async fn test_performance_benchmarking() {
    skip_if_backends_unavailable!();

    let router = create_production_router().await;
    let operation_count = 50;

    // Benchmark Redis performance
    let redis_backend = router
        .route_data_operation(&DataOperation::Set {
            key: "cache:benchmark".to_string(),
            value: DataValue::Bool(true),
            ttl: None,
        })
        .await
        .unwrap();

    let start = Instant::now();
    for i in 0..operation_count {
        let op = DataOperation::Set {
            key: format!("cache:perf:redis:{}", i),
            value: DataValue::Object({
                let mut obj = HashMap::new();
                obj.insert("id".to_string(), DataValue::Int(i));
                obj.insert(
                    "timestamp".to_string(),
                    DataValue::Int(chrono::Utc::now().timestamp()),
                );
                obj.insert(
                    "data".to_string(),
                    DataValue::String(format!("benchmark_data_{}", i)),
                );
                obj
            }),
            ttl: Some(3600),
        };
        redis_backend.execute_data(op).await.unwrap();
    }
    let redis_duration = start.elapsed();

    // Benchmark PostgreSQL performance
    let postgres_backend = router
        .route_data_operation(&DataOperation::Set {
            key: "analytics:benchmark".to_string(),
            value: DataValue::Bool(true),
            ttl: None,
        })
        .await
        .unwrap();

    let start = Instant::now();
    for i in 0..operation_count {
        let op = DataOperation::Set {
            key: format!("analytics:perf:postgres:{}", i),
            value: DataValue::Object({
                let mut obj = HashMap::new();
                obj.insert("id".to_string(), DataValue::Int(i));
                obj.insert(
                    "timestamp".to_string(),
                    DataValue::Int(chrono::Utc::now().timestamp()),
                );
                obj.insert(
                    "data".to_string(),
                    DataValue::String(format!("benchmark_data_{}", i)),
                );
                obj
            }),
            ttl: None,
        };
        postgres_backend.execute_data(op).await.unwrap();
    }
    let postgres_duration = start.elapsed();

    println!("Performance benchmark ({} operations):", operation_count);
    println!(
        "  Redis: {:?} ({:.2} ops/sec)",
        redis_duration,
        operation_count as f64 / redis_duration.as_secs_f64()
    );
    println!(
        "  PostgreSQL: {:?} ({:.2} ops/sec)",
        postgres_duration,
        operation_count as f64 / postgres_duration.as_secs_f64()
    );

    // Performance ratio analysis
    let ratio = redis_duration.as_millis() as f64 / postgres_duration.as_millis() as f64;
    if ratio < 1.0 {
        println!(
            "✓ Redis is {:.2}x faster than PostgreSQL for these operations",
            1.0 / ratio
        );
    } else {
        println!(
            "✓ PostgreSQL is {:.2}x faster than Redis for these operations",
            ratio
        );
    }

    // Cleanup benchmark data
    let cleanup_keys: Vec<String> = (0..operation_count)
        .flat_map(|i| {
            vec![
                format!("cache:perf:redis:{}", i),
                format!("analytics:perf:postgres:{}", i),
            ]
        })
        .collect();
    cleanup_test_data(&router, &cleanup_keys).await;
}

#[tokio::test]
async fn test_comprehensive_health_monitoring() {
    skip_if_backends_unavailable!();

    let router = create_production_router().await;

    // Test health checks across all backends
    let health_results = router.health_check_all().await;

    assert!(!health_results.is_empty(), "Should have health results");
    assert!(health_results.len() >= 4, "Should have at least 4 backends");

    let mut redis_backends = 0;
    let mut postgres_backends = 0;

    for (backend_name, health_result) in &health_results {
        let health = health_result.as_ref().unwrap();

        println!(
            "Backend: {}, Status: {:?}, Response time: {:?}ms",
            backend_name, health.status, health.response_time_ms
        );

        assert_eq!(health.status, dbx_core::HealthStatus::Healthy);
        assert!(health.response_time_ms.is_some());

        if backend_name.starts_with("redis") {
            redis_backends += 1;
        } else if backend_name.starts_with("postgres") {
            postgres_backends += 1;
        }
    }

    assert!(redis_backends >= 2, "Should have multiple Redis backends");
    assert!(
        postgres_backends >= 2,
        "Should have multiple PostgreSQL backends"
    );

    println!(
        "✓ Health monitoring verified: {} Redis, {} PostgreSQL backends",
        redis_backends, postgres_backends
    );
}

#[tokio::test]
async fn test_streaming_operations_routing() {
    skip_if_backends_unavailable!();

    let router = create_production_router().await;

    // Test that streaming operations route to Redis (which supports streaming)
    let redis_backend = router
        .route_data_operation(&DataOperation::Set {
            key: "cache:stream_test".to_string(),
            value: DataValue::Bool(true),
            ttl: None,
        })
        .await
        .unwrap();

    // Test stream publish
    let stream_op = StreamOperation::Publish {
        channel: "test_channel".to_string(),
        message: DataValue::Object({
            let mut obj = HashMap::new();
            obj.insert(
                "event".to_string(),
                DataValue::String("test_event".to_string()),
            );
            obj.insert(
                "timestamp".to_string(),
                DataValue::Int(chrono::Utc::now().timestamp()),
            );
            obj
        }),
    };

    let stream_result = redis_backend.execute_stream(stream_op).await;
    assert!(
        stream_result.is_ok(),
        "Redis should handle streaming operations"
    );

    match stream_result.unwrap() {
        dbx_core::StreamResult::Published {
            channel,
            message_id,
        } => {
            assert_eq!(channel, "test_channel");
            assert!(!message_id.is_empty());
            println!(
                "✓ Stream published to channel: {}, message_id: {}",
                channel, message_id
            );
        }
        _ => panic!("Expected Published result"),
    }

    // Cleanup
    let _ = redis_backend
        .execute_data(DataOperation::Delete {
            key: "cache:stream_test".to_string(),
            fields: None,
        })
        .await;
}

#[tokio::test]
async fn test_query_operations_routing() {
    skip_if_backends_unavailable!();

    let router = create_production_router().await;

    // Test Redis key pattern queries
    let redis_backend = router
        .route_data_operation(&DataOperation::Set {
            key: "cache:query_test".to_string(),
            value: DataValue::String("test_data".to_string()),
            ttl: None,
        })
        .await
        .unwrap();

    let query_op = QueryOperation {
        id: Uuid::new_v4(),
        filter: QueryFilter::KeyPattern {
            pattern: "cache:query*".to_string(),
        },
        projection: None,
        sort: None,
        limit: Some(10),
        offset: None,
    };

    let query_result = redis_backend.execute_query(query_op).await;
    assert!(
        query_result.is_ok(),
        "Redis should handle key pattern queries"
    );

    let result = query_result.unwrap();
    println!(
        "✓ Redis key pattern query executed, found {} results",
        result.total_count.unwrap_or(0)
    );

    // Cleanup
    let _ = redis_backend
        .execute_data(DataOperation::Delete {
            key: "cache:query_test".to_string(),
            fields: None,
        })
        .await;
}
