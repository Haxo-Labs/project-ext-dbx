//! Multi-backend integration tests
//!
//! These tests verify that multiple database backends can coexist
//! and operate correctly together in the same system.

use dbx_adapter::postgres::factory::PostgresBackendFactory;
use dbx_adapter::redis::factory::RedisBackendFactory;
use dbx_config::BackendConfig;
use dbx_core::{DataOperation, DataValue};
use dbx_router::registry::{BackendFactory, BackendRegistryBuilder};
use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use tokio;

/// Get test PostgreSQL URL from environment or use default
fn get_test_postgres_url() -> String {
    env::var("TEST_POSTGRES_URL")
        .unwrap_or_else(|_| "postgresql://postgres:password@localhost:5432/dbx_test".to_string())
}

/// Get test Redis URL from environment or use default
fn get_test_redis_url() -> String {
    env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string())
}

/// Check if PostgreSQL is available for testing
async fn is_postgres_available() -> bool {
    use tokio_postgres::connect;
    let url = get_test_postgres_url();
    match connect(&url, tokio_postgres::NoTls).await {
        Ok((client, connection)) => {
            tokio::spawn(connection);
            client.simple_query("SELECT 1").await.is_ok()
        }
        Err(_) => false,
    }
}

/// Check if Redis is available for testing
async fn is_redis_available() -> bool {
    use redis::Client;
    let url = get_test_redis_url();
    match Client::open(url) {
        Ok(client) => match client.get_connection() {
            Ok(mut conn) => redis::cmd("PING").query::<String>(&mut conn).is_ok(),
            Err(_) => false,
        },
        Err(_) => false,
    }
}

/// Macro to skip tests if required backends are not available
macro_rules! skip_if_backends_unavailable {
    ($postgres:expr, $redis:expr) => {
        if $postgres && !is_postgres_available().await {
            eprintln!("Skipping test: PostgreSQL not available");
            return;
        }
        if $redis && !is_redis_available().await {
            eprintln!("Skipping test: Redis not available");
            return;
        }
    };
}

#[tokio::test]
async fn test_backend_factory_registry() {
    // Test that both PostgreSQL and Redis factories can be registered together
    let mut registry_builder = BackendRegistryBuilder::new();

    let postgres_factory = PostgresBackendFactory::new();
    let redis_factory = RedisBackendFactory::new();

    registry_builder = registry_builder.with_factory("postgresql", postgres_factory);
    registry_builder = registry_builder.with_factory("redis", redis_factory);

    let registry = registry_builder.build();

    // Verify both factories are registered
    assert!(registry.has_factory("postgresql"));
    assert!(registry.has_factory("redis"));

    let mut provider_names = registry.get_provider_names();
    provider_names.sort();
    assert_eq!(provider_names, vec!["postgresql", "redis"]);
}

#[tokio::test]
async fn test_multi_backend_creation() {
    skip_if_backends_unavailable!(true, true);

    // Create configurations for both backends
    let postgres_config = BackendConfig {
        provider: "postgresql".to_string(),
        url: get_test_postgres_url(),
        pool_size: Some(5),
        timeout_ms: Some(5000),
        retry_attempts: Some(3),
        retry_delay_ms: Some(1000),
        capabilities: None,
        additional_config: HashMap::new(),
    };

    let redis_config = BackendConfig {
        provider: "redis".to_string(),
        url: get_test_redis_url(),
        pool_size: Some(5),
        timeout_ms: Some(5000),
        retry_attempts: Some(3),
        retry_delay_ms: Some(1000),
        capabilities: None,
        additional_config: HashMap::new(),
    };

    // Create backend factories
    let postgres_factory = PostgresBackendFactory::new();
    let redis_factory = RedisBackendFactory::new();

    // Create backends
    let postgres_backend = postgres_factory
        .create_backend("postgres", &postgres_config)
        .await;
    let redis_backend = redis_factory.create_backend("redis", &redis_config).await;

    assert!(
        postgres_backend.is_ok(),
        "PostgreSQL backend creation failed: {:?}",
        postgres_backend.err()
    );
    assert!(
        redis_backend.is_ok(),
        "Redis backend creation failed: {:?}",
        redis_backend.err()
    );

    let postgres_backend = postgres_backend.unwrap();
    let redis_backend = redis_backend.unwrap();

    // Verify backends have different names and capabilities
    assert_eq!(postgres_backend.name(), "postgres");
    assert_eq!(redis_backend.name(), "redis");

    // Verify both backends are healthy
    let postgres_health = postgres_backend.health_check().await;
    let redis_health = redis_backend.health_check().await;

    assert!(
        postgres_health.is_ok(),
        "PostgreSQL health check failed: {:?}",
        postgres_health.err()
    );
    assert!(
        redis_health.is_ok(),
        "Redis health check failed: {:?}",
        redis_health.err()
    );
}

#[tokio::test]
async fn test_cross_backend_data_operations() {
    skip_if_backends_unavailable!(true, true);

    // Create both backends
    let postgres_config = BackendConfig {
        provider: "postgresql".to_string(),
        url: get_test_postgres_url(),
        pool_size: Some(5),
        timeout_ms: Some(5000),
        retry_attempts: Some(3),
        retry_delay_ms: Some(1000),
        capabilities: None,
        additional_config: HashMap::new(),
    };

    let redis_config = BackendConfig {
        provider: "redis".to_string(),
        url: get_test_redis_url(),
        pool_size: Some(5),
        timeout_ms: Some(5000),
        retry_attempts: Some(3),
        retry_delay_ms: Some(1000),
        capabilities: None,
        additional_config: HashMap::new(),
    };

    let postgres_factory = PostgresBackendFactory::new();
    let redis_factory = RedisBackendFactory::new();

    let postgres_backend = postgres_factory
        .create_backend("postgres", &postgres_config)
        .await
        .unwrap();
    let redis_backend = redis_factory
        .create_backend("redis", &redis_config)
        .await
        .unwrap();

    // Test same operations on both backends
    let test_data = vec![
        (
            "test:multi:string",
            DataValue::String("Hello from both backends!".to_string()),
        ),
        ("test:multi:int", DataValue::Int(42)),
        ("test:multi:bool", DataValue::Bool(true)),
        ("test:multi:float", DataValue::Float(3.14159)),
    ];

    for (key, value) in test_data {
        // Set in both backends
        let postgres_set = DataOperation::Set {
            key: format!("postgres:{}", key),
            value: value.clone(),
            ttl: None,
        };

        let redis_set = DataOperation::Set {
            key: format!("redis:{}", key),
            value: value.clone(),
            ttl: None,
        };

        let postgres_result = postgres_backend.execute_data(postgres_set).await.unwrap();
        let redis_result = redis_backend.execute_data(redis_set).await.unwrap();

        assert!(
            postgres_result.is_success(),
            "PostgreSQL set failed for key: {}",
            key
        );
        assert!(
            redis_result.is_success(),
            "Redis set failed for key: {}",
            key
        );

        // Get from both backends
        let postgres_get = DataOperation::Get {
            key: format!("postgres:{}", key),
            fields: None,
        };

        let redis_get = DataOperation::Get {
            key: format!("redis:{}", key),
            fields: None,
        };

        let postgres_result = postgres_backend.execute_data(postgres_get).await.unwrap();
        let redis_result = redis_backend.execute_data(redis_get).await.unwrap();

        assert!(
            postgres_result.is_success(),
            "PostgreSQL get failed for key: {}",
            key
        );
        assert!(
            redis_result.is_success(),
            "Redis get failed for key: {}",
            key
        );
        assert_eq!(
            postgres_result.data,
            Some(value.clone()),
            "PostgreSQL data mismatch for key: {}",
            key
        );
        assert_eq!(
            redis_result.data,
            Some(value.clone()),
            "Redis data mismatch for key: {}",
            key
        );
    }

    // Cleanup
    for (key, _) in [
        ("test:multi:string", DataValue::String("".to_string())),
        ("test:multi:int", DataValue::Int(0)),
        ("test:multi:bool", DataValue::Bool(false)),
        ("test:multi:float", DataValue::Float(0.0)),
    ] {
        let postgres_delete = DataOperation::Delete {
            key: format!("postgres:{}", key),
            fields: None,
        };
        let redis_delete = DataOperation::Delete {
            key: format!("redis:{}", key),
            fields: None,
        };

        let _ = postgres_backend.execute_data(postgres_delete).await;
        let _ = redis_backend.execute_data(redis_delete).await;
    }
}

#[tokio::test]
async fn test_backend_capabilities_comparison() {
    skip_if_backends_unavailable!(true, true);

    let postgres_config = BackendConfig {
        provider: "postgresql".to_string(),
        url: get_test_postgres_url(),
        pool_size: Some(5),
        timeout_ms: Some(5000),
        retry_attempts: Some(3),
        retry_delay_ms: Some(1000),
        capabilities: None,
        additional_config: HashMap::new(),
    };

    let redis_config = BackendConfig {
        provider: "redis".to_string(),
        url: get_test_redis_url(),
        pool_size: Some(5),
        timeout_ms: Some(5000),
        retry_attempts: Some(3),
        retry_delay_ms: Some(1000),
        capabilities: None,
        additional_config: HashMap::new(),
    };

    let postgres_factory = PostgresBackendFactory::new();
    let redis_factory = RedisBackendFactory::new();

    let postgres_backend = postgres_factory
        .create_backend("postgres", &postgres_config)
        .await
        .unwrap();
    let redis_backend = redis_factory
        .create_backend("redis", &redis_config)
        .await
        .unwrap();

    let postgres_capabilities = postgres_backend.capabilities();
    let redis_capabilities = redis_backend.capabilities();

    // Both should support basic operations
    use dbx_core::DataOperationType;
    let basic_operations = vec![
        DataOperationType::Get,
        DataOperationType::Set,
        DataOperationType::Delete,
        DataOperationType::Exists,
    ];

    for operation in basic_operations {
        assert!(
            postgres_capabilities.data_operations.contains(&operation),
            "PostgreSQL should support {:?}",
            operation
        );
        assert!(
            redis_capabilities.data_operations.contains(&operation),
            "Redis should support {:?}",
            operation
        );
    }

    // PostgreSQL should support more advanced features
    use dbx_core::BackendFeature;
    assert!(
        postgres_capabilities
            .features
            .contains(&BackendFeature::JsonSupport),
        "PostgreSQL should support JSON"
    );
    assert!(
        postgres_capabilities.query_capabilities.field_filters,
        "PostgreSQL should support field filters"
    );
    assert!(
        postgres_capabilities.query_capabilities.aggregations,
        "PostgreSQL should support aggregations"
    );

    // Redis should support some features too
    assert!(
        redis_capabilities
            .features
            .contains(&BackendFeature::JsonSupport),
        "Redis should support JSON"
    );
    assert!(
        redis_capabilities.stream_capabilities.pub_sub,
        "Redis should support pub/sub"
    );
}

#[tokio::test]
async fn test_concurrent_multi_backend_operations() {
    skip_if_backends_unavailable!(true, true);

    let postgres_config = BackendConfig {
        provider: "postgresql".to_string(),
        url: get_test_postgres_url(),
        pool_size: Some(10),
        timeout_ms: Some(5000),
        retry_attempts: Some(3),
        retry_delay_ms: Some(1000),
        capabilities: None,
        additional_config: HashMap::new(),
    };

    let redis_config = BackendConfig {
        provider: "redis".to_string(),
        url: get_test_redis_url(),
        pool_size: Some(10),
        timeout_ms: Some(5000),
        retry_attempts: Some(3),
        retry_delay_ms: Some(1000),
        capabilities: None,
        additional_config: HashMap::new(),
    };

    let postgres_factory = PostgresBackendFactory::new();
    let redis_factory = RedisBackendFactory::new();

    let postgres_backend = Arc::new(
        postgres_factory
            .create_backend("postgres", &postgres_config)
            .await
            .unwrap(),
    );
    let redis_backend = Arc::new(
        redis_factory
            .create_backend("redis", &redis_config)
            .await
            .unwrap(),
    );

    // Perform concurrent operations on both backends
    let mut handles = vec![];

    for i in 0..10 {
        let postgres_backend_clone = Arc::clone(&postgres_backend);
        let redis_backend_clone = Arc::clone(&redis_backend);

        let handle = tokio::spawn(async move {
            // PostgreSQL operations
            let postgres_set = DataOperation::Set {
                key: format!("test:concurrent:postgres:{}", i),
                value: DataValue::String(format!("postgres_value_{}", i)),
                ttl: None,
            };

            let postgres_result = postgres_backend_clone.execute_data(postgres_set).await;
            assert!(postgres_result.is_ok() && postgres_result.unwrap().is_success());

            // Redis operations
            let redis_set = DataOperation::Set {
                key: format!("test:concurrent:redis:{}", i),
                value: DataValue::String(format!("redis_value_{}", i)),
                ttl: None,
            };

            let redis_result = redis_backend_clone.execute_data(redis_set).await;
            assert!(redis_result.is_ok() && redis_result.unwrap().is_success());
        });

        handles.push(handle);
    }

    // Wait for all operations to complete
    for handle in handles {
        handle.await.unwrap();
    }

    // Verify all operations succeeded
    for i in 0..10 {
        let postgres_get = DataOperation::Get {
            key: format!("test:concurrent:postgres:{}", i),
            fields: None,
        };

        let redis_get = DataOperation::Get {
            key: format!("test:concurrent:redis:{}", i),
            fields: None,
        };

        let postgres_result = postgres_backend.execute_data(postgres_get).await.unwrap();
        let redis_result = redis_backend.execute_data(redis_get).await.unwrap();

        assert!(postgres_result.is_success());
        assert!(redis_result.is_success());
        assert_eq!(
            postgres_result.data,
            Some(DataValue::String(format!("postgres_value_{}", i)))
        );
        assert_eq!(
            redis_result.data,
            Some(DataValue::String(format!("redis_value_{}", i)))
        );
    }

    // Cleanup
    for i in 0..10 {
        let postgres_delete = DataOperation::Delete {
            key: format!("test:concurrent:postgres:{}", i),
            fields: None,
        };
        let redis_delete = DataOperation::Delete {
            key: format!("test:concurrent:redis:{}", i),
            fields: None,
        };

        let _ = postgres_backend.execute_data(postgres_delete).await;
        let _ = redis_backend.execute_data(redis_delete).await;
    }
}

#[tokio::test]
async fn test_backend_performance_comparison() {
    skip_if_backends_unavailable!(true, true);

    use std::time::Instant;

    let postgres_config = BackendConfig {
        provider: "postgresql".to_string(),
        url: get_test_postgres_url(),
        pool_size: Some(10),
        timeout_ms: Some(5000),
        retry_attempts: Some(3),
        retry_delay_ms: Some(1000),
        capabilities: None,
        additional_config: HashMap::new(),
    };

    let redis_config = BackendConfig {
        provider: "redis".to_string(),
        url: get_test_redis_url(),
        pool_size: Some(10),
        timeout_ms: Some(5000),
        retry_attempts: Some(3),
        retry_delay_ms: Some(1000),
        capabilities: None,
        additional_config: HashMap::new(),
    };

    let postgres_factory = PostgresBackendFactory::new();
    let redis_factory = RedisBackendFactory::new();

    let postgres_backend = postgres_factory
        .create_backend("postgres", &postgres_config)
        .await
        .unwrap();
    let redis_backend = redis_factory
        .create_backend("redis", &redis_config)
        .await
        .unwrap();

    // Benchmark simple operations
    let operation_count = 50;

    // PostgreSQL benchmark
    let postgres_start = Instant::now();
    for i in 0..operation_count {
        let set_op = DataOperation::Set {
            key: format!("test:perf:postgres:{}", i),
            value: DataValue::String(format!("value_{}", i)),
            ttl: None,
        };
        let _ = postgres_backend.execute_data(set_op).await.unwrap();
    }
    let postgres_duration = postgres_start.elapsed();

    // Redis benchmark
    let redis_start = Instant::now();
    for i in 0..operation_count {
        let set_op = DataOperation::Set {
            key: format!("test:perf:redis:{}", i),
            value: DataValue::String(format!("value_{}", i)),
            ttl: None,
        };
        let _ = redis_backend.execute_data(set_op).await.unwrap();
    }
    let redis_duration = redis_start.elapsed();

    println!(
        "PostgreSQL: {} operations in {:?}",
        operation_count, postgres_duration
    );
    println!(
        "Redis: {} operations in {:?}",
        operation_count, redis_duration
    );

    // Both should complete reasonably quickly (less than 5 seconds for 50 operations)
    assert!(
        postgres_duration.as_secs() < 5,
        "PostgreSQL performance too slow"
    );
    assert!(redis_duration.as_secs() < 5, "Redis performance too slow");

    // Cleanup
    for i in 0..operation_count {
        let postgres_delete = DataOperation::Delete {
            key: format!("test:perf:postgres:{}", i),
            fields: None,
        };
        let redis_delete = DataOperation::Delete {
            key: format!("test:perf:redis:{}", i),
            fields: None,
        };

        let _ = postgres_backend.execute_data(postgres_delete).await;
        let _ = redis_backend.execute_data(redis_delete).await;
    }
}
