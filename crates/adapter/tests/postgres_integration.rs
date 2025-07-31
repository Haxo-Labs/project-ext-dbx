//! PostgreSQL adapter integration tests
//!
//! These tests verify the PostgreSQL adapter through the full backend interface,
//! testing real database interactions and integration with the broader system.

use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio_postgres::{connect, NoTls};
use uuid::Uuid;

use dbx_adapter::postgres::{PostgresBackend, PostgresBackendFactory, PostgresConnectionPool};
use dbx_config::BackendConfig;
use dbx_core::{DataOperation, DataValue, UniversalBackend};
use dbx_router::registry::{BackendFactory, BackendRegistryBuilder};

/// Test utilities for integration tests
mod utils {
    use super::*;

    pub fn get_test_postgres_url() -> String {
        env::var("TEST_POSTGRES_URL").unwrap_or_else(|_| {
            "postgresql://postgres:password@localhost:5432/dbx_test".to_string()
        })
    }

    pub async fn is_postgres_available() -> bool {
        let url = get_test_postgres_url();
        match connect(&url, NoTls).await {
            Ok((client, connection)) => {
                tokio::spawn(connection);
                client.simple_query("SELECT 1").await.is_ok()
            }
            Err(_) => false,
        }
    }

    pub fn create_test_config() -> BackendConfig {
        BackendConfig {
            provider: "postgresql".to_string(),
            url: get_test_postgres_url(),
            pool_size: Some(5),
            timeout_ms: Some(5000),
            retry_attempts: Some(3),
            retry_delay_ms: Some(1000),
            capabilities: None,
            additional_config: HashMap::new(),
        }
    }

    pub async fn create_test_backend(
    ) -> Result<Arc<dyn UniversalBackend>, Box<dyn std::error::Error + Send + Sync>> {
        if !is_postgres_available().await {
            return Err("PostgreSQL not available for testing".into());
        }

        let config = create_test_config();
        let factory = PostgresBackendFactory::new();
        let backend = factory.create_backend("test_postgres", &config).await?;

        Ok(backend)
    }

    /// Macro to skip tests if PostgreSQL is not available
    macro_rules! skip_if_no_postgres {
        () => {
            if !utils::is_postgres_available().await {
                eprintln!("Skipping integration test: PostgreSQL not available");
                return;
            }
        };
    }

    pub(crate) use skip_if_no_postgres;
}

/// Test factory registration and backend creation through the registry
#[tokio::test]
async fn test_factory_registration() {
    utils::skip_if_no_postgres!();

    let postgres_factory = PostgresBackendFactory::new();
    let mut registry_builder = BackendRegistryBuilder::new();

    registry_builder = registry_builder.with_factory("postgresql", postgres_factory);
    let registry = registry_builder.build();

    // Verify factory is registered
    assert!(registry.has_factory("postgresql"));

    // Test backend creation directly through factory
    let factory = PostgresBackendFactory::new();
    let config = utils::create_test_config();
    let result = factory.create_backend("test_postgres", &config).await;

    assert!(
        result.is_ok(),
        "Backend creation through factory should succeed"
    );

    let backend = result.unwrap();
    assert_eq!(backend.name(), "test_postgres");
}

/// Test end-to-end data flow through the backend
#[tokio::test]
async fn test_end_to_end_data_flow() {
    utils::skip_if_no_postgres!();

    let backend = utils::create_test_backend().await.unwrap();
    let test_key = format!("integration:e2e:{}", Uuid::new_v4());

    // Test complex data structure
    let complex_data = DataValue::Object({
        let mut map = HashMap::new();
        map.insert("user_id".to_string(), DataValue::Int(12345));
        map.insert(
            "username".to_string(),
            DataValue::String("test_user".to_string()),
        );
        map.insert("active".to_string(), DataValue::Bool(true));
        map.insert(
            "scores".to_string(),
            DataValue::Array(vec![
                DataValue::Int(100),
                DataValue::Int(85),
                DataValue::Int(92),
            ]),
        );
        map.insert(
            "metadata".to_string(),
            DataValue::Object({
                let mut meta = HashMap::new();
                meta.insert(
                    "created_at".to_string(),
                    DataValue::String("2024-01-01".to_string()),
                );
                meta.insert("version".to_string(), DataValue::Float(1.2));
                meta
            }),
        );
        map
    });

    // Store complex data
    let set_op = DataOperation::Set {
        key: test_key.clone(),
        value: complex_data.clone(),
        ttl: Some(300), // 5 minutes
    };
    let result = backend.execute_data(set_op).await.unwrap();
    assert!(result.is_success());

    // Retrieve and verify
    let get_op = DataOperation::Get {
        key: test_key.clone(),
        fields: None,
    };
    let result = backend.execute_data(get_op).await.unwrap();
    assert!(result.is_success());
    assert_eq!(result.data, Some(complex_data));

    // Test TTL
    let get_ttl_op = DataOperation::GetTtl {
        key: test_key.clone(),
    };
    let result = backend.execute_data(get_ttl_op).await.unwrap();
    assert!(result.is_success());
    if let Some(DataValue::Int(ttl)) = result.data {
        assert!(ttl > 0 && ttl <= 300);
    }

    // Cleanup
    let delete_op = DataOperation::Delete {
        key: test_key,
        fields: None,
    };
    let _ = backend.execute_data(delete_op).await;
}

/// Test concurrent access patterns
#[tokio::test]
async fn test_concurrent_access_patterns() {
    utils::skip_if_no_postgres!();

    let backend = Arc::new(utils::create_test_backend().await.unwrap());
    let base_key = format!("integration:concurrent:{}", Uuid::new_v4());

    let start_time = Instant::now();

    // Spawn multiple concurrent tasks with different operation patterns
    let mut handles = vec![];

    // Write-heavy tasks
    for i in 0..10 {
        let backend_clone = Arc::clone(&backend);
        let key = format!("{}:write:{}", base_key, i);

        let handle = tokio::spawn(async move {
            for j in 0..5 {
                let set_op = DataOperation::Set {
                    key: format!("{}:{}", key, j),
                    value: DataValue::String(format!("write_value_{}_{}", i, j)),
                    ttl: None,
                };
                let result = backend_clone.execute_data(set_op).await;
                assert!(result.is_ok());
            }
        });
        handles.push(handle);
    }

    // Read-heavy tasks
    for i in 0..5 {
        let backend_clone = Arc::clone(&backend);
        let key = format!("{}:read:{}", base_key, i);

        let handle = tokio::spawn(async move {
            // First write a value
            let set_op = DataOperation::Set {
                key: key.clone(),
                value: DataValue::String(format!("read_value_{}", i)),
                ttl: None,
            };
            let _ = backend_clone.execute_data(set_op).await.unwrap();

            // Then read it multiple times
            for _ in 0..10 {
                let get_op = DataOperation::Get {
                    key: key.clone(),
                    fields: None,
                };
                let result = backend_clone.execute_data(get_op).await;
                assert!(result.is_ok());
            }
        });
        handles.push(handle);
    }

    // Mixed operation tasks
    for i in 0..5 {
        let backend_clone = Arc::clone(&backend);
        let key = format!("{}:mixed:{}", base_key, i);

        let handle = tokio::spawn(async move {
            // Set initial value
            let set_op = DataOperation::Set {
                key: key.clone(),
                value: DataValue::Int(0),
                ttl: None,
            };
            let _ = backend_clone.execute_data(set_op).await.unwrap();

            // Increment multiple times
            for _ in 0..3 {
                let inc_op = DataOperation::Increment {
                    key: key.clone(),
                    amount: 1,
                };
                let result = backend_clone.execute_data(inc_op).await;
                assert!(result.is_ok());
            }

            // Check final value
            let get_op = DataOperation::Get {
                key: key.clone(),
                fields: None,
            };
            let result = backend_clone.execute_data(get_op).await.unwrap();
            assert!(result.is_success());
        });
        handles.push(handle);
    }

    // Wait for all tasks to complete
    for handle in handles {
        handle.await.unwrap();
    }

    let duration = start_time.elapsed();
    println!("Concurrent operations completed in: {:?}", duration);

    // Should complete within reasonable time
    assert!(
        duration.as_secs() < 30,
        "Concurrent operations took too long"
    );

    // Cleanup
    for category in ["write", "read", "mixed"] {
        for i in 0..10 {
            let key = if category == "write" {
                for j in 0..5 {
                    let delete_op = DataOperation::Delete {
                        key: format!("{}:{}:{}:{}", base_key, category, i, j),
                        fields: None,
                    };
                    let _ = backend.execute_data(delete_op).await;
                }
                continue;
            } else {
                format!("{}:{}:{}", base_key, category, i)
            };

            let delete_op = DataOperation::Delete { key, fields: None };
            let _ = backend.execute_data(delete_op).await;
        }
    }
}

/// Test transaction-like behavior with compare-and-swap
#[tokio::test]
async fn test_transaction_patterns() {
    utils::skip_if_no_postgres!();

    let backend = Arc::new(utils::create_test_backend().await.unwrap());
    let test_key = format!("integration:transaction:{}", Uuid::new_v4());

    // Set initial counter value
    let set_op = DataOperation::Set {
        key: test_key.clone(),
        value: DataValue::Int(0),
        ttl: None,
    };
    let result = backend.execute_data(set_op).await.unwrap();
    assert!(result.is_success());

    // Simulate concurrent counter increments using CAS
    let mut handles = vec![];
    for _i in 0..10 {
        let backend_clone = Arc::clone(&backend);
        let key_clone = test_key.clone();

        let handle = tokio::spawn(async move {
            for attempt in 0..5 {
                // Read current value
                let get_op = DataOperation::Get {
                    key: key_clone.clone(),
                    fields: None,
                };
                let result = backend_clone.execute_data(get_op).await.unwrap();

                if let Some(DataValue::Int(current_value)) = result.data {
                    // Try to increment with CAS
                    let new_value = current_value + 1;
                    let cas_op = DataOperation::CompareAndSwap {
                        key: key_clone.clone(),
                        expected_value: current_value.to_string(),
                        new_value: new_value.to_string(),
                        ttl: None,
                    };

                    let cas_result = backend_clone.execute_data(cas_op).await.unwrap();
                    if let Some(DataValue::Bool(success)) = cas_result.data {
                        if success {
                            // CAS succeeded, we're done
                            return Ok(());
                        }
                    }
                }

                // CAS failed, retry with backoff
                tokio::time::sleep(Duration::from_millis(10 * attempt as u64)).await;
            }

            Err::<(), Box<dyn std::error::Error + Send + Sync>>("CAS failed after retries".into())
        });
        handles.push(handle);
    }

    // Wait for all increment attempts
    let mut successful_increments = 0;
    for handle in handles {
        if handle.await.unwrap().is_ok() {
            successful_increments += 1;
        }
    }

    // Check final value
    let get_final = DataOperation::Get {
        key: test_key.clone(),
        fields: None,
    };
    let result = backend.execute_data(get_final).await.unwrap();
    assert!(result.is_success());

    if let Some(DataValue::Int(final_value)) = result.data {
        // Final value should reflect the successful increments
        assert!(final_value > 0);
        assert!(final_value <= 10); // At most 10 increments
        println!(
            "Final counter value: {}, Successful increments: {}",
            final_value, successful_increments
        );
    }

    // Cleanup
    let delete_op = DataOperation::Delete {
        key: test_key,
        fields: None,
    };
    let _ = backend.execute_data(delete_op).await;
}

/// Test performance characteristics
#[tokio::test]
async fn test_performance_characteristics() {
    utils::skip_if_no_postgres!();

    let backend = utils::create_test_backend().await.unwrap();
    let base_key = format!("integration:perf:{}", Uuid::new_v4());

    // Test batch operation performance
    let batch_size = 100;
    let mut operations = Vec::with_capacity(batch_size);

    for i in 0..batch_size {
        operations.push(DataOperation::Set {
            key: format!("{}:batch:{}", base_key, i),
            value: DataValue::String(format!("batch_value_{}", i)),
            ttl: None,
        });
    }

    let batch_start = Instant::now();
    let batch_op = DataOperation::Batch { operations };
    let result = backend.execute_data(batch_op).await.unwrap();
    let batch_duration = batch_start.elapsed();

    assert!(result.is_success());
    println!(
        "Batch of {} operations took: {:?}",
        batch_size, batch_duration
    );

    // Batch should be faster than individual operations
    assert!(
        batch_duration.as_millis() < 5000,
        "Batch operations should be reasonably fast"
    );

    // Test individual operation performance
    let individual_start = Instant::now();
    for i in 0..10 {
        let set_op = DataOperation::Set {
            key: format!("{}:individual:{}", base_key, i),
            value: DataValue::String(format!("individual_value_{}", i)),
            ttl: None,
        };
        let result = backend.execute_data(set_op).await.unwrap();
        assert!(result.is_success());
    }
    let individual_duration = individual_start.elapsed();

    println!("10 individual operations took: {:?}", individual_duration);

    // Test health check performance
    let health_start = Instant::now();
    let health = backend.health_check().await.unwrap();
    let health_duration = health_start.elapsed();

    assert_eq!(health.status, dbx_core::HealthStatus::Healthy);
    assert!(
        health_duration.as_millis() < 1000,
        "Health check should be fast"
    );

    // Test stats retrieval performance
    let stats_start = Instant::now();
    let stats = backend.get_stats().await.unwrap();
    let stats_duration = stats_start.elapsed();

    assert!(stats.connections.total <= stats.connections.max_pool_size);
    assert!(
        stats_duration.as_millis() < 1000,
        "Stats retrieval should be fast"
    );

    // Cleanup
    for i in 0..batch_size {
        let delete_op = DataOperation::Delete {
            key: format!("{}:batch:{}", base_key, i),
            fields: None,
        };
        let _ = backend.execute_data(delete_op).await;
    }

    for i in 0..10 {
        let delete_op = DataOperation::Delete {
            key: format!("{}:individual:{}", base_key, i),
            fields: None,
        };
        let _ = backend.execute_data(delete_op).await;
    }
}

/// Test error recovery and resilience
#[tokio::test]
async fn test_error_recovery() {
    utils::skip_if_no_postgres!();

    let backend = utils::create_test_backend().await.unwrap();
    let test_key = format!("integration:error:{}", Uuid::new_v4());

    // Test operations on non-existent keys
    let get_nonexistent = DataOperation::Get {
        key: format!("{}:nonexistent", test_key),
        fields: None,
    };
    let result = backend.execute_data(get_nonexistent).await.unwrap();
    assert!(result.is_success());
    assert_eq!(result.data, Some(DataValue::Null));

    // Test large payload handling
    let large_string = "x".repeat(100_000); // 100KB string
    let set_large = DataOperation::Set {
        key: format!("{}:large", test_key),
        value: DataValue::String(large_string.clone()),
        ttl: None,
    };

    let result = backend.execute_data(set_large).await;
    match result {
        Ok(res) => {
            assert!(res.is_success());

            // Verify we can retrieve it
            let get_large = DataOperation::Get {
                key: format!("{}:large", test_key),
                fields: None,
            };
            let get_result = backend.execute_data(get_large).await.unwrap();
            assert!(get_result.is_success());
            assert_eq!(get_result.data, Some(DataValue::String(large_string)));

            // Cleanup large value
            let delete_large = DataOperation::Delete {
                key: format!("{}:large", test_key),
                fields: None,
            };
            let _ = backend.execute_data(delete_large).await;
        }
        Err(_) => {
            // Large payloads might be rejected, which is acceptable
            println!("Large payload was rejected (acceptable behavior)");
        }
    }

    // Test invalid increment operations
    let set_string = DataOperation::Set {
        key: format!("{}:string", test_key),
        value: DataValue::String("not_a_number".to_string()),
        ttl: None,
    };
    let _ = backend.execute_data(set_string).await.unwrap();

    let inc_string = DataOperation::Increment {
        key: format!("{}:string", test_key),
        amount: 1,
    };
    let result = backend.execute_data(inc_string).await;

    // Should handle gracefully (either succeed with conversion or fail gracefully)
    match result {
        Ok(_) => println!("String increment handled gracefully"),
        Err(_) => println!("String increment rejected gracefully"),
    }

    // Cleanup
    let delete_string = DataOperation::Delete {
        key: format!("{}:string", test_key),
        fields: None,
    };
    let _ = backend.execute_data(delete_string).await;
}

/// Test connection pool behavior under load
#[tokio::test]
async fn test_connection_pool_behavior() {
    utils::skip_if_no_postgres!();

    let config = utils::create_test_config();
    let pool = PostgresConnectionPool::new(&config.url, 3).unwrap(); // Small pool for testing
    let backend = PostgresBackend::new(Arc::new(pool), "test_pool".to_string());
    let backend = Arc::new(backend);

    let base_key = format!("integration:pool:{}", Uuid::new_v4());

    // Create more concurrent tasks than pool size
    let mut handles = vec![];
    for i in 0..10 {
        let backend_clone = Arc::clone(&backend);
        let key = format!("{}:{}", base_key, i);

        let handle = tokio::spawn(async move {
            let set_op = DataOperation::Set {
                key: key.clone(),
                value: DataValue::String(format!("pool_test_{}", i)),
                ttl: None,
            };

            let start = Instant::now();
            let result = backend_clone.execute_data(set_op).await;
            let duration = start.elapsed();

            (result, duration)
        });
        handles.push(handle);
    }

    // Collect results
    let mut total_duration = Duration::new(0, 0);
    let mut success_count = 0;

    for handle in handles {
        let (result, duration) = handle.await.unwrap();
        total_duration += duration;

        if result.is_ok() {
            success_count += 1;
        }
    }

    // All operations should succeed despite limited pool size
    assert_eq!(
        success_count, 10,
        "All operations should succeed with pool management"
    );

    let avg_duration = total_duration / 10;
    println!(
        "Average operation duration with limited pool: {:?}",
        avg_duration
    );

    // Cleanup
    for i in 0..10 {
        let delete_op = DataOperation::Delete {
            key: format!("{}:{}", base_key, i),
            fields: None,
        };
        let _ = backend.execute_data(delete_op).await;
    }
}
