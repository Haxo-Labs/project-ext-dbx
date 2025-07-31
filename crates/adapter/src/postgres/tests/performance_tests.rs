//! PostgreSQL performance and load tests

use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;

use super::utils::{self, skip_if_no_postgres};
use dbx_core::{DataOperation, DataValue, UniversalBackend};

#[tokio::test]
async fn test_concurrent_operations() {
    skip_if_no_postgres!();

    let backend = Arc::new(utils::create_test_backend().await.unwrap());
    let base_key = format!("test:concurrent:{}", Uuid::new_v4());

    let start_time = Instant::now();

    // Perform 50 concurrent operations
    let mut handles = vec![];
    for i in 0..50 {
        let backend_clone = Arc::clone(&backend);
        let key = format!("{}:{}", base_key, i);

        let handle = tokio::spawn(async move {
            let set_op = DataOperation::Set {
                key: key.clone(),
                value: DataValue::String(format!("value_{}", i)),
                ttl: None,
            };
            backend_clone.execute_data(set_op).await
        });
        handles.push(handle);
    }

    // Wait for all operations to complete
    for handle in handles {
        let result = handle.await.unwrap().unwrap();
        assert!(result.is_success());
    }

    let duration = start_time.elapsed();
    println!("50 concurrent operations took: {:?}", duration);

    // Should complete within reasonable time
    assert!(
        duration.as_secs() < 30,
        "Concurrent operations took too long"
    );

    // Cleanup
    for i in 0..50 {
        let delete_op = DataOperation::Delete {
            key: format!("{}:{}", base_key, i),
            fields: None,
        };
        let _ = backend.execute_data(delete_op).await;
    }
}

#[tokio::test]
async fn test_batch_performance() {
    skip_if_no_postgres!();

    let backend = utils::create_test_backend().await.unwrap();
    let base_key = format!("test:batch_perf:{}", Uuid::new_v4());

    // Create 100 operations
    let mut operations = Vec::new();
    for i in 0..100 {
        operations.push(DataOperation::Set {
            key: format!("{}:{}", base_key, i),
            value: DataValue::String(format!("batch_value_{}", i)),
            ttl: None,
        });
    }

    let start_time = Instant::now();

    let batch_op = DataOperation::Batch { operations };
    let result = backend.execute_data(batch_op).await.unwrap();
    assert!(result.is_success());

    let duration = start_time.elapsed();
    println!("Batch of 100 operations took: {:?}", duration);

    // Should be reasonably fast
    assert!(duration.as_secs() < 10, "Batch operations took too long");

    // Cleanup
    for i in 0..100 {
        let delete_op = DataOperation::Delete {
            key: format!("{}:{}", base_key, i),
            fields: None,
        };
        let _ = backend.execute_data(delete_op).await;
    }
}

#[tokio::test]
async fn test_large_data_performance() {
    skip_if_no_postgres!();

    let backend = utils::create_test_backend().await.unwrap();
    let test_key = format!("test:large_perf:{}", Uuid::new_v4());

    // Test with different data sizes
    let sizes = [1024, 10240, 102400]; // 1KB, 10KB, 100KB

    for size in &sizes {
        let large_data = "x".repeat(*size);

        let start_time = Instant::now();

        let set_op = DataOperation::Set {
            key: format!("{}:{}", test_key, size),
            value: DataValue::String(large_data.clone()),
            ttl: None,
        };

        let result = backend.execute_data(set_op).await;

        match result {
            Ok(res) => {
                assert!(res.is_success());

                let set_duration = start_time.elapsed();
                println!("Set {} bytes took: {:?}", size, set_duration);

                // Test retrieval performance
                let get_start = Instant::now();
                let get_op = DataOperation::Get {
                    key: format!("{}:{}", test_key, size),
                    fields: None,
                };
                let get_result = backend.execute_data(get_op).await.unwrap();
                assert!(get_result.is_success());

                let get_duration = get_start.elapsed();
                println!("Get {} bytes took: {:?}", size, get_duration);

                // Both operations should be reasonably fast
                assert!(set_duration.as_secs() < 5, "Large data set took too long");
                assert!(get_duration.as_secs() < 5, "Large data get took too long");

                // Cleanup
                let delete_op = DataOperation::Delete {
                    key: format!("{}:{}", test_key, size),
                    fields: None,
                };
                let _ = backend.execute_data(delete_op).await;
            }
            Err(_) => {
                println!("Large data size {} was rejected", size);
            }
        }
    }
}

#[tokio::test]
async fn test_connection_pool_stress() {
    skip_if_no_postgres!();

    // Create backend with small pool for stress testing
    let config = utils::create_custom_config(Some(3), Some(5000), None);
    let pool = crate::postgres::PostgresConnectionPool::new(&config.url, 3).unwrap();
    let backend = crate::postgres::PostgresBackend::new(Arc::new(pool), "stress_test".to_string());
    let backend = Arc::new(backend);

    let base_key = format!("test:stress:{}", Uuid::new_v4());

    // Create many more tasks than pool size
    let mut handles = vec![];
    for i in 0..20 {
        let backend_clone = Arc::clone(&backend);
        let key = format!("{}:{}", base_key, i);

        let handle = tokio::spawn(async move {
            // Perform multiple operations per task
            for j in 0..5 {
                let set_op = DataOperation::Set {
                    key: format!("{}:{}", key, j),
                    value: DataValue::String(format!("stress_value_{}_{}", i, j)),
                    ttl: None,
                };

                let result = backend_clone.execute_data(set_op).await;
                if result.is_err() {
                    return Err(format!("Operation failed for task {}, iteration {}", i, j));
                }
            }
            Ok(i)
        });
        handles.push(handle);
    }

    let start_time = Instant::now();

    // Wait for all tasks to complete
    let mut success_count = 0;
    for handle in handles {
        match handle.await {
            Ok(Ok(_)) => success_count += 1,
            Ok(Err(e)) => println!("Task failed: {}", e),
            Err(e) => println!("Task panicked: {:?}", e),
        }
    }

    let duration = start_time.elapsed();
    println!("Stress test completed in: {:?}", duration);
    println!("Successful tasks: {}/20", success_count);

    // Most tasks should succeed despite limited pool
    assert!(success_count >= 15, "Too many tasks failed under stress");
    assert!(duration.as_secs() < 60, "Stress test took too long");

    // Cleanup
    for i in 0..20 {
        for j in 0..5 {
            let delete_op = DataOperation::Delete {
                key: format!("{}:{}:{}", base_key, i, j),
                fields: None,
            };
            let _ = backend.execute_data(delete_op).await;
        }
    }
}

#[tokio::test]
async fn test_health_check_performance() {
    skip_if_no_postgres!();

    let backend = utils::create_test_backend().await.unwrap();

    // Perform multiple health checks
    let mut durations = Vec::new();

    for _ in 0..10 {
        let start_time = Instant::now();
        let health = backend.health_check().await.unwrap();
        let duration = start_time.elapsed();

        assert_eq!(health.status, dbx_core::HealthStatus::Healthy);
        durations.push(duration);
    }

    let avg_duration = durations.iter().sum::<std::time::Duration>() / durations.len() as u32;
    let max_duration = durations.iter().max().unwrap();

    println!(
        "Health check average: {:?}, max: {:?}",
        avg_duration, max_duration
    );

    // Health checks should be fast
    assert!(
        avg_duration.as_millis() < 100,
        "Average health check too slow"
    );
    assert!(max_duration.as_millis() < 500, "Max health check too slow");
}

#[tokio::test]
async fn test_stats_retrieval_performance() {
    skip_if_no_postgres!();

    let backend = utils::create_test_backend().await.unwrap();

    // Perform multiple stats retrievals
    let mut durations = Vec::new();

    for _ in 0..10 {
        let start_time = Instant::now();
        let stats = backend.get_stats().await.unwrap();
        let duration = start_time.elapsed();

        assert!(stats.connections.total <= stats.connections.max_pool_size);
        durations.push(duration);
    }

    let avg_duration = durations.iter().sum::<std::time::Duration>() / durations.len() as u32;
    let max_duration = durations.iter().max().unwrap();

    println!(
        "Stats retrieval average: {:?}, max: {:?}",
        avg_duration, max_duration
    );

    // Stats retrieval should be fast
    assert!(
        avg_duration.as_millis() < 200,
        "Average stats retrieval too slow"
    );
    assert!(
        max_duration.as_millis() < 1000,
        "Max stats retrieval too slow"
    );
}
