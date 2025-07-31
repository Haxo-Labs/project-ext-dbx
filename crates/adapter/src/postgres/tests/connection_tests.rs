//! PostgreSQL connection pool tests

use super::utils::{self, skip_if_no_postgres};
use crate::postgres::PostgresConnectionPool;

#[tokio::test]
async fn test_connection_pool_creation() {
    skip_if_no_postgres!();

    let url = utils::get_test_postgres_url();
    let pool = PostgresConnectionPool::new(&url, 5);

    assert!(pool.is_ok(), "Connection pool creation should succeed");

    let pool = pool.unwrap();
    assert_eq!(pool.url(), &url);
}

#[tokio::test]
async fn test_connection_pool_get_connection() {
    skip_if_no_postgres!();

    let url = utils::get_test_postgres_url();
    let pool = PostgresConnectionPool::new(&url, 5).unwrap();

    let conn = pool.get().await;
    assert!(conn.is_ok(), "Getting connection should succeed");
}

#[tokio::test]
async fn test_connection_pool_stats() {
    skip_if_no_postgres!();

    let url = utils::get_test_postgres_url();
    let pool = PostgresConnectionPool::new(&url, 5).unwrap();

    let stats = pool.get_stats().await;
    assert!(stats.total_connections <= 5);
    assert!(stats.max_connections == 5);
}

#[tokio::test]
async fn test_connection_pool_invalid_url() {
    let pool = PostgresConnectionPool::new("invalid_url", 5);
    assert!(
        pool.is_err(),
        "Invalid URL should cause pool creation to fail"
    );
}

#[tokio::test]
async fn test_connection_pool_concurrent_access() {
    skip_if_no_postgres!();

    let url = utils::get_test_postgres_url();
    let pool = PostgresConnectionPool::new(&url, 3).unwrap(); // Small pool
    let pool = std::sync::Arc::new(pool);

    // Create more concurrent requests than pool size
    let mut handles = vec![];
    for i in 0..10 {
        let pool_clone = std::sync::Arc::clone(&pool);
        let handle = tokio::spawn(async move {
            let _conn = pool_clone.get().await;
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            i // Return task ID for verification
        });
        handles.push(handle);
    }

    // All tasks should complete successfully
    for handle in handles {
        let result = handle.await;
        assert!(result.is_ok(), "Concurrent pool access should succeed");
    }
}
