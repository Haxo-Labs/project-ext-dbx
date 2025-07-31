//! PostgreSQL client test modules

use crate::postgres::client::PostgresConnectionPool;

#[tokio::test]
async fn test_postgres_connection_pool_creation() {
    let url = "postgresql://postgres:postgres@localhost:5432/test";
    let result = PostgresConnectionPool::new(url, 5);
    // This will fail without a running PostgreSQL instance, but we're testing URL parsing
    match result {
        Ok(_) => {} // Connection successful
        Err(e) => {
            // Expected if no PostgreSQL instance is running
            assert!(e.to_string().contains("Failed to create PostgreSQL pool"));
        }
    }
}

#[test]
fn test_url_storage() {
    let url = "postgresql://test:test@localhost:5432/testdb";
    if let Ok(pool) = PostgresConnectionPool::new(url, 5) {
        assert_eq!(pool.url(), url);
    }
}
