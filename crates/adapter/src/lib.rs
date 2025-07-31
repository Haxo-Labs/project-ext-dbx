//! DBX Adapter library
//!
//! Database adapters and utilities for database interactions.

pub mod error;
pub mod postgres;
pub mod redis;
pub mod traits;

use error::AdapterError;

/// Get Redis URL from environment variable with default
pub fn get_redis_url() -> String {
    std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string())
}

/// Create a Redis connection pool with default settings
pub async fn create_redis_pool() -> Result<std::sync::Arc<redis::RedisConnectionPool>, AdapterError>
{
    let url = get_redis_url();
    let pool = redis::RedisConnectionPool::new(&url, 10)?;
    Ok(std::sync::Arc::new(pool))
}

/// Get PostgreSQL URL from environment variable with default
pub fn get_postgres_url() -> String {
    std::env::var("POSTGRES_URL")
        .unwrap_or_else(|_| "postgresql://postgres:postgres@127.0.0.1:5432/dbx".to_string())
}

/// Create a PostgreSQL connection pool with default settings
pub async fn create_postgres_pool(
) -> Result<std::sync::Arc<postgres::PostgresConnectionPool>, AdapterError> {
    let url = get_postgres_url();
    let pool = postgres::PostgresConnectionPool::new(&url, 10)?;
    Ok(std::sync::Arc::new(pool))
}

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Library name
pub const NAME: &str = env!("CARGO_PKG_NAME");
