//! Adapter test utilities and helpers

use std::env;

/// Load environment variables from .env file for tests
#[ctor::ctor]
fn init() {
    dotenv::dotenv().ok();
}

/// Get Redis URL from environment variable with fallback to default
pub fn get_test_redis_url() -> String {
    env::var("REDIS_URL").unwrap_or_else(|_| "redis://default:redispw@localhost:55000".to_string())
}

/// Get PostgreSQL URL from environment variable with fallback to default
pub fn get_test_postgres_url() -> String {
    env::var("POSTGRES_URL")
        .unwrap_or_else(|_| "postgresql://postgres:postgres@localhost:5432/dbx_test".to_string())
}
