//! Adapter test utilities and helpers

use std::env;

/// Load environment variables from .env file for tests
#[ctor::ctor]
fn init() {
    dotenv::dotenv().ok();
}

/// Get test Redis URL with fallback to localhost
pub fn get_test_redis_url() -> String {
    // Use TEST_REDIS_URL for test-specific configuration
    env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string())
}
