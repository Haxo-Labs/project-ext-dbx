// Re-export modules for tests
pub mod common;
pub mod redis;
pub mod redis_ws;

/// Helper function to get base URL for tests
pub async fn get_test_base_url() -> String {
    std::env::var("DBX_BASE_URL").unwrap_or_else(|_| "http://localhost:3000".to_string())
}

/// Helper function to get WebSocket URL for tests
pub async fn get_test_ws_url() -> String {
    std::env::var("DBX_WS_HOST_URL").unwrap_or_else(|_| "ws://localhost:3000/redis_ws".to_string())
}
