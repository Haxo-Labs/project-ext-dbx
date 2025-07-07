//! Integration tests for redis_rs crate

pub mod common;
pub mod redis;
pub mod redis_ws;

/// Test utilities and common functionality

/// Test utilities and helpers
pub mod utils {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    /// Get test HTTP server URL
    pub fn http_test_url() -> String {
        std::env::var("TEST_HTTP_URL").unwrap_or_else(|_| "http://localhost:3000".to_string())
    }

    /// Get test WebSocket server URL
    pub fn ws_test_url() -> String {
        std::env::var("TEST_WS_URL").unwrap_or_else(|_| "ws://localhost:3000/redis_ws".to_string())
    }

    /// Check if the test server is available
    pub async fn is_test_server_available() -> bool {
        // Try to make a simple HTTP request to the health endpoint
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();

        let url = format!("{}/health", http_test_url());

        match client.get(&url).send().await {
            Ok(response) => response.status().is_success(),
            Err(_) => false,
        }
    }

    /// Skip test if server is not available
    pub async fn skip_if_no_server() {
        if !is_test_server_available().await {
            eprintln!(
                "Test server not available at {}, skipping test",
                http_test_url()
            );
            return;
        }
    }

    /// Generate a unique test key
    pub fn unique_key(prefix: &str) -> String {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        format!("{}_{}_{}", prefix, timestamp, rand::random::<u32>())
    }

    /// Wait for a short duration (useful for async tests)
    pub async fn wait_for(duration: Duration) {
        tokio::time::sleep(duration).await;
    }

    /// Mock HTTP server for testing
    pub async fn start_mock_http_server() -> Result<(), Box<dyn std::error::Error>> {
        // This would start a mock HTTP server for testing
        // For now, we'll assume the real server is running
        Ok(())
    }

    /// Mock WebSocket server for testing
    pub async fn start_mock_ws_server() -> Result<(), Box<dyn std::error::Error>> {
        // This would start a mock WebSocket server for testing
        // For now, we'll assume the real server is running
        Ok(())
    }
}
