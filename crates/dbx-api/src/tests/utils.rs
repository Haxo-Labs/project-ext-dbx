//! Shared test utilities for DBX API tests

use std::env;
use std::sync::Once;

use crate::test_helpers::{create_mock_backend, create_mock_backend_with_data, MockBackendFactory};
use dbx_config::BackendConfig;
use dbx_core::UniversalBackend;
use std::sync::Arc;

/// Ensures test setup is only done once across all tests
static INIT: Once = Once::new();

/// Initialize test environment
pub fn init_test_env() {
    INIT.call_once(|| {
        // Set test environment variables
        env::set_var("JWT_SECRET", "test-jwt-secret-for-testing-only");
        env::set_var("RUST_LOG", "debug");
        println!("Test environment initialized");
    });
}

/// Utility for testing with environment variables
pub fn with_env_var<F>(key: &str, value: Option<&str>, test: F)
where
    F: FnOnce(),
{
    let original = env::var(key).ok();

    match value {
        Some(val) => env::set_var(key, val),
        None => env::remove_var(key),
    }

    test();

    match original {
        Some(val) => env::set_var(key, val),
        None => env::remove_var(key),
    }
}

/// Create a mock backend for testing
pub fn create_test_backend() -> Arc<dyn UniversalBackend> {
    create_mock_backend()
}

/// Create a mock backend with pre-populated test data
pub async fn create_test_backend_with_data() -> Arc<dyn UniversalBackend> {
    create_mock_backend_with_data().await
}

/// Create a test backend configuration
pub fn create_test_backend_config() -> BackendConfig {
    BackendConfig {
        provider: "mock".to_string(),
        url: "mock://test".to_string(),
        pool_size: Some(1),
        timeout_ms: Some(1000),
        retry_attempts: Some(1),
        retry_delay_ms: Some(100),
        capabilities: None,
        additional_config: std::collections::HashMap::new(),
    }
}

/// Create a mock backend factory for testing
pub fn create_test_backend_factory() -> MockBackendFactory {
    MockBackendFactory::new()
}
