//! PostgreSQL factory tests

use super::utils::{self, skip_if_no_postgres};
use crate::postgres::PostgresBackendFactory;
use dbx_config::BackendConfig;
use dbx_router::registry::BackendFactory;

#[tokio::test]
async fn test_factory_creation() {
    let factory = PostgresBackendFactory::new();
    assert_eq!(factory.provider_name(), "postgresql");
}

#[tokio::test]
async fn test_factory_config_validation() {
    let factory = PostgresBackendFactory::new();

    // Valid config
    let valid_config = utils::create_test_config();
    let result = factory.validate_config(&valid_config);
    assert!(result.is_ok(), "Valid config should pass validation");

    // Invalid provider
    let invalid_config = BackendConfig {
        provider: "redis".to_string(),
        ..valid_config.clone()
    };
    let result = factory.validate_config(&invalid_config);
    assert!(result.is_err(), "Invalid provider should fail validation");

    // Invalid URL
    let invalid_url_config =
        utils::create_custom_config(Some(5), Some(5000), Some("not_a_url".to_string()));
    let result = factory.validate_config(&invalid_url_config);
    assert!(result.is_err(), "Invalid URL should fail validation");
}

#[tokio::test]
async fn test_factory_backend_creation() {
    skip_if_no_postgres!();

    let factory = PostgresBackendFactory::new();
    let config = utils::create_test_config();

    let result = factory.create_backend("test_backend", &config).await;
    assert!(result.is_ok(), "Backend creation should succeed");

    let backend = result.unwrap();
    assert_eq!(backend.name(), "test_backend");
}

#[tokio::test]
async fn test_factory_config_edge_cases() {
    let factory = PostgresBackendFactory::new();

    // Empty URL
    let empty_url_config = utils::create_custom_config(Some(5), Some(5000), Some("".to_string()));
    let result = factory.validate_config(&empty_url_config);
    assert!(result.is_err(), "Empty URL should fail validation");

    // Zero pool size
    let zero_pool_config = utils::create_custom_config(Some(0), Some(5000), None);
    let result = factory.validate_config(&zero_pool_config);
    assert!(result.is_err(), "Zero pool size should fail validation");

    // Very high pool size
    let high_pool_config = utils::create_custom_config(Some(10000), Some(5000), None);
    let result = factory.validate_config(&high_pool_config);
    assert!(
        result.is_err(),
        "Excessively high pool size should fail validation"
    );
}

#[tokio::test]
async fn test_factory_multiple_backends() {
    skip_if_no_postgres!();

    let factory = PostgresBackendFactory::new();
    let config = utils::create_test_config();

    // Create multiple backends with different names
    let backend1 = factory.create_backend("postgres_1", &config).await;
    let backend2 = factory.create_backend("postgres_2", &config).await;

    assert!(backend1.is_ok(), "First backend creation should succeed");
    assert!(backend2.is_ok(), "Second backend creation should succeed");

    let backend1 = backend1.unwrap();
    let backend2 = backend2.unwrap();

    assert_eq!(backend1.name(), "postgres_1");
    assert_eq!(backend2.name(), "postgres_2");
    assert_ne!(backend1.name(), backend2.name());
}
