//! PostgreSQL factory tests

use crate::postgres::factory::PostgresBackendFactory;
use dbx_config::BackendConfig;
use dbx_router::registry::BackendFactory;

#[test]
fn test_factory_creation() {
    let factory = PostgresBackendFactory::new();
    assert_eq!(factory.provider_name(), "postgresql");
}

#[test]
fn test_default_factory() {
    let factory = PostgresBackendFactory::default();
    assert_eq!(factory.provider_name(), "postgresql");
}

#[tokio::test]
async fn test_invalid_provider() {
    let factory = PostgresBackendFactory::new();
    let config = BackendConfig {
        provider: "redis".to_string(),
        url: "postgresql://localhost:5432/test".to_string(),
        pool_size: Some(5),
        timeout_ms: None,
        retry_attempts: None,
        retry_delay_ms: None,
        capabilities: None,
        additional_config: std::collections::HashMap::new(),
    };

    let result = factory.create_backend("test", &config).await;
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Expected provider"));
}

#[test]
fn test_validate_config() {
    let factory = PostgresBackendFactory::new();

    // Valid config
    let valid_config = BackendConfig {
        provider: "postgresql".to_string(),
        url: "postgresql://localhost:5432/dbx".to_string(),
        pool_size: Some(10),
        timeout_ms: Some(5000),
        retry_attempts: Some(3),
        retry_delay_ms: Some(1000),
        capabilities: None,
        additional_config: std::collections::HashMap::new(),
    };

    assert!(factory.validate_config(&valid_config).is_ok());

    // Valid with postgres:// scheme
    let valid_postgres_config = BackendConfig {
        provider: "postgres".to_string(),
        url: "postgres://localhost:5432/dbx".to_string(),
        pool_size: None,
        timeout_ms: None,
        retry_attempts: None,
        retry_delay_ms: None,
        capabilities: None,
        additional_config: std::collections::HashMap::new(),
    };

    assert!(factory.validate_config(&valid_postgres_config).is_ok());

    // Invalid URL
    let invalid_url = BackendConfig {
        provider: "postgresql".to_string(),
        url: "http://localhost:5432/dbx".to_string(),
        pool_size: None,
        timeout_ms: None,
        retry_attempts: None,
        retry_delay_ms: None,
        capabilities: None,
        additional_config: std::collections::HashMap::new(),
    };

    assert!(factory.validate_config(&invalid_url).is_err());
}
