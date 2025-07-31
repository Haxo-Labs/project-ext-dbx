//! Redis factory test modules

use crate::redis::factory::RedisBackendFactory;
use dbx_config::BackendConfig;
use dbx_core::BackendFactory;

#[test]
fn test_redis_factory_provider_name() {
    let factory = RedisBackendFactory::new();
    assert_eq!(factory.provider_name(), "redis");
}

#[tokio::test]
async fn test_redis_factory_validate_config() {
    let factory = RedisBackendFactory::new();

    // Valid config
    let valid_config = BackendConfig {
        provider: "redis".to_string(),
        url: "redis://localhost:6379".to_string(),
        pool_size: Some(10),
        timeout_ms: Some(5000),
        retry_attempts: Some(3),
        retry_delay_ms: Some(1000),
        capabilities: None,
        additional_config: std::collections::HashMap::new(),
    };

    assert!(factory.validate_config(&valid_config).is_ok());

    // Invalid provider
    let invalid_provider = BackendConfig {
        provider: "postgresql".to_string(),
        url: "redis://localhost:6379".to_string(),
        pool_size: None,
        timeout_ms: None,
        retry_attempts: None,
        retry_delay_ms: None,
        capabilities: None,
        additional_config: std::collections::HashMap::new(),
    };

    assert!(factory.validate_config(&invalid_provider).is_err());

    // Invalid URL
    let invalid_url = BackendConfig {
        provider: "redis".to_string(),
        url: "http://localhost:6379".to_string(),
        pool_size: None,
        timeout_ms: None,
        retry_attempts: None,
        retry_delay_ms: None,
        capabilities: None,
        additional_config: std::collections::HashMap::new(),
    };

    assert!(factory.validate_config(&invalid_url).is_err());

    // Invalid pool size
    let invalid_pool_size = BackendConfig {
        provider: "redis".to_string(),
        url: "redis://localhost:6379".to_string(),
        pool_size: Some(0),
        timeout_ms: None,
        retry_attempts: None,
        retry_delay_ms: None,
        capabilities: None,
        additional_config: std::collections::HashMap::new(),
    };

    assert!(factory.validate_config(&invalid_pool_size).is_err());
}
