//! PostgreSQL integration tests for DBX API
//!
//! These tests verify PostgreSQL backend integration through the API layer.
//! Tests are skipped if PostgreSQL is not available.

use std::env;

/// Get test PostgreSQL URL from environment or use default
fn get_test_postgres_url() -> String {
    env::var("TEST_POSTGRES_URL")
        .unwrap_or_else(|_| "postgresql://postgres:password@localhost:5432/dbx_test".to_string())
}

/// Check if PostgreSQL is available for testing
async fn is_postgres_available() -> bool {
    use tokio_postgres::connect;
    let url = get_test_postgres_url();
    match connect(&url, tokio_postgres::NoTls).await {
        Ok((client, connection)) => {
            tokio::spawn(connection);
            client.simple_query("SELECT 1").await.is_ok()
        }
        Err(_) => false,
    }
}

/// Macro to skip tests if PostgreSQL is not available
macro_rules! skip_if_no_postgres {
    () => {
        if !is_postgres_available().await {
            eprintln!("Skipping test: PostgreSQL not available");
            return;
        }
    };
}

#[tokio::test]
async fn test_postgres_backend_availability() {
    // This test just verifies PostgreSQL backend can be created
    skip_if_no_postgres!();

    use dbx_adapter::postgres::factory::PostgresBackendFactory;
    use dbx_config::BackendConfig;
    use dbx_router::registry::BackendFactory;
    use std::collections::HashMap;

    let factory = PostgresBackendFactory::new();
    assert_eq!(factory.provider_name(), "postgresql");

    let config = BackendConfig {
        provider: "postgresql".to_string(),
        url: get_test_postgres_url(),
        pool_size: Some(5),
        timeout_ms: Some(5000),
        retry_attempts: Some(3),
        retry_delay_ms: Some(1000),
        capabilities: None,
        additional_config: HashMap::new(),
    };

    let result = factory.create_backend("test_postgres", &config).await;
    assert!(
        result.is_ok(),
        "PostgreSQL backend creation should succeed: {:?}",
        result.err()
    );

    let backend = result.unwrap();
    assert_eq!(backend.name(), "test_postgres");

    // Test basic health check
    let health = backend.health_check().await;
    assert!(
        health.is_ok(),
        "PostgreSQL backend should be healthy: {:?}",
        health.err()
    );
}

#[tokio::test]
async fn test_postgres_backend_basic_operations() {
    skip_if_no_postgres!();

    use dbx_adapter::postgres::factory::PostgresBackendFactory;
    use dbx_config::BackendConfig;
    use dbx_core::{DataOperation, DataValue, UniversalBackend};
    use dbx_router::registry::BackendFactory;
    use std::collections::HashMap;

    let factory = PostgresBackendFactory::new();
    let config = BackendConfig {
        provider: "postgresql".to_string(),
        url: get_test_postgres_url(),
        pool_size: Some(5),
        timeout_ms: Some(5000),
        retry_attempts: Some(3),
        retry_delay_ms: Some(1000),
        capabilities: None,
        additional_config: HashMap::new(),
    };

    let backend = factory
        .create_backend("test_postgres", &config)
        .await
        .unwrap();

    // Test basic set operation
    let set_op = DataOperation::Set {
        key: "test:integration:basic".to_string(),
        value: DataValue::String("Integration test value".to_string()),
        ttl: None,
    };

    let result = backend.execute_data(set_op).await.unwrap();
    assert!(result.is_success());

    // Test basic get operation
    let get_op = DataOperation::Get {
        key: "test:integration:basic".to_string(),
        fields: None,
    };

    let result = backend.execute_data(get_op).await.unwrap();
    assert!(result.is_success());
    assert_eq!(
        result.data,
        Some(DataValue::String("Integration test value".to_string()))
    );

    // Test delete operation
    let delete_op = DataOperation::Delete {
        key: "test:integration:basic".to_string(),
        fields: None,
    };

    let result = backend.execute_data(delete_op).await.unwrap();
    assert!(result.is_success());

    // Verify deletion
    let get_after_delete = DataOperation::Get {
        key: "test:integration:basic".to_string(),
        fields: None,
    };

    let result = backend.execute_data(get_after_delete).await.unwrap();
    assert!(result.is_success());
    assert_eq!(result.data, Some(DataValue::Null));
}

#[tokio::test]
async fn test_postgres_backend_json_operations() {
    skip_if_no_postgres!();

    use dbx_adapter::postgres::factory::PostgresBackendFactory;
    use dbx_config::BackendConfig;
    use dbx_core::{DataOperation, DataValue, UniversalBackend};
    use dbx_router::registry::BackendFactory;
    use std::collections::HashMap;

    let factory = PostgresBackendFactory::new();
    let config = BackendConfig {
        provider: "postgresql".to_string(),
        url: get_test_postgres_url(),
        pool_size: Some(5),
        timeout_ms: Some(5000),
        retry_attempts: Some(3),
        retry_delay_ms: Some(1000),
        capabilities: None,
        additional_config: HashMap::new(),
    };

    let backend = factory
        .create_backend("test_postgres", &config)
        .await
        .unwrap();

    // Create test JSON object
    let mut json_object = HashMap::new();
    json_object.insert(
        "name".to_string(),
        DataValue::String("Integration Test User".to_string()),
    );
    json_object.insert("id".to_string(), DataValue::Int(12345));
    json_object.insert("active".to_string(), DataValue::Bool(true));
    json_object.insert(
        "tags".to_string(),
        DataValue::Array(vec![
            DataValue::String("integration".to_string()),
            DataValue::String("test".to_string()),
        ]),
    );

    // Test JSON set operation
    let set_op = DataOperation::Set {
        key: "test:integration:json".to_string(),
        value: DataValue::Object(json_object.clone()),
        ttl: None,
    };

    let result = backend.execute_data(set_op).await.unwrap();
    assert!(result.is_success());

    // Test JSON get operation
    let get_op = DataOperation::Get {
        key: "test:integration:json".to_string(),
        fields: None,
    };

    let result = backend.execute_data(get_op).await.unwrap();
    assert!(result.is_success());

    if let Some(DataValue::Object(retrieved_obj)) = result.data {
        assert_eq!(
            retrieved_obj.get("name"),
            Some(&DataValue::String("Integration Test User".to_string()))
        );
        assert_eq!(retrieved_obj.get("id"), Some(&DataValue::Int(12345)));
        assert_eq!(retrieved_obj.get("active"), Some(&DataValue::Bool(true)));

        if let Some(DataValue::Array(tags)) = retrieved_obj.get("tags") {
            assert_eq!(tags.len(), 2);
            assert_eq!(tags[0], DataValue::String("integration".to_string()));
            assert_eq!(tags[1], DataValue::String("test".to_string()));
        } else {
            panic!("Expected tags array");
        }
    } else {
        panic!("Expected JSON object, got: {:?}", result.data);
    }

    // Cleanup
    let delete_op = DataOperation::Delete {
        key: "test:integration:json".to_string(),
        fields: None,
    };
    let _ = backend.execute_data(delete_op).await;
}

#[tokio::test]
async fn test_postgres_backend_factory_registration() {
    // Test that the PostgreSQL factory can be registered in the backend registry
    use dbx_adapter::postgres::factory::PostgresBackendFactory;
    use dbx_router::registry::BackendRegistryBuilder;

    let mut registry_builder = BackendRegistryBuilder::new();
    let postgres_factory = PostgresBackendFactory::new();

    registry_builder = registry_builder.with_factory("postgresql", postgres_factory);
    let registry = registry_builder.build();

    // Verify the factory is registered
    assert!(registry.has_factory("postgresql"));
    assert!(!registry.has_factory("nonexistent"));
}
