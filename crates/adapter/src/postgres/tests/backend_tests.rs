//! PostgreSQL backend implementation tests

use super::utils::{self, skip_if_no_postgres};
use crate::postgres::PostgresBackendFactory;
use dbx_core::{BackendFeature, DataOperationType, HealthStatus};
use dbx_router::registry::BackendFactory;

#[tokio::test]
async fn test_backend_creation() {
    skip_if_no_postgres!();

    let config = utils::create_test_config();
    let factory = PostgresBackendFactory::new();
    let result = factory.create_backend("test_postgres", &config).await;

    assert!(result.is_ok(), "Backend creation should succeed");

    let backend = result.unwrap();
    assert_eq!(backend.name(), "test_postgres");
}

#[tokio::test]
async fn test_backend_capabilities() {
    skip_if_no_postgres!();

    let backend = utils::create_test_backend().await.unwrap();
    let capabilities = backend.capabilities();

    // Verify data operations support
    let expected_ops = [
        DataOperationType::Get,
        DataOperationType::Set,
        DataOperationType::Update,
        DataOperationType::Delete,
        DataOperationType::Exists,
        DataOperationType::GetTtl,
        DataOperationType::SetTtl,
        DataOperationType::Increment,
        DataOperationType::Decrement,
        DataOperationType::Append,
        DataOperationType::Length,
        DataOperationType::CompareAndSwap,
        DataOperationType::Batch,
    ];

    for op in &expected_ops {
        assert!(
            capabilities.data_operations.contains(op),
            "PostgreSQL should support {:?}",
            op
        );
    }

    // Verify advanced features
    assert!(capabilities.features.contains(&BackendFeature::JsonSupport));
    assert!(capabilities
        .features
        .contains(&BackendFeature::FullTextSearch));
    assert!(capabilities.features.contains(&BackendFeature::Analytics));
}

#[tokio::test]
async fn test_backend_health_check() {
    skip_if_no_postgres!();

    let backend = utils::create_test_backend().await.unwrap();
    let health = backend.health_check().await;

    assert!(health.is_ok(), "Health check should succeed");

    let health = health.unwrap();
    assert_eq!(health.status, HealthStatus::Healthy);
    assert!(health.response_time_ms.is_some());
}

#[tokio::test]
async fn test_backend_stats() {
    skip_if_no_postgres!();

    let backend = utils::create_test_backend().await.unwrap();
    let stats = backend.get_stats().await;

    assert!(stats.is_ok(), "Getting stats should succeed");

    let stats = stats.unwrap();
    assert!(stats.connections.active <= stats.connections.total);
    assert!(stats.connections.total <= stats.connections.max_pool_size);
}

#[tokio::test]
async fn test_backend_connection_test() {
    skip_if_no_postgres!();

    let backend = utils::create_test_backend().await.unwrap();
    let result = backend.test_connection().await;

    assert!(result.is_ok(), "Connection test should succeed");
}

#[tokio::test]
async fn test_backend_query_capabilities() {
    skip_if_no_postgres!();

    let backend = utils::create_test_backend().await.unwrap();
    let capabilities = backend.capabilities();

    // PostgreSQL should support advanced query features
    assert!(capabilities.query_capabilities.field_filters);
    assert!(capabilities.query_capabilities.range_queries);
    assert!(capabilities.query_capabilities.text_search);
    assert!(capabilities.query_capabilities.logical_operations);
    assert!(capabilities.query_capabilities.sorting);
    assert!(capabilities.query_capabilities.pagination);
    assert!(capabilities.query_capabilities.aggregations);
}

#[tokio::test]
async fn test_backend_stream_capabilities() {
    skip_if_no_postgres!();

    let backend = utils::create_test_backend().await.unwrap();
    let capabilities = backend.capabilities();

    // PostgreSQL does not support streaming features
    assert!(!capabilities.stream_capabilities.pub_sub);
    assert!(!capabilities.stream_capabilities.streams);
    assert!(!capabilities.stream_capabilities.persistent_streams);
}
