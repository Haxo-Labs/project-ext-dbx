use async_trait::async_trait;
use dbx_config::BackendConfig;
use dbx_core::{
    BackendCapabilities, BackendFeature, BackendHealth, BackendStats, ConnectionStats,
    DataOperation, DataOperationType, DataResult, DataValue, DbxResult, HealthStatus,
    OperationStats, PerformanceStats, QueryCapabilities, QueryOperation, QueryResult,
    QueryResultItem, StreamCapabilities, StreamOperation, StreamResult, TransactionSupport,
    UniversalBackend,
};
use dbx_router::registry::BackendFactory;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Mock backend for testing that doesn't require external dependencies
#[derive(Debug)]
pub struct MockBackend {
    name: String,
    data: Arc<RwLock<HashMap<String, DataValue>>>,
}

impl MockBackend {
    pub fn new(name: String) -> Self {
        Self {
            name,
            data: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl UniversalBackend for MockBackend {
    fn name(&self) -> &str {
        &self.name
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            data_operations: vec![
                DataOperationType::Get,
                DataOperationType::Set,
                DataOperationType::Delete,
                DataOperationType::Exists,
            ],
            query_capabilities: QueryCapabilities {
                key_patterns: true,
                field_filters: false,
                range_queries: false,
                text_search: false,
                logical_operations: false,
                sorting: false,
                pagination: true,
                aggregations: false,
            },
            stream_capabilities: StreamCapabilities {
                pub_sub: false,
                streams: false,
                persistent_streams: false,
                stream_groups: false,
            },
            transaction_support: TransactionSupport::None,
            features: vec![BackendFeature::JsonSupport],
        }
    }

    async fn execute_data(&self, operation: DataOperation) -> DbxResult<DataResult> {
        let mut data = self.data.write().await;

        match operation {
            DataOperation::Get { key, .. } => {
                let value = data.get(&key).cloned();
                Ok(DataResult {
                    operation_id: uuid::Uuid::new_v4(),
                    success: true,
                    data: value,
                    metadata: None,
                    error: None,
                })
            }
            DataOperation::Set { key, value, .. } => {
                data.insert(key, value);
                Ok(DataResult {
                    operation_id: uuid::Uuid::new_v4(),
                    success: true,
                    data: Some(DataValue::Bool(true)),
                    metadata: None,
                    error: None,
                })
            }
            DataOperation::Delete { key, .. } => {
                let existed = data.remove(&key).is_some();
                Ok(DataResult {
                    operation_id: uuid::Uuid::new_v4(),
                    success: true,
                    data: Some(DataValue::Bool(existed)),
                    metadata: None,
                    error: None,
                })
            }
            DataOperation::Exists { key, .. } => {
                let exists = data.contains_key(&key);
                Ok(DataResult {
                    operation_id: uuid::Uuid::new_v4(),
                    success: true,
                    data: Some(DataValue::Bool(exists)),
                    metadata: None,
                    error: None,
                })
            }
            DataOperation::Batch { operations } => {
                for op in operations {
                    self.execute_data(op).await?;
                }
                Ok(DataResult {
                    operation_id: uuid::Uuid::new_v4(),
                    success: true,
                    data: Some(DataValue::Bool(true)),
                    metadata: None,
                    error: None,
                })
            }
            _ => Ok(DataResult {
                operation_id: uuid::Uuid::new_v4(),
                success: true,
                data: Some(DataValue::Bool(true)),
                metadata: None,
                error: None,
            }),
        }
    }

    async fn execute_query(&self, operation: QueryOperation) -> DbxResult<QueryResult> {
        let data = self.data.read().await;

        let results = match &operation.filter {
            dbx_core::QueryFilter::KeyPattern { pattern } => {
                let mut items = Vec::new();
                for (key, value) in data.iter() {
                    if pattern == "*" || key.contains(pattern.trim_end_matches('*')) {
                        items.push(QueryResultItem {
                            key: key.clone(),
                            data: value.clone(),
                            score: None,
                        });
                    }
                }
                items
            }
            _ => Vec::new(),
        };

        let result_count = results.len();
        Ok(QueryResult {
            query_id: operation.id,
            success: true,
            results,
            total_count: Some(result_count),
            metadata: None,
            error: None,
        })
    }

    async fn execute_stream(&self, _operation: StreamOperation) -> DbxResult<StreamResult> {
        Ok(StreamResult::Subscribed {
            channel: "mock".to_string(),
            subscriber_id: uuid::Uuid::new_v4(),
        })
    }

    async fn health_check(&self) -> DbxResult<BackendHealth> {
        Ok(BackendHealth {
            status: HealthStatus::Healthy,
            response_time_ms: Some(1),
            details: None,
            last_check: chrono::Utc::now(),
        })
    }

    async fn get_stats(&self) -> DbxResult<BackendStats> {
        Ok(BackendStats {
            connections: ConnectionStats {
                active: 1,
                idle: 0,
                total: 1,
                max_pool_size: 1,
            },
            operations: OperationStats {
                total_operations: 0,
                successful_operations: 0,
                failed_operations: 0,
                operations_per_second: 1000.0,
            },
            performance: PerformanceStats {
                avg_response_time_ms: 1.0,
                p95_response_time_ms: 2.0,
                p99_response_time_ms: 5.0,
            },
            storage: None,
        })
    }

    async fn test_connection(&self) -> DbxResult<()> {
        Ok(())
    }
}

/// Mock backend factory for testing
pub struct MockBackendFactory;

impl MockBackendFactory {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl BackendFactory for MockBackendFactory {
    async fn create_backend(
        &self,
        name: &str,
        _config: &BackendConfig,
    ) -> Result<Arc<dyn UniversalBackend>, dbx_router::RouterError> {
        Ok(Arc::new(MockBackend::new(name.to_string())))
    }

    fn provider_name(&self) -> &str {
        "mock"
    }

    fn validate_config(&self, _config: &BackendConfig) -> Result<(), dbx_router::RouterError> {
        Ok(())
    }
}
