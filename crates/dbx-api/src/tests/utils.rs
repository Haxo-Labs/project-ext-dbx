//! Test utilities for DBX API

#[cfg(test)]
mod test_helpers {
    use dbx_config::BackendConfig;
    use dbx_core::UniversalBackend;
    use dbx_router::error::RouterError;
    use dbx_router::registry::BackendFactory;
    use std::sync::Arc;

    /// Mock backend implementation for testing
    #[derive(Clone, Debug)]
    pub struct MockBackend {
        pub name: String,
    }

    /// Mock backend factory for testing
    pub struct MockBackendFactory;

    #[async_trait::async_trait]
    impl BackendFactory for MockBackendFactory {
        async fn create_backend(
            &self,
            name: &str,
            _config: &BackendConfig,
        ) -> Result<Arc<dyn UniversalBackend>, RouterError> {
            Ok(Arc::new(MockBackend {
                name: name.to_string(),
            }))
        }

        fn provider_name(&self) -> &str {
            "mock"
        }

        fn validate_config(&self, _config: &BackendConfig) -> Result<(), RouterError> {
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl UniversalBackend for MockBackend {
        fn name(&self) -> &str {
            &self.name
        }

        fn capabilities(&self) -> dbx_core::BackendCapabilities {
            dbx_core::BackendCapabilities::default()
        }

        async fn execute_data(
            &self,
            _operation: dbx_core::DataOperation,
        ) -> Result<dbx_core::DataResult, dbx_core::DbxError> {
            Ok(dbx_core::DataResult::success(
                uuid::Uuid::new_v4(),
                dbx_core::DataValue::Bool(true),
            ))
        }

        async fn execute_query(
            &self,
            _operation: dbx_core::QueryOperation,
        ) -> Result<dbx_core::QueryResult, dbx_core::DbxError> {
            Ok(dbx_core::QueryResult::success(uuid::Uuid::new_v4(), vec![]))
        }

        async fn execute_stream(
            &self,
            _operation: dbx_core::StreamOperation,
        ) -> Result<dbx_core::StreamResult, dbx_core::DbxError> {
            Ok(dbx_core::StreamResult::Published {
                channel: "test".to_string(),
                message_id: "test".to_string(),
            })
        }

        async fn health_check(&self) -> Result<dbx_core::BackendHealth, dbx_core::DbxError> {
            Ok(dbx_core::BackendHealth {
                status: dbx_core::HealthStatus::Healthy,
                response_time_ms: Some(1),
                details: None,
                last_check: chrono::Utc::now(),
            })
        }

        async fn get_stats(&self) -> Result<dbx_core::BackendStats, dbx_core::DbxError> {
            Ok(dbx_core::BackendStats {
                connections: dbx_core::ConnectionStats {
                    active: 1,
                    idle: 0,
                    total: 1,
                    max_pool_size: 1,
                },
                operations: dbx_core::OperationStats {
                    total_operations: 0,
                    successful_operations: 0,
                    failed_operations: 0,
                    operations_per_second: 0.0,
                },
                performance: dbx_core::PerformanceStats {
                    avg_response_time_ms: 0.0,
                    p95_response_time_ms: 0.0,
                    p99_response_time_ms: 0.0,
                },
                storage: None,
            })
        }

        async fn test_connection(&self) -> Result<(), dbx_core::DbxError> {
            Ok(())
        }
    }
}
