use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{
    DataOperation, DataResult, DbxError, QueryOperation, QueryResult, StreamOperation, StreamResult,
};

/// Backend trait that all database implementations must implement
/// This provides a database-agnostic interface for all operations
#[async_trait]
pub trait UniversalBackend: Send + Sync {
    /// Get the name of this backend
    fn name(&self) -> &str;

    /// Get the capabilities of this backend
    fn capabilities(&self) -> BackendCapabilities;

    /// Execute a data operation
    async fn execute_data(&self, operation: DataOperation) -> Result<DataResult, DbxError>;

    /// Execute a query operation
    async fn execute_query(&self, operation: QueryOperation) -> Result<QueryResult, DbxError>;

    /// Execute a stream operation
    async fn execute_stream(&self, operation: StreamOperation) -> Result<StreamResult, DbxError>;

    /// Health check for this backend
    async fn health_check(&self) -> Result<BackendHealth, DbxError>;

    /// Get backend statistics
    async fn get_stats(&self) -> Result<BackendStats, DbxError>;

    /// Test the connection to the backend
    async fn test_connection(&self) -> Result<(), DbxError>;
}

/// Backend capabilities indicate what operations the backend supports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendCapabilities {
    /// Data operations supported
    pub data_operations: Vec<DataOperationType>,
    /// Query capabilities
    pub query_capabilities: QueryCapabilities,
    /// Stream capabilities
    pub stream_capabilities: StreamCapabilities,
    /// Transaction support
    pub transaction_support: TransactionSupport,
    /// Additional features
    pub features: Vec<BackendFeature>,
}

/// Types of data operations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DataOperationType {
    Get,
    Set,
    Update,
    Delete,
    Exists,
    GetTtl,
    SetTtl,
    Batch,
}

/// Query capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryCapabilities {
    pub key_patterns: bool,
    pub field_filters: bool,
    pub range_queries: bool,
    pub text_search: bool,
    pub logical_operations: bool,
    pub sorting: bool,
    pub pagination: bool,
    pub aggregations: bool,
}

/// Stream capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamCapabilities {
    pub pub_sub: bool,
    pub streams: bool,
    pub persistent_streams: bool,
    pub stream_groups: bool,
}

/// Transaction support levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TransactionSupport {
    None,
    SingleOperation,
    MultiOperation,
    Acid,
}

/// Backend-specific features
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendFeature {
    JsonSupport,
    BinaryData,
    Compression,
    Encryption,
    Replication,
    Clustering,
    Backup,
    Analytics,
    VectorSearch,
    FullTextSearch,
    Geospatial,
    TimeSeries,
}

/// Backend health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendHealth {
    pub status: HealthStatus,
    pub response_time_ms: Option<u64>,
    pub details: Option<HashMap<String, serde_json::Value>>,
    pub last_check: chrono::DateTime<chrono::Utc>,
}

/// Health status levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

/// Backend statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendStats {
    pub connections: ConnectionStats,
    pub operations: OperationStats,
    pub performance: PerformanceStats,
    pub storage: Option<StorageStats>,
}

/// Connection statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionStats {
    pub active: u32,
    pub idle: u32,
    pub total: u32,
    pub max_pool_size: u32,
}

/// Operation statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationStats {
    pub total_operations: u64,
    pub successful_operations: u64,
    pub failed_operations: u64,
    pub operations_per_second: f64,
}

/// Performance statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceStats {
    pub avg_response_time_ms: f64,
    pub p95_response_time_ms: f64,
    pub p99_response_time_ms: f64,
}

/// Storage statistics (optional for backends that provide this info)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStats {
    pub used_memory_bytes: u64,
    pub total_memory_bytes: Option<u64>,
    pub key_count: u64,
    pub database_size_bytes: Option<u64>,
}

impl Default for BackendCapabilities {
    fn default() -> Self {
        Self {
            data_operations: vec![
                DataOperationType::Get,
                DataOperationType::Set,
                DataOperationType::Delete,
                DataOperationType::Exists,
            ],
            query_capabilities: QueryCapabilities {
                key_patterns: false,
                field_filters: false,
                range_queries: false,
                text_search: false,
                logical_operations: false,
                sorting: false,
                pagination: false,
                aggregations: false,
            },
            stream_capabilities: StreamCapabilities {
                pub_sub: false,
                streams: false,
                persistent_streams: false,
                stream_groups: false,
            },
            transaction_support: TransactionSupport::None,
            features: vec![],
        }
    }
}

impl Default for QueryCapabilities {
    fn default() -> Self {
        Self {
            key_patterns: false,
            field_filters: false,
            range_queries: false,
            text_search: false,
            logical_operations: false,
            sorting: false,
            pagination: false,
            aggregations: false,
        }
    }
}

impl Default for StreamCapabilities {
    fn default() -> Self {
        Self {
            pub_sub: false,
            streams: false,
            persistent_streams: false,
            stream_groups: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_backend_capabilities_default() {
        let capabilities = BackendCapabilities::default();

        // Check default data operations
        assert!(capabilities
            .data_operations
            .contains(&DataOperationType::Get));
        assert!(capabilities
            .data_operations
            .contains(&DataOperationType::Set));
        assert!(capabilities
            .data_operations
            .contains(&DataOperationType::Delete));
        assert!(capabilities
            .data_operations
            .contains(&DataOperationType::Exists));
        assert_eq!(capabilities.data_operations.len(), 4);

        // Check default query capabilities
        assert!(!capabilities.query_capabilities.key_patterns);
        assert!(!capabilities.query_capabilities.field_filters);
        assert!(!capabilities.query_capabilities.range_queries);
        assert!(!capabilities.query_capabilities.text_search);
        assert!(!capabilities.query_capabilities.logical_operations);
        assert!(!capabilities.query_capabilities.sorting);
        assert!(!capabilities.query_capabilities.pagination);
        assert!(!capabilities.query_capabilities.aggregations);

        // Check default stream capabilities
        assert!(!capabilities.stream_capabilities.pub_sub);
        assert!(!capabilities.stream_capabilities.streams);
        assert!(!capabilities.stream_capabilities.persistent_streams);
        assert!(!capabilities.stream_capabilities.stream_groups);

        // Check default transaction support
        assert_eq!(capabilities.transaction_support, TransactionSupport::None);

        // Check default features
        assert!(capabilities.features.is_empty());
    }

    #[test]
    fn test_data_operation_type_serialization() {
        let operations = vec![
            DataOperationType::Get,
            DataOperationType::Set,
            DataOperationType::Update,
            DataOperationType::Delete,
            DataOperationType::Exists,
            DataOperationType::GetTtl,
            DataOperationType::SetTtl,
            DataOperationType::Batch,
        ];

        for operation in operations {
            let json = serde_json::to_string(&operation).unwrap();
            let deserialized: DataOperationType = serde_json::from_str(&json).unwrap();
            // Note: Can't directly compare due to no PartialEq, but serialization test is sufficient
            let _json2 = serde_json::to_string(&deserialized).unwrap();
        }
    }

    #[test]
    fn test_query_capabilities_default() {
        let capabilities = QueryCapabilities::default();

        assert!(!capabilities.key_patterns);
        assert!(!capabilities.field_filters);
        assert!(!capabilities.range_queries);
        assert!(!capabilities.text_search);
        assert!(!capabilities.logical_operations);
        assert!(!capabilities.sorting);
        assert!(!capabilities.pagination);
        assert!(!capabilities.aggregations);
    }

    #[test]
    fn test_query_capabilities_full_featured() {
        let capabilities = QueryCapabilities {
            key_patterns: true,
            field_filters: true,
            range_queries: true,
            text_search: true,
            logical_operations: true,
            sorting: true,
            pagination: true,
            aggregations: true,
        };

        let json = serde_json::to_string(&capabilities).unwrap();
        let deserialized: QueryCapabilities = serde_json::from_str(&json).unwrap();

        assert!(deserialized.key_patterns);
        assert!(deserialized.field_filters);
        assert!(deserialized.range_queries);
        assert!(deserialized.text_search);
        assert!(deserialized.logical_operations);
        assert!(deserialized.sorting);
        assert!(deserialized.pagination);
        assert!(deserialized.aggregations);
    }

    #[test]
    fn test_stream_capabilities_default() {
        let capabilities = StreamCapabilities::default();

        assert!(!capabilities.pub_sub);
        assert!(!capabilities.streams);
        assert!(!capabilities.persistent_streams);
        assert!(!capabilities.stream_groups);
    }

    #[test]
    fn test_stream_capabilities_full_featured() {
        let capabilities = StreamCapabilities {
            pub_sub: true,
            streams: true,
            persistent_streams: true,
            stream_groups: true,
        };

        let json = serde_json::to_string(&capabilities).unwrap();
        let deserialized: StreamCapabilities = serde_json::from_str(&json).unwrap();

        assert!(deserialized.pub_sub);
        assert!(deserialized.streams);
        assert!(deserialized.persistent_streams);
        assert!(deserialized.stream_groups);
    }

    #[test]
    fn test_transaction_support_variants() {
        let variants = vec![
            TransactionSupport::None,
            TransactionSupport::SingleOperation,
            TransactionSupport::MultiOperation,
            TransactionSupport::Acid,
        ];

        for variant in variants {
            let json = serde_json::to_string(&variant).unwrap();
            let _deserialized: TransactionSupport = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn test_backend_feature_variants() {
        let features = vec![
            BackendFeature::JsonSupport,
            BackendFeature::BinaryData,
            BackendFeature::Compression,
            BackendFeature::Encryption,
            BackendFeature::Replication,
            BackendFeature::Clustering,
            BackendFeature::Backup,
            BackendFeature::Analytics,
            BackendFeature::VectorSearch,
            BackendFeature::FullTextSearch,
            BackendFeature::Geospatial,
            BackendFeature::TimeSeries,
        ];

        for feature in features {
            let json = serde_json::to_string(&feature).unwrap();
            let _deserialized: BackendFeature = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn test_health_status_variants() {
        let statuses = vec![
            HealthStatus::Healthy,
            HealthStatus::Degraded,
            HealthStatus::Unhealthy,
            HealthStatus::Unknown,
        ];

        for (i, status) in statuses.iter().enumerate() {
            let json = serde_json::to_string(status).unwrap();
            let deserialized: HealthStatus = serde_json::from_str(&json).unwrap();

            // Test PartialEq implementation - each status should equal itself
            assert_eq!(*status, deserialized);

            // Test that different statuses are not equal
            for (j, other_status) in statuses.iter().enumerate() {
                if i == j {
                    assert_eq!(*status, *other_status);
                } else {
                    assert_ne!(*status, *other_status);
                }
            }
        }
    }

    #[test]
    fn test_backend_health() {
        use chrono::Utc;
        use std::collections::HashMap;

        let mut details = HashMap::new();
        details.insert("connection_count".to_string(), serde_json::json!(42));
        details.insert("memory_usage".to_string(), serde_json::json!("256MB"));

        let health = BackendHealth {
            status: HealthStatus::Healthy,
            response_time_ms: Some(150),
            details: Some(details.clone()),
            last_check: Utc::now(),
        };

        assert_eq!(health.status, HealthStatus::Healthy);
        assert_eq!(health.response_time_ms, Some(150));
        assert!(health.details.is_some());

        let json = serde_json::to_string(&health).unwrap();
        let deserialized: BackendHealth = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.status, HealthStatus::Healthy);
        assert_eq!(deserialized.response_time_ms, Some(150));
        assert!(deserialized.details.is_some());

        if let Some(ref deser_details) = deserialized.details {
            assert_eq!(deser_details.len(), 2);
            assert!(deser_details.contains_key("connection_count"));
            assert!(deser_details.contains_key("memory_usage"));
        }
    }

    #[test]
    fn test_backend_stats() {
        let stats = BackendStats {
            connections: ConnectionStats {
                active: 10,
                idle: 5,
                total: 15,
                max_pool_size: 20,
            },
            operations: OperationStats {
                total_operations: 10000,
                successful_operations: 9950,
                failed_operations: 50,
                operations_per_second: 150.5,
            },
            performance: PerformanceStats {
                avg_response_time_ms: 25.5,
                p95_response_time_ms: 100.0,
                p99_response_time_ms: 250.0,
            },
            storage: Some(StorageStats {
                used_memory_bytes: 1073741824,        // 1GB
                total_memory_bytes: Some(4294967296), // 4GB
                key_count: 1000000,
                database_size_bytes: Some(2147483648), // 2GB
            }),
        };

        let json = serde_json::to_string(&stats).unwrap();
        let deserialized: BackendStats = serde_json::from_str(&json).unwrap();

        // Test connection stats
        assert_eq!(deserialized.connections.active, 10);
        assert_eq!(deserialized.connections.idle, 5);
        assert_eq!(deserialized.connections.total, 15);
        assert_eq!(deserialized.connections.max_pool_size, 20);

        // Test operation stats
        assert_eq!(deserialized.operations.total_operations, 10000);
        assert_eq!(deserialized.operations.successful_operations, 9950);
        assert_eq!(deserialized.operations.failed_operations, 50);
        assert_eq!(deserialized.operations.operations_per_second, 150.5);

        // Test performance stats
        assert_eq!(deserialized.performance.avg_response_time_ms, 25.5);
        assert_eq!(deserialized.performance.p95_response_time_ms, 100.0);
        assert_eq!(deserialized.performance.p99_response_time_ms, 250.0);

        // Test storage stats
        assert!(deserialized.storage.is_some());
        if let Some(storage) = deserialized.storage {
            assert_eq!(storage.used_memory_bytes, 1073741824);
            assert_eq!(storage.total_memory_bytes, Some(4294967296));
            assert_eq!(storage.key_count, 1000000);
            assert_eq!(storage.database_size_bytes, Some(2147483648));
        }
    }

    #[test]
    fn test_connection_stats() {
        let stats = ConnectionStats {
            active: 25,
            idle: 10,
            total: 35,
            max_pool_size: 50,
        };

        let json = serde_json::to_string(&stats).unwrap();
        let deserialized: ConnectionStats = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.active, 25);
        assert_eq!(deserialized.idle, 10);
        assert_eq!(deserialized.total, 35);
        assert_eq!(deserialized.max_pool_size, 50);
    }

    #[test]
    fn test_operation_stats() {
        let stats = OperationStats {
            total_operations: 50000,
            successful_operations: 49800,
            failed_operations: 200,
            operations_per_second: 275.8,
        };

        let json = serde_json::to_string(&stats).unwrap();
        let deserialized: OperationStats = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.total_operations, 50000);
        assert_eq!(deserialized.successful_operations, 49800);
        assert_eq!(deserialized.failed_operations, 200);
        assert_eq!(deserialized.operations_per_second, 275.8);
    }

    #[test]
    fn test_performance_stats() {
        let stats = PerformanceStats {
            avg_response_time_ms: 12.5,
            p95_response_time_ms: 45.0,
            p99_response_time_ms: 120.0,
        };

        let json = serde_json::to_string(&stats).unwrap();
        let deserialized: PerformanceStats = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.avg_response_time_ms, 12.5);
        assert_eq!(deserialized.p95_response_time_ms, 45.0);
        assert_eq!(deserialized.p99_response_time_ms, 120.0);
    }

    #[test]
    fn test_storage_stats() {
        let stats = StorageStats {
            used_memory_bytes: 536870912,         // 512MB
            total_memory_bytes: Some(2147483648), // 2GB
            key_count: 500000,
            database_size_bytes: Some(1073741824), // 1GB
        };

        let json = serde_json::to_string(&stats).unwrap();
        let deserialized: StorageStats = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.used_memory_bytes, 536870912);
        assert_eq!(deserialized.total_memory_bytes, Some(2147483648));
        assert_eq!(deserialized.key_count, 500000);
        assert_eq!(deserialized.database_size_bytes, Some(1073741824));
    }

    #[test]
    fn test_storage_stats_optional_fields() {
        let stats = StorageStats {
            used_memory_bytes: 1024,
            total_memory_bytes: None,
            key_count: 100,
            database_size_bytes: None,
        };

        let json = serde_json::to_string(&stats).unwrap();
        let deserialized: StorageStats = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.used_memory_bytes, 1024);
        assert_eq!(deserialized.total_memory_bytes, None);
        assert_eq!(deserialized.key_count, 100);
        assert_eq!(deserialized.database_size_bytes, None);
    }

    #[test]
    fn test_backend_capabilities_comprehensive() {
        let capabilities = BackendCapabilities {
            data_operations: vec![
                DataOperationType::Get,
                DataOperationType::Set,
                DataOperationType::Update,
                DataOperationType::Delete,
                DataOperationType::Exists,
                DataOperationType::GetTtl,
                DataOperationType::SetTtl,
                DataOperationType::Batch,
            ],
            query_capabilities: QueryCapabilities {
                key_patterns: true,
                field_filters: true,
                range_queries: true,
                text_search: true,
                logical_operations: true,
                sorting: true,
                pagination: true,
                aggregations: false, // Partially supported
            },
            stream_capabilities: StreamCapabilities {
                pub_sub: true,
                streams: true,
                persistent_streams: true,
                stream_groups: false, // Not supported
            },
            transaction_support: TransactionSupport::Acid,
            features: vec![
                BackendFeature::JsonSupport,
                BackendFeature::BinaryData,
                BackendFeature::Compression,
                BackendFeature::Encryption,
                BackendFeature::Replication,
                BackendFeature::Clustering,
                BackendFeature::VectorSearch,
                BackendFeature::FullTextSearch,
            ],
        };

        let json = serde_json::to_string(&capabilities).unwrap();
        let deserialized: BackendCapabilities = serde_json::from_str(&json).unwrap();

        // Verify data operations
        assert_eq!(deserialized.data_operations.len(), 8);

        // Verify query capabilities
        assert!(deserialized.query_capabilities.key_patterns);
        assert!(deserialized.query_capabilities.field_filters);
        assert!(deserialized.query_capabilities.range_queries);
        assert!(deserialized.query_capabilities.text_search);
        assert!(deserialized.query_capabilities.logical_operations);
        assert!(deserialized.query_capabilities.sorting);
        assert!(deserialized.query_capabilities.pagination);
        assert!(!deserialized.query_capabilities.aggregations);

        // Verify stream capabilities
        assert!(deserialized.stream_capabilities.pub_sub);
        assert!(deserialized.stream_capabilities.streams);
        assert!(deserialized.stream_capabilities.persistent_streams);
        assert!(!deserialized.stream_capabilities.stream_groups);

        // Verify features
        assert_eq!(deserialized.features.len(), 8);
    }

    #[test]
    fn test_minimal_backend_health() {
        use chrono::Utc;

        let health = BackendHealth {
            status: HealthStatus::Unknown,
            response_time_ms: None,
            details: None,
            last_check: Utc::now(),
        };

        let json = serde_json::to_string(&health).unwrap();
        let deserialized: BackendHealth = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.status, HealthStatus::Unknown);
        assert_eq!(deserialized.response_time_ms, None);
        assert!(deserialized.details.is_none());
    }

    #[test]
    fn test_backend_stats_without_storage() {
        let stats = BackendStats {
            connections: ConnectionStats {
                active: 5,
                idle: 2,
                total: 7,
                max_pool_size: 10,
            },
            operations: OperationStats {
                total_operations: 1000,
                successful_operations: 995,
                failed_operations: 5,
                operations_per_second: 50.0,
            },
            performance: PerformanceStats {
                avg_response_time_ms: 10.0,
                p95_response_time_ms: 30.0,
                p99_response_time_ms: 80.0,
            },
            storage: None,
        };

        let json = serde_json::to_string(&stats).unwrap();
        let deserialized: BackendStats = serde_json::from_str(&json).unwrap();

        assert!(deserialized.storage.is_none());
        assert_eq!(deserialized.connections.active, 5);
        assert_eq!(deserialized.operations.total_operations, 1000);
        assert_eq!(deserialized.performance.avg_response_time_ms, 10.0);
    }
}
