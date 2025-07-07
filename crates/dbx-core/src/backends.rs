use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{DataOperation, DataResult, DbxError, QueryOperation, QueryResult, StreamOperation, StreamResult};

/// Universal backend trait that all database implementations must implement
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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