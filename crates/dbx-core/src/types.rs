use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::{DataValue, DbxError};

/// Result of a data operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataResult {
    pub operation_id: Uuid,
    pub success: bool,
    pub data: Option<DataValue>,
    pub metadata: Option<ResultMetadata>,
    pub error: Option<DbxError>,
}

/// Result of a query operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    pub query_id: Uuid,
    pub success: bool,
    pub results: Vec<QueryResultItem>,
    pub total_count: Option<usize>,
    pub metadata: Option<ResultMetadata>,
    pub error: Option<DbxError>,
}

/// Individual query result item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResultItem {
    pub key: String,
    pub data: DataValue,
    pub score: Option<f64>,
}

/// Result of a stream operation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum StreamResult {
    /// Subscription confirmation
    Subscribed {
        channel: String,
        subscriber_id: Uuid,
    },
    /// Unsubscription confirmation
    Unsubscribed {
        channel: String,
        subscriber_id: Uuid,
    },
    /// Published message confirmation
    Published { channel: String, message_id: String },
    /// Received message
    Message {
        channel: String,
        message: DataValue,
        timestamp: chrono::DateTime<chrono::Utc>,
    },
    /// Stream created
    StreamCreated { stream: String, stream_id: String },
    /// Stream entry added
    StreamEntryAdded { stream: String, entry_id: String },
    /// Stream read result
    StreamRead {
        stream: String,
        entries: Vec<StreamEntry>,
    },
    /// Error result
    Error { operation_id: Uuid, error: DbxError },
}

/// Stream entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamEntry {
    pub id: String,
    pub fields: HashMap<String, DataValue>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Metadata for operation results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultMetadata {
    pub backend: String,
    pub execution_time_ms: u64,
    pub cached: bool,
    pub cache_ttl: Option<u64>,
    pub version: Option<String>,
    pub additional: HashMap<String, serde_json::Value>,
}

/// Configuration for a database backend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    pub name: String,
    pub provider: String,
    pub url: String,
    pub pool_size: Option<u32>,
    pub timeout_ms: Option<u64>,
    pub retry_attempts: Option<u32>,
    pub retry_delay_ms: Option<u64>,
    pub additional_config: HashMap<String, serde_json::Value>,
}

/// Routing configuration for operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingConfig {
    pub default_backend: String,
    pub operation_routing: HashMap<String, String>,
    pub key_routing: Vec<KeyRoutingRule>,
    pub load_balancing: Option<LoadBalancingConfig>,
}

/// Key-based routing rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRoutingRule {
    pub pattern: String,
    pub backend: String,
    pub priority: u32,
}

/// Load balancing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadBalancingConfig {
    pub strategy: LoadBalancingStrategy,
    pub backends: Vec<String>,
    pub health_check_interval_ms: u64,
}

/// Load balancing strategies
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancingStrategy {
    RoundRobin,
    Random,
    LeastConnections,
    WeightedRoundRobin,
    ConsistentHash,
}

/// Database configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub backends: HashMap<String, BackendConfig>,
    pub routing: RoutingConfig,
    pub consistency: ConsistencyConfig,
    pub performance: PerformanceConfig,
    pub security: SecurityConfig,
}

/// Consistency configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsistencyConfig {
    pub level: ConsistencyLevel,
    pub cross_backend: CrossBackendConsistency,
    pub transaction_timeout_ms: u64,
}

/// Consistency levels
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsistencyLevel {
    Eventual,
    Strong,
    BoundedStaleness,
    Session,
    ConsistentPrefix,
}

/// Cross-backend consistency options
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossBackendConsistency {
    BestEffort,
    TwoPhaseCommit,
    Saga,
    EventSourcing,
}

/// Performance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    pub query_timeout_ms: u64,
    pub connection_timeout_ms: u64,
    pub max_concurrent_operations: u32,
    pub cache_enabled: bool,
    pub cache_ttl_ms: u64,
    pub metrics_enabled: bool,
    pub tracing_enabled: bool,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub authentication_required: bool,
    pub authorization_enabled: bool,
    pub encryption_at_rest: bool,
    pub encryption_in_transit: bool,
    pub audit_logging: bool,
    pub rate_limiting: Option<RateLimitConfig>,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub requests_per_second: u32,
    pub burst_size: u32,
    pub window_ms: u64,
}

impl DataResult {
    /// Create a successful result
    pub fn success(operation_id: Uuid, data: DataValue) -> Self {
        Self {
            operation_id,
            success: true,
            data: Some(data),
            metadata: None,
            error: None,
        }
    }

    /// Create a successful result with metadata
    pub fn success_with_metadata(
        operation_id: Uuid,
        data: DataValue,
        metadata: ResultMetadata,
    ) -> Self {
        Self {
            operation_id,
            success: true,
            data: Some(data),
            metadata: Some(metadata),
            error: None,
        }
    }

    /// Create an error result
    pub fn error(operation_id: Uuid, error: DbxError) -> Self {
        Self {
            operation_id,
            success: false,
            data: None,
            metadata: None,
            error: Some(error),
        }
    }

    /// Create an empty success result (for operations that don't return data)
    pub fn empty_success(operation_id: Uuid) -> Self {
        Self {
            operation_id,
            success: true,
            data: None,
            metadata: None,
            error: None,
        }
    }
}

impl QueryResult {
    /// Create a successful query result
    pub fn success(query_id: Uuid, results: Vec<QueryResultItem>) -> Self {
        Self {
            query_id,
            success: true,
            results,
            total_count: None,
            metadata: None,
            error: None,
        }
    }

    /// Create a successful query result with total count
    pub fn success_with_count(
        query_id: Uuid,
        results: Vec<QueryResultItem>,
        total_count: usize,
    ) -> Self {
        Self {
            query_id,
            success: true,
            results,
            total_count: Some(total_count),
            metadata: None,
            error: None,
        }
    }

    /// Create an error result
    pub fn error(query_id: Uuid, error: DbxError) -> Self {
        Self {
            query_id,
            success: false,
            results: vec![],
            total_count: None,
            metadata: None,
            error: Some(error),
        }
    }
}

impl ResultMetadata {
    /// Create new metadata
    pub fn new(backend: String, execution_time_ms: u64) -> Self {
        Self {
            backend,
            execution_time_ms,
            cached: false,
            cache_ttl: None,
            version: None,
            additional: HashMap::new(),
        }
    }

    /// Mark as cached result
    pub fn with_cache(mut self, ttl: u64) -> Self {
        self.cached = true;
        self.cache_ttl = Some(ttl);
        self
    }

    /// Add version information
    pub fn with_version(mut self, version: String) -> Self {
        self.version = Some(version);
        self
    }

    /// Add additional metadata
    pub fn with_additional(mut self, key: String, value: serde_json::Value) -> Self {
        self.additional.insert(key, value);
        self
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            backends: HashMap::new(),
            routing: RoutingConfig {
                default_backend: "default".to_string(),
                operation_routing: HashMap::new(),
                key_routing: vec![],
                load_balancing: None,
            },
            consistency: ConsistencyConfig {
                level: ConsistencyLevel::Eventual,
                cross_backend: CrossBackendConsistency::BestEffort,
                transaction_timeout_ms: 30000,
            },
            performance: PerformanceConfig {
                query_timeout_ms: 30000,
                connection_timeout_ms: 5000,
                max_concurrent_operations: 1000,
                cache_enabled: false,
                cache_ttl_ms: 300000,
                metrics_enabled: true,
                tracing_enabled: true,
            },
            security: SecurityConfig {
                authentication_required: false,
                authorization_enabled: false,
                encryption_at_rest: false,
                encryption_in_transit: false,
                audit_logging: false,
                rate_limiting: None,
            },
        }
    }
}
