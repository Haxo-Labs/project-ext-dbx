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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
                default_backend: "".to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;
    use std::collections::HashMap;

    #[test]
    fn test_data_result_success() {
        let operation_id = Uuid::new_v4();
        let data = DataValue::String("test_value".to_string());

        let result = DataResult::success(operation_id, data.clone());

        assert_eq!(result.operation_id, operation_id);
        assert!(result.success);
        assert_eq!(result.data, Some(data));
        assert!(result.metadata.is_none());
        assert!(result.error.is_none());
    }

    #[test]
    fn test_data_result_success_with_metadata() {
        let operation_id = Uuid::new_v4();
        let data = DataValue::String("test_value".to_string());
        let metadata = ResultMetadata::new("redis".to_string(), 100);

        let result =
            DataResult::success_with_metadata(operation_id, data.clone(), metadata.clone());

        assert_eq!(result.operation_id, operation_id);
        assert!(result.success);
        assert_eq!(result.data, Some(data));
        assert_eq!(result.metadata, Some(metadata));
        assert!(result.error.is_none());
    }

    #[test]
    fn test_data_result_error() {
        let operation_id = Uuid::new_v4();
        let error = DbxError::internal("test error");

        let result = DataResult::error(operation_id, error.clone());

        assert_eq!(result.operation_id, operation_id);
        assert!(!result.success);
        assert!(result.data.is_none());
        assert!(result.metadata.is_none());
        assert_eq!(result.error, Some(error));
    }

    #[test]
    fn test_data_result_empty_success() {
        let operation_id = Uuid::new_v4();

        let result = DataResult::empty_success(operation_id);

        assert_eq!(result.operation_id, operation_id);
        assert!(result.success);
        assert!(result.data.is_none());
        assert!(result.metadata.is_none());
        assert!(result.error.is_none());
    }

    #[test]
    fn test_query_result_success() {
        let query_id = Uuid::new_v4();
        let results = vec![
            QueryResultItem {
                key: "key1".to_string(),
                data: DataValue::String("value1".to_string()),
                score: Some(1.0),
            },
            QueryResultItem {
                key: "key2".to_string(),
                data: DataValue::String("value2".to_string()),
                score: Some(0.8),
            },
        ];

        let query_result = QueryResult::success(query_id, results.clone());

        assert_eq!(query_result.query_id, query_id);
        assert!(query_result.success);
        assert_eq!(query_result.results, results);
        assert!(query_result.total_count.is_none());
        assert!(query_result.metadata.is_none());
        assert!(query_result.error.is_none());
    }

    #[test]
    fn test_query_result_success_with_count() {
        let query_id = Uuid::new_v4();
        let results = vec![QueryResultItem {
            key: "key1".to_string(),
            data: DataValue::String("value1".to_string()),
            score: None,
        }];
        let total_count = 100;

        let query_result = QueryResult::success_with_count(query_id, results.clone(), total_count);

        assert_eq!(query_result.query_id, query_id);
        assert!(query_result.success);
        assert_eq!(query_result.results, results);
        assert_eq!(query_result.total_count, Some(total_count));
        assert!(query_result.metadata.is_none());
        assert!(query_result.error.is_none());
    }

    #[test]
    fn test_query_result_error() {
        let query_id = Uuid::new_v4();
        let error = DbxError::internal("query failed");

        let query_result = QueryResult::error(query_id, error.clone());

        assert_eq!(query_result.query_id, query_id);
        assert!(!query_result.success);
        assert!(query_result.results.is_empty());
        assert!(query_result.total_count.is_none());
        assert!(query_result.metadata.is_none());
        assert_eq!(query_result.error, Some(error));
    }

    #[test]
    fn test_result_metadata_builder() {
        let metadata = ResultMetadata::new("postgres".to_string(), 150)
            .with_cache(3600)
            .with_version("1.0.0".to_string())
            .with_additional(
                "custom_field".to_string(),
                serde_json::json!("custom_value"),
            );

        assert_eq!(metadata.backend, "postgres");
        assert_eq!(metadata.execution_time_ms, 150);
        assert!(metadata.cached);
        assert_eq!(metadata.cache_ttl, Some(3600));
        assert_eq!(metadata.version, Some("1.0.0".to_string()));
        assert_eq!(
            metadata.additional.get("custom_field"),
            Some(&serde_json::json!("custom_value"))
        );
    }

    #[test]
    fn test_stream_result_variants() {
        let subscriber_id = Uuid::new_v4();
        let channel = "test_channel".to_string();

        // Test Subscribed variant
        let subscribed = StreamResult::Subscribed {
            channel: channel.clone(),
            subscriber_id,
        };

        match subscribed {
            StreamResult::Subscribed {
                channel: c,
                subscriber_id: id,
            } => {
                assert_eq!(c, channel);
                assert_eq!(id, subscriber_id);
            }
            _ => panic!("Expected Subscribed variant"),
        }

        // Test Message variant
        let message = StreamResult::Message {
            channel: channel.clone(),
            message: DataValue::String("hello".to_string()),
            timestamp: chrono::Utc::now(),
        };

        match message {
            StreamResult::Message {
                channel: c,
                message: m,
                timestamp: _,
            } => {
                assert_eq!(c, channel);
                assert_eq!(m, DataValue::String("hello".to_string()));
            }
            _ => panic!("Expected Message variant"),
        }
    }

    #[test]
    fn test_stream_entry() {
        let mut fields = HashMap::new();
        fields.insert("temperature".to_string(), DataValue::Float(23.5));
        fields.insert("humidity".to_string(), DataValue::Int(65));

        let entry = StreamEntry {
            id: "1234567890-0".to_string(),
            fields: fields.clone(),
            timestamp: chrono::Utc::now(),
        };

        assert_eq!(entry.id, "1234567890-0");
        assert_eq!(entry.fields, fields);
    }

    #[test]
    fn test_backend_config_serialization() {
        let mut additional_config = HashMap::new();
        additional_config.insert("max_connections".to_string(), serde_json::json!(100));

        let config = BackendConfig {
            name: "test_backend".to_string(),
            provider: "redis".to_string(),
            url: "redis://localhost:6379".to_string(),
            pool_size: Some(10),
            timeout_ms: Some(5000),
            retry_attempts: Some(3),
            retry_delay_ms: Some(1000),
            additional_config,
        };

        // Test serialization and deserialization
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: BackendConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config.name, deserialized.name);
        assert_eq!(config.provider, deserialized.provider);
        assert_eq!(config.url, deserialized.url);
        assert_eq!(config.pool_size, deserialized.pool_size);
        assert_eq!(config.timeout_ms, deserialized.timeout_ms);
        assert_eq!(config.retry_attempts, deserialized.retry_attempts);
        assert_eq!(config.retry_delay_ms, deserialized.retry_delay_ms);
    }

    #[test]
    fn test_load_balancing_strategies() {
        let strategies = vec![
            LoadBalancingStrategy::RoundRobin,
            LoadBalancingStrategy::Random,
            LoadBalancingStrategy::LeastConnections,
            LoadBalancingStrategy::WeightedRoundRobin,
            LoadBalancingStrategy::ConsistentHash,
        ];

        for strategy in strategies {
            // Test that each strategy can be serialized and deserialized
            let json = serde_json::to_string(&strategy).unwrap();
            let _deserialized: LoadBalancingStrategy = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn test_consistency_levels() {
        let levels = vec![
            ConsistencyLevel::Eventual,
            ConsistencyLevel::Strong,
            ConsistencyLevel::BoundedStaleness,
            ConsistencyLevel::Session,
            ConsistencyLevel::ConsistentPrefix,
        ];

        for level in levels {
            // Test that each level can be serialized and deserialized
            let json = serde_json::to_string(&level).unwrap();
            let _deserialized: ConsistencyLevel = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn test_cross_backend_consistency() {
        let strategies = vec![
            CrossBackendConsistency::BestEffort,
            CrossBackendConsistency::TwoPhaseCommit,
            CrossBackendConsistency::Saga,
            CrossBackendConsistency::EventSourcing,
        ];

        for strategy in strategies {
            // Test that each strategy can be serialized and deserialized
            let json = serde_json::to_string(&strategy).unwrap();
            let _deserialized: CrossBackendConsistency = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn test_database_config_default() {
        let config = DatabaseConfig::default();

        assert!(config.backends.is_empty());
        assert_eq!(config.routing.default_backend, "");
        assert!(config.routing.operation_routing.is_empty());
        assert!(config.routing.key_routing.is_empty());
        assert!(config.routing.load_balancing.is_none());
    }

    #[test]
    fn test_routing_config() {
        let mut operation_routing = HashMap::new();
        operation_routing.insert("get".to_string(), "redis".to_string());
        operation_routing.insert("set".to_string(), "postgres".to_string());

        let key_routing = vec![
            KeyRoutingRule {
                pattern: "user:*".to_string(),
                backend: "redis".to_string(),
                priority: 1,
            },
            KeyRoutingRule {
                pattern: "analytics:*".to_string(),
                backend: "postgres".to_string(),
                priority: 2,
            },
        ];

        let load_balancing = LoadBalancingConfig {
            strategy: LoadBalancingStrategy::RoundRobin,
            backends: vec!["backend1".to_string(), "backend2".to_string()],
            health_check_interval_ms: 30000,
        };

        let routing_config = RoutingConfig {
            default_backend: "redis".to_string(),
            operation_routing,
            key_routing,
            load_balancing: Some(load_balancing),
        };

        assert_eq!(routing_config.default_backend, "redis");
        assert_eq!(routing_config.operation_routing.len(), 2);
        assert_eq!(routing_config.key_routing.len(), 2);
        assert!(routing_config.load_balancing.is_some());
    }

    #[test]
    fn test_rate_limit_config() {
        let rate_limit = RateLimitConfig {
            requests_per_second: 100,
            burst_size: 200,
            window_ms: 1000,
        };

        assert_eq!(rate_limit.requests_per_second, 100);
        assert_eq!(rate_limit.burst_size, 200);
        assert_eq!(rate_limit.window_ms, 1000);
    }

    #[test]
    fn test_performance_config() {
        let perf_config = PerformanceConfig {
            query_timeout_ms: 30000,
            connection_timeout_ms: 5000,
            max_concurrent_operations: 1000,
            cache_enabled: true,
            cache_ttl_ms: 300000,
            metrics_enabled: true,
            tracing_enabled: false,
        };

        assert_eq!(perf_config.query_timeout_ms, 30000);
        assert_eq!(perf_config.connection_timeout_ms, 5000);
        assert_eq!(perf_config.max_concurrent_operations, 1000);
        assert!(perf_config.cache_enabled);
        assert_eq!(perf_config.cache_ttl_ms, 300000);
        assert!(perf_config.metrics_enabled);
        assert!(!perf_config.tracing_enabled);
    }

    #[test]
    fn test_security_config() {
        let rate_limit = RateLimitConfig {
            requests_per_second: 50,
            burst_size: 100,
            window_ms: 1000,
        };

        let security_config = SecurityConfig {
            authentication_required: true,
            authorization_enabled: true,
            encryption_at_rest: true,
            encryption_in_transit: true,
            audit_logging: true,
            rate_limiting: Some(rate_limit),
        };

        assert!(security_config.authentication_required);
        assert!(security_config.authorization_enabled);
        assert!(security_config.encryption_at_rest);
        assert!(security_config.encryption_in_transit);
        assert!(security_config.audit_logging);
        assert!(security_config.rate_limiting.is_some());
    }
}
