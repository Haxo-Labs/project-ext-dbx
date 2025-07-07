use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use validator::Validate;

use dbx_core::{
    BackendCapabilities, ConsistencyLevel, CrossBackendConsistency, LoadBalancingStrategy,
};

/// Main configuration for DBX
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct DbxConfig {
    /// Database backends configuration
    #[validate(length(min = 1, message = "At least one backend must be configured"))]
    pub backends: HashMap<String, BackendConfig>,

    /// Routing configuration
    pub routing: RoutingConfig,

    /// Consistency configuration
    pub consistency: ConsistencyConfig,

    /// Performance configuration
    pub performance: PerformanceConfig,

    /// Security configuration
    pub security: SecurityConfig,

    /// Server configuration
    pub server: ServerConfig,
}

/// Configuration for a database backend
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct BackendConfig {
    /// Backend provider name (e.g., "redis", "postgresql", "mongodb")
    #[validate(length(min = 1, message = "Provider name cannot be empty"))]
    pub provider: String,

    /// Connection URL
    #[validate(url(message = "Invalid URL format"))]
    pub url: String,

    /// Connection pool size
    #[validate(range(min = 1, max = 1000, message = "Pool size must be between 1 and 1000"))]
    pub pool_size: Option<u32>,

    /// Connection timeout in milliseconds
    #[validate(range(
        min = 100,
        max = 60000,
        message = "Timeout must be between 100ms and 60s"
    ))]
    pub timeout_ms: Option<u64>,

    /// Maximum retry attempts
    #[validate(range(max = 10, message = "Retry attempts must not exceed 10"))]
    pub retry_attempts: Option<u32>,

    /// Delay between retries in milliseconds
    #[validate(range(
        min = 100,
        max = 30000,
        message = "Retry delay must be between 100ms and 30s"
    ))]
    pub retry_delay_ms: Option<u64>,

    /// Backend capabilities (auto-detected if not specified)
    pub capabilities: Option<BackendCapabilities>,

    /// Additional provider-specific configuration
    pub additional_config: HashMap<String, serde_json::Value>,
}

/// Routing configuration for operations
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct RoutingConfig {
    /// Default backend for operations when no specific routing rule applies
    #[validate(length(min = 1, message = "Default backend cannot be empty"))]
    pub default_backend: String,

    /// Operation-specific routing (operation_type -> backend_name)
    pub operation_routing: HashMap<String, String>,

    /// Key-based routing rules
    pub key_routing: Vec<KeyRoutingRule>,

    /// Load balancing configuration
    pub load_balancing: Option<LoadBalancingConfig>,
}

/// Key-based routing rule
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct KeyRoutingRule {
    /// Pattern to match against keys (supports wildcards and regex)
    #[validate(length(min = 1, message = "Pattern cannot be empty"))]
    pub pattern: String,

    /// Backend to route matching keys to
    #[validate(length(min = 1, message = "Backend name cannot be empty"))]
    pub backend: String,

    /// Rule priority (higher numbers take precedence)
    pub priority: u32,

    /// Pattern type (glob, regex, exact)
    pub pattern_type: PatternType,
}

/// Pattern matching types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PatternType {
    Exact,
    Glob,
    Regex,
    Prefix,
    Suffix,
}

/// Load balancing configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct LoadBalancingConfig {
    /// Load balancing strategy
    pub strategy: LoadBalancingStrategy,

    /// List of backends to load balance across
    #[validate(length(min = 2, message = "Load balancing requires at least 2 backends"))]
    pub backends: Vec<String>,

    /// Health check interval in milliseconds
    #[validate(range(
        min = 1000,
        max = 300000,
        message = "Health check interval must be between 1s and 5m"
    ))]
    pub health_check_interval_ms: u64,

    /// Weights for weighted round-robin (backend_name -> weight)
    pub weights: Option<HashMap<String, f64>>,
}

/// Consistency configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsistencyConfig {
    /// Consistency level for operations
    pub level: ConsistencyLevel,

    /// Cross-backend consistency strategy
    pub cross_backend: CrossBackendConsistency,

    /// Transaction timeout in milliseconds
    pub transaction_timeout_ms: u64,

    /// Enable read-after-write consistency
    pub read_after_write: bool,

    /// Eventual consistency delay tolerance in milliseconds
    pub staleness_tolerance_ms: Option<u64>,
}

/// Performance configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct PerformanceConfig {
    /// Query timeout in milliseconds
    #[validate(range(
        min = 100,
        max = 300000,
        message = "Query timeout must be between 100ms and 5m"
    ))]
    pub query_timeout_ms: u64,

    /// Connection timeout in milliseconds
    #[validate(range(
        min = 100,
        max = 60000,
        message = "Connection timeout must be between 100ms and 1m"
    ))]
    pub connection_timeout_ms: u64,

    /// Maximum concurrent operations per backend
    #[validate(range(
        min = 1,
        max = 10000,
        message = "Concurrent operations must be between 1 and 10000"
    ))]
    pub max_concurrent_operations: u32,

    /// Enable caching
    pub cache_enabled: bool,

    /// Cache TTL in milliseconds
    #[validate(range(
        min = 1000,
        max = 86400000,
        message = "Cache TTL must be between 1s and 1d"
    ))]
    pub cache_ttl_ms: u64,

    /// Enable metrics collection
    pub metrics_enabled: bool,

    /// Enable distributed tracing
    pub tracing_enabled: bool,

    /// Batch size for bulk operations
    #[validate(range(
        min = 1,
        max = 10000,
        message = "Batch size must be between 1 and 10000"
    ))]
    pub batch_size: u32,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Require authentication for all operations
    pub authentication_required: bool,

    /// Enable role-based authorization
    pub authorization_enabled: bool,

    /// Enable encryption at rest
    pub encryption_at_rest: bool,

    /// Enable encryption in transit (TLS)
    pub encryption_in_transit: bool,

    /// Enable audit logging
    pub audit_logging: bool,

    /// Rate limiting configuration
    pub rate_limiting: Option<RateLimitConfig>,

    /// JWT configuration for authentication
    pub jwt: Option<JwtConfig>,

    /// TLS configuration
    pub tls: Option<TlsConfig>,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct RateLimitConfig {
    /// Requests per second limit
    #[validate(range(min = 1, max = 100000, message = "RPS must be between 1 and 100000"))]
    pub requests_per_second: u32,

    /// Burst size for token bucket
    #[validate(range(
        min = 1,
        max = 10000,
        message = "Burst size must be between 1 and 10000"
    ))]
    pub burst_size: u32,

    /// Rate limiting window in milliseconds
    #[validate(range(
        min = 1000,
        max = 3600000,
        message = "Window must be between 1s and 1h"
    ))]
    pub window_ms: u64,

    /// Per-user rate limiting
    pub per_user: bool,

    /// Per-IP rate limiting
    pub per_ip: bool,
}

/// JWT configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct JwtConfig {
    /// JWT secret for signing tokens
    #[validate(length(min = 32, message = "JWT secret must be at least 32 characters"))]
    pub secret: String,

    /// Token expiration time in seconds
    #[validate(range(
        min = 300,
        max = 86400,
        message = "Token expiration must be between 5m and 1d"
    ))]
    pub expiration_seconds: u64,

    /// Token issuer
    pub issuer: String,

    /// Token audience
    pub audience: Option<String>,
}

/// TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct TlsConfig {
    /// Path to certificate file
    #[validate(length(min = 1, message = "Certificate path cannot be empty"))]
    pub cert_path: String,

    /// Path to private key file
    #[validate(length(min = 1, message = "Key path cannot be empty"))]
    pub key_path: String,

    /// Path to CA certificate file (for client verification)
    pub ca_cert_path: Option<String>,

    /// Require client certificates
    pub require_client_cert: bool,
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ServerConfig {
    /// Server host address
    #[validate(length(min = 1, message = "Host cannot be empty"))]
    pub host: String,

    /// Server port
    #[validate(range(min = 1, max = 65535, message = "Port must be between 1 and 65535"))]
    pub port: u16,

    /// Number of worker threads
    #[validate(range(
        min = 1,
        max = 128,
        message = "Worker threads must be between 1 and 128"
    ))]
    pub workers: Option<u32>,

    /// Enable WebSocket support
    pub websocket_enabled: bool,

    /// WebSocket ping interval in seconds
    #[validate(range(
        min = 10,
        max = 300,
        message = "WebSocket ping interval must be between 10s and 5m"
    ))]
    pub websocket_ping_interval: Option<u64>,

    /// Request timeout in milliseconds
    #[validate(range(
        min = 1000,
        max = 300000,
        message = "Request timeout must be between 1s and 5m"
    ))]
    pub request_timeout_ms: u64,

    /// Maximum request body size in bytes
    #[validate(range(
        min = 1024,
        max = 104857600,
        message = "Max body size must be between 1KB and 100MB"
    ))]
    pub max_body_size: u64,

    /// Enable CORS
    pub cors_enabled: bool,

    /// CORS allowed origins
    pub cors_origins: Vec<String>,
}

impl Default for DbxConfig {
    fn default() -> Self {
        Self {
            backends: HashMap::new(),
            routing: RoutingConfig::default(),
            consistency: ConsistencyConfig::default(),
            performance: PerformanceConfig::default(),
            security: SecurityConfig::default(),
            server: ServerConfig::default(),
        }
    }
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            default_backend: "default".to_string(),
            operation_routing: HashMap::new(),
            key_routing: vec![],
            load_balancing: None,
        }
    }
}

impl Default for ConsistencyConfig {
    fn default() -> Self {
        Self {
            level: ConsistencyLevel::Eventual,
            cross_backend: CrossBackendConsistency::BestEffort,
            transaction_timeout_ms: 30000,
            read_after_write: false,
            staleness_tolerance_ms: Some(1000),
        }
    }
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            query_timeout_ms: 30000,
            connection_timeout_ms: 5000,
            max_concurrent_operations: 1000,
            cache_enabled: false,
            cache_ttl_ms: 300000,
            metrics_enabled: true,
            tracing_enabled: true,
            batch_size: 100,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            authentication_required: false,
            authorization_enabled: false,
            encryption_at_rest: false,
            encryption_in_transit: false,
            audit_logging: false,
            rate_limiting: None,
            jwt: None,
            tls: None,
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 3000,
            workers: None,
            websocket_enabled: true,
            websocket_ping_interval: Some(30),
            request_timeout_ms: 30000,
            max_body_size: 10485760, // 10MB
            cors_enabled: true,
            cors_origins: vec!["*".to_string()],
        }
    }
}
