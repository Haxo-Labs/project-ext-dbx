use napi_derive::napi;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// DBX Client Configuration
#[napi(object)]
#[derive(Clone)]
pub struct DbxConfig {
    /// DBX API base URL (e.g., "http://localhost:3000")
    pub base_url: String,
    /// Authentication username (optional for API key auth)
    pub username: Option<String>,
    /// Authentication password (optional for API key auth)
    pub password: Option<String>,
    /// API key for authentication (alternative to username/password)
    pub api_key: Option<String>,
    /// Request timeout in milliseconds (default: 30000)
    pub timeout_ms: Option<u32>,
    /// Maximum retry attempts (default: 3)
    pub max_retries: Option<u32>,
    /// Retry delay in milliseconds (default: 1000)
    pub retry_delay_ms: Option<u32>,
    /// Connection pool size (default: 10)
    pub pool_size: Option<u32>,
    /// Enable automatic token refresh (default: true)
    pub auto_refresh_token: Option<bool>,
    /// Enable request logging (default: false)
    pub enable_logging: Option<bool>,
}

/// API Response Structure
#[napi(object)]
pub struct DbxResponse {
    pub success: bool,
    pub data: Option<String>,
    pub error: Option<String>,
    pub operation_id: Option<String>,
    pub execution_time_ms: Option<u32>,
    pub backend: Option<String>,
    pub metadata: Option<String>,
}

/// Query Response Structure
#[napi(object)]
pub struct DbxQueryResponse {
    pub success: bool,
    pub query_id: String,
    pub results: Vec<DbxQueryResult>,
    pub total_count: Option<u32>,
    pub execution_time_ms: Option<u32>,
    pub backend: Option<String>,
    pub error: Option<String>,
}

/// Query Result Item
#[napi(object)]
pub struct DbxQueryResult {
    pub key: String,
    pub data: String,
    pub score: Option<f64>,
}

/// Batch Operation Request
#[napi(object)]
#[derive(Clone)]
pub struct DbxBatchOperation {
    #[napi(js_name = "operationType")]
    pub operation_type: String,
    pub key: String,
    pub value: Option<String>,
    pub fields: Option<String>,
    pub ttl: Option<u32>,
}

/// API Key Information
#[napi(object)]
#[derive(Serialize, Deserialize)]
pub struct DbxApiKey {
    pub id: String,
    pub name: String,
    pub key_prefix: String,
    pub permissions: Vec<String>,
    pub expires_at: Option<String>,
    pub created_at: String,
    pub last_used: Option<String>,
    pub is_active: bool,
}

/// Role Information
#[napi(object)]
#[derive(Serialize, Deserialize)]
pub struct DbxRole {
    pub name: String,
    pub permissions: Vec<String>,
    pub description: Option<String>,
    pub inherits_from: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
    pub is_system_role: bool,
}

/// User Role Assignment
#[napi(object)]
#[derive(Serialize, Deserialize)]
pub struct DbxUserRoleAssignment {
    pub user_id: String,
    pub username: String,
    pub role_name: String,
    pub assigned_by: String,
    pub assigned_at: String,
    pub expires_at: Option<String>,
    pub is_active: bool,
}

/// Rate Limit Policy
#[napi(object)]
#[derive(Serialize, Deserialize)]
pub struct DbxRateLimitPolicy {
    pub identifier: String,
    pub policy_type: String,
    pub requests: u32,
    pub window_seconds: u32,
    pub burst_allowance: Option<u32>,
    pub created_at: String,
    pub updated_at: String,
}

/// Rate Limit Status
#[napi(object)]
#[derive(Serialize, Deserialize)]
pub struct DbxRateLimitStatus {
    pub identifier: String,
    pub requests_made: u32,
    pub requests_remaining: u32,
    pub window_reset_time: String,
    pub burst_available: Option<u32>,
}

/// System Health Information
#[napi(object)]
#[derive(Serialize, Deserialize)]
pub struct DbxSystemHealth {
    pub status: String,
    pub version: String,
    pub uptime_seconds: String,
    pub backends: String,
    pub memory_usage: Option<String>,
    pub active_connections: Option<u32>,
}

/// WebSocket Configuration
#[napi(object)]
pub struct DbxWebSocketConfig {
    pub url: String,
    pub reconnect_attempts: Option<u32>,
    pub reconnect_delay_ms: Option<u32>,
    pub ping_interval_ms: Option<u32>,
    pub max_message_size: Option<u32>,
}

/// Stream Configuration
#[napi(object)]
pub struct DbxStreamConfig {
    pub stream_name: String,
    pub max_len: Option<u32>,
    pub retention_ms: Option<String>,
    pub consumer_group: Option<String>,
    pub consumer_name: Option<String>,
}

// Internal API structures
#[derive(Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct LoginResponse {
    pub success: bool,
    pub data: Option<AuthData>,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct AuthData {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

#[derive(Serialize, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Serialize, Deserialize)]
pub struct SetDataRequest {
    pub value: serde_json::Value,
    pub ttl: Option<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct UpdateDataRequest {
    pub fields: HashMap<String, serde_json::Value>,
    pub ttl: Option<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct BatchOperationRequest {
    pub operations: Vec<BatchOperation>,
}

#[derive(Serialize, Deserialize)]
pub struct BatchOperation {
    pub operation_type: String,
    pub key: String,
    pub value: Option<serde_json::Value>,
    pub fields: Option<HashMap<String, serde_json::Value>>,
    pub ttl: Option<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct PatternSearchRequest {
    pub pattern: String,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Serialize, Deserialize)]
pub struct TextSearchRequest {
    pub query: String,
    pub fields: Option<Vec<String>>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Serialize, Deserialize)]
pub struct ApiKeyCreateRequest {
    pub name: String,
    pub permissions: Vec<String>,
    pub expires_at: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct RoleCreateRequest {
    pub name: String,
    pub permissions: Vec<String>,
    pub description: Option<String>,
    pub inherits_from: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
pub struct UserRoleAssignRequest {
    pub user_id: String,
    pub role_name: String,
    pub expires_at: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct RateLimitPolicyRequest {
    pub identifier: String,
    pub policy_type: String,
    pub requests: u32,
    pub window_seconds: u32,
    pub burst_allowance: Option<u32>,
}

#[derive(Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DataResponseData {
    pub operation_id: String,
    pub success: bool,
    pub data: Option<serde_json::Value>,
    pub execution_time_ms: Option<u64>,
    pub backend: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct QueryResponseData {
    pub query_id: String,
    pub success: bool,
    pub results: Vec<QueryResultItem>,
    pub total_count: Option<usize>,
    pub execution_time_ms: Option<u64>,
    pub backend: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct QueryResultItem {
    pub key: String,
    pub data: serde_json::Value,
    pub score: Option<f64>,
}
