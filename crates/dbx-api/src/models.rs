use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// API response wrapper
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn error(error: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error),
        }
    }
}

/// User roles for role-based access control
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum UserRole {
    Admin,
    User,
    ReadOnly,
}

impl std::fmt::Display for UserRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserRole::Admin => write!(f, "admin"),
            UserRole::User => write!(f, "user"),
            UserRole::ReadOnly => write!(f, "readonly"),
        }
    }
}

/// User model for authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub role: UserRole,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_active: bool,
}

/// JWT Claims structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub username: String,
    pub role: UserRole,
    pub permissions: Vec<String>, // Permission names for RBAC
    pub exp: i64,
    pub iat: i64,
    pub iss: String,
    pub token_type: TokenType,
}

/// Token type enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TokenType {
    Access,
    Refresh,
}

/// Login request model
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// User request model
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub role: UserRole,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub user: UserInfo,
}

/// User information for responses (excludes sensitive data)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: String,
    pub username: String,
    pub role: UserRole,
}

/// Refresh token request
#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenValidationResponse {
    pub valid: bool,
    pub user: Option<UserInfo>,
    pub expires_at: Option<DateTime<Utc>>,
}

// API Key Authentication Models

/// API Key permission levels
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApiKeyPermission {
    ReadOnly,
    ReadWrite,
    Admin,
}

impl std::fmt::Display for ApiKeyPermission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiKeyPermission::ReadOnly => write!(f, "readonly"),
            ApiKeyPermission::ReadWrite => write!(f, "readwrite"),
            ApiKeyPermission::Admin => write!(f, "admin"),
        }
    }
}

impl From<ApiKeyPermission> for UserRole {
    fn from(permission: ApiKeyPermission) -> Self {
        match permission {
            ApiKeyPermission::ReadOnly => UserRole::ReadOnly,
            ApiKeyPermission::ReadWrite => UserRole::User,
            ApiKeyPermission::Admin => UserRole::Admin,
        }
    }
}

/// API Key usage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyUsageStats {
    pub total_requests: u64,
    pub last_used_at: Option<DateTime<Utc>>,
    pub requests_today: u64,
    pub requests_this_hour: u64,
    pub last_reset_date: Option<chrono::NaiveDate>,
    pub last_reset_hour: Option<u32>,
}

impl Default for ApiKeyUsageStats {
    fn default() -> Self {
        Self {
            total_requests: 0,
            last_used_at: None,
            requests_today: 0,
            requests_this_hour: 0,
            last_reset_date: None,
            last_reset_hour: None,
        }
    }
}

/// API Key model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub key_prefix: String,
    pub key_hash: String,
    pub permission: ApiKeyPermission,
    pub owner_id: String,
    pub owner_username: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub usage_stats: ApiKeyUsageStats,
    pub rate_limit_requests: Option<u32>,
    pub rate_limit_window_seconds: Option<u32>,
}

/// Create API Key request
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
    pub description: Option<String>,
    pub permission: ApiKeyPermission,
    pub expires_in_days: Option<u32>,
    pub rate_limit_requests: Option<u32>,
    pub rate_limit_window_seconds: Option<u32>,
}

/// API Key response (includes the plaintext key only on creation)
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiKeyResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub key_prefix: String,
    pub permission: ApiKeyPermission,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub usage_stats: ApiKeyUsageStats,
    pub rate_limit_requests: Option<u32>,
    pub rate_limit_window_seconds: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>, // Only included on creation
}

impl From<&ApiKey> for ApiKeyResponse {
    fn from(api_key: &ApiKey) -> Self {
        Self {
            id: api_key.id.clone(),
            name: api_key.name.clone(),
            description: api_key.description.clone(),
            key_prefix: api_key.key_prefix.clone(),
            permission: api_key.permission.clone(),
            created_at: api_key.created_at,
            expires_at: api_key.expires_at,
            is_active: api_key.is_active,
            usage_stats: api_key.usage_stats.clone(),
            rate_limit_requests: api_key.rate_limit_requests,
            rate_limit_window_seconds: api_key.rate_limit_window_seconds,
            key: None,
        }
    }
}

/// Update API Key request
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateApiKeyRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub is_active: Option<bool>,
    pub rate_limit_requests: Option<u32>,
    pub rate_limit_window_seconds: Option<u32>,
}

/// API Key rotation response
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiKeyRotationResponse {
    pub id: String,
    pub new_key: String,
    pub key_prefix: String,
    pub rotated_at: DateTime<Utc>,
}

/// List API Keys request
#[derive(Debug, Serialize, Deserialize)]
pub struct ListApiKeysRequest {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub active_only: Option<bool>,
}

/// List API Keys response
#[derive(Debug, Serialize, Deserialize)]
pub struct ListApiKeysResponse {
    pub keys: Vec<ApiKeyResponse>,
    pub total: u32,
    pub limit: u32,
    pub offset: u32,
}

/// API Key validation context
#[derive(Debug, Clone)]
pub struct ApiKeyContext {
    pub api_key: ApiKey,
    pub user_role: UserRole,
}

// RBAC (Role-Based Access Control) Models

/// User role assignment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRoleAssignment {
    pub user_id: String,
    pub username: String,
    pub role_name: String,
    pub assigned_by: String,
    pub assigned_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub metadata: Option<serde_json::Value>,
}

/// Request to update an existing role
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateRoleRequest {
    /// Optional new description for the role
    pub description: Option<String>,
    /// Optional new permissions for the role
    pub permissions: Option<Vec<String>>,
    /// Optional roles this role inherits from
    pub inherits_from: Option<Vec<String>>,
}

/// Request to create a new role
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateRoleRequest {
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<String>,
    pub inherits_from: Option<Vec<String>>,
}

/// Request to assign a role to a user
#[derive(Debug, Serialize, Deserialize)]
pub struct AssignRoleRequest {
    pub user_id: String,
    pub role_name: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub expires_in_days: Option<u32>,
    pub metadata: Option<serde_json::Value>,
}

/// Request to revoke a role from a user
#[derive(Debug, Serialize, Deserialize)]
pub struct RevokeRoleRequest {
    pub user_id: String,
    pub role_name: String,
    pub reason: Option<String>,
}

/// Role response for API
#[derive(Debug, Serialize, Deserialize)]
pub struct RoleResponse {
    pub name: String,
    pub description: String,
    pub permissions: Vec<String>,
    pub inherits_from: Vec<String>,
    pub is_default: bool,
    pub is_system: bool,
    pub effective_permissions: Vec<String>,
}

/// User permissions response
#[derive(Debug, Serialize, Deserialize)]
pub struct UserPermissionsResponse {
    pub user_id: String,
    pub username: String,
    pub roles: Vec<String>,
    pub effective_permissions: Vec<String>,
    pub role_assignments: Vec<UserRoleAssignment>,
}

/// Audit log entry for authorization events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: AuditEventType,
    pub user_id: Option<String>,
    pub username: Option<String>,
    pub resource: String,
    pub action: String,
    pub permission_required: Option<String>,
    pub permission_granted: bool,
    pub role: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

/// Audit event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventType {
    Authorization,
    Authentication,
    RoleAssignment,
    RoleRevocation,
    RoleCreation,
    RoleUpdate,
    RoleDeletion,
    RoleManagement,
    PermissionCheck,
    AccessDenied,
    AccessGranted,
}

impl std::fmt::Display for AuditEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditEventType::Authorization => write!(f, "authorization"),
            AuditEventType::Authentication => write!(f, "authentication"),
            AuditEventType::RoleAssignment => write!(f, "role_assignment"),
            AuditEventType::RoleRevocation => write!(f, "role_revocation"),
            AuditEventType::RoleCreation => write!(f, "role_creation"),
            AuditEventType::RoleUpdate => write!(f, "role_update"),
            AuditEventType::RoleDeletion => write!(f, "role_deletion"),
            AuditEventType::RoleManagement => write!(f, "role_management"),
            AuditEventType::PermissionCheck => write!(f, "permission_check"),
            AuditEventType::AccessDenied => write!(f, "access_denied"),
            AuditEventType::AccessGranted => write!(f, "access_granted"),
        }
    }
}

/// Audit query parameters
#[derive(Debug, Deserialize)]
pub struct AuditQueryParams {
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    pub user_id: Option<String>,
    pub event_type: Option<AuditEventType>,
    pub resource: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

/// Permission check context for audit logging
#[derive(Debug, Clone)]
pub struct PermissionCheckContext {
    pub user_id: Option<String>,
    pub username: Option<String>,
    pub role: Option<String>,
    pub resource: String,
    pub action: String,
    pub permission_required: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// RBAC context that contains authenticated user information and RBAC service
#[derive(Debug, Clone)]
pub struct RbacContext {
    pub user_id: String,
    pub username: String,
    pub roles: Vec<String>,
    pub rbac_service: Arc<crate::auth::RbacService>,
    pub role: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
};

#[async_trait]
impl<S> FromRequestParts<S> for RbacContext
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<RbacContext>()
            .cloned()
            .ok_or(StatusCode::UNAUTHORIZED)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitPolicy {
    pub requests: u32,
    pub window_seconds: u32,
    pub burst_allowance: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitInfo {
    pub allowed: bool,
    pub limit: u32,
    pub remaining: u32,
    pub reset_time: DateTime<Utc>,
    pub retry_after: Option<u32>,
}
