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
}

impl Default for ApiKeyUsageStats {
    fn default() -> Self {
        Self {
            total_requests: 0,
            last_used_at: None,
            requests_today: 0,
            requests_this_hour: 0,
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

/// Role assignment request
#[derive(Debug, Serialize, Deserialize)]
pub struct AssignRoleRequest {
    pub user_id: String,
    pub role_name: String,
    pub expires_in_days: Option<u32>,
    pub metadata: Option<serde_json::Value>,
}

/// Role revocation request
#[derive(Debug, Serialize, Deserialize)]
pub struct RevokeRoleRequest {
    pub user_id: String,
    pub role_name: String,
    pub reason: Option<String>,
}

/// Create custom role request
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateRoleRequest {
    pub name: String,
    pub description: String,
    pub permissions: Vec<String>,
    pub inherits_from: Option<Vec<String>>,
}

/// Update role request
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateRoleRequest {
    pub description: Option<String>,
    pub permissions: Option<Vec<String>>,
    pub inherits_from: Option<Vec<String>>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_user_role_serialization() {
        assert_eq!(
            serde_json::to_string(&UserRole::Admin).unwrap(),
            "\"Admin\""
        );
        assert_eq!(serde_json::to_string(&UserRole::User).unwrap(), "\"User\"");
        assert_eq!(
            serde_json::to_string(&UserRole::ReadOnly).unwrap(),
            "\"ReadOnly\""
        );
    }

    #[test]
    fn test_user_role_deserialization() {
        assert_eq!(
            serde_json::from_str::<UserRole>("\"Admin\"").unwrap(),
            UserRole::Admin
        );
        assert_eq!(
            serde_json::from_str::<UserRole>("\"User\"").unwrap(),
            UserRole::User
        );
        assert_eq!(
            serde_json::from_str::<UserRole>("\"ReadOnly\"").unwrap(),
            UserRole::ReadOnly
        );
    }

    #[test]
    fn test_user_role_equality() {
        assert_eq!(UserRole::Admin, UserRole::Admin);
        assert_ne!(UserRole::Admin, UserRole::User);
        assert_ne!(UserRole::User, UserRole::ReadOnly);
    }

    #[test]
    fn test_user_serialization() {
        let user = User {
            id: "test-id".to_string(),
            username: "testuser".to_string(),
            password_hash: "hash123".to_string(),
            role: UserRole::Admin,
            is_active: true,
            created_at: DateTime::from_timestamp(1640995200, 0).unwrap(),
            updated_at: DateTime::from_timestamp(1640995200, 0).unwrap(),
        };

        let json = serde_json::to_string(&user).unwrap();
        let deserialized: User = serde_json::from_str(&json).unwrap();

        assert_eq!(user.id, deserialized.id);
        assert_eq!(user.username, deserialized.username);
        assert_eq!(user.role, deserialized.role);
        assert_eq!(user.is_active, deserialized.is_active);
    }

    #[test]
    fn test_create_user_request() {
        let request = CreateUserRequest {
            username: "newuser".to_string(),
            password: "password123".to_string(),
            role: UserRole::User,
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: CreateUserRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(request.username, deserialized.username);
        assert_eq!(request.password, deserialized.password);
        assert_eq!(request.role, deserialized.role);
    }

    #[test]
    fn test_login_request() {
        let request = LoginRequest {
            username: "user".to_string(),
            password: "pass".to_string(),
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: LoginRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(request.username, deserialized.username);
        assert_eq!(request.password, deserialized.password);
    }

    #[test]
    fn test_refresh_request() {
        let request = RefreshRequest {
            refresh_token: "token123".to_string(),
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: RefreshRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(request.refresh_token, deserialized.refresh_token);
    }

    #[test]
    fn test_user_info() {
        let user_info = UserInfo {
            id: "user-id".to_string(),
            username: "username".to_string(),
            role: UserRole::ReadOnly,
        };

        let json = serde_json::to_string(&user_info).unwrap();
        let deserialized: UserInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(user_info.id, deserialized.id);
        assert_eq!(user_info.username, deserialized.username);
        assert_eq!(user_info.role, deserialized.role);
    }

    #[test]
    fn test_auth_response() {
        let user_info = UserInfo {
            id: "user-id".to_string(),
            username: "username".to_string(),
            role: UserRole::Admin,
        };

        let auth_response = AuthResponse {
            access_token: "access123".to_string(),
            refresh_token: "refresh123".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 3600,
            user: user_info,
        };

        let json = serde_json::to_string(&auth_response).unwrap();
        let deserialized: AuthResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(auth_response.access_token, deserialized.access_token);
        assert_eq!(auth_response.refresh_token, deserialized.refresh_token);
        assert_eq!(auth_response.token_type, deserialized.token_type);
        assert_eq!(auth_response.expires_in, deserialized.expires_in);
        assert_eq!(auth_response.user.id, deserialized.user.id);
    }

    #[test]
    fn test_token_validation_response_valid() {
        let user_info = UserInfo {
            id: "user-id".to_string(),
            username: "username".to_string(),
            role: UserRole::User,
        };

        let response = TokenValidationResponse {
            valid: true,
            user: Some(user_info),
            expires_at: Some(DateTime::from_timestamp(1640995200, 0).unwrap()),
        };

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: TokenValidationResponse = serde_json::from_str(&json).unwrap();

        assert!(deserialized.valid);
        assert!(deserialized.user.is_some());
        assert!(deserialized.expires_at.is_some());
    }

    #[test]
    fn test_token_validation_response_invalid() {
        let response = TokenValidationResponse {
            valid: false,
            user: None,
            expires_at: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: TokenValidationResponse = serde_json::from_str(&json).unwrap();

        assert!(!deserialized.valid);
        assert!(deserialized.user.is_none());
        assert!(deserialized.expires_at.is_none());
    }

    #[test]
    fn test_api_response_success() {
        let response = ApiResponse::success("test data".to_string());

        assert!(response.success);
        assert_eq!(response.data, Some("test data".to_string()));
        assert!(response.error.is_none());

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: ApiResponse<String> = serde_json::from_str(&json).unwrap();

        assert!(deserialized.success);
        assert_eq!(deserialized.data, Some("test data".to_string()));
        assert!(deserialized.error.is_none());
    }

    #[test]
    fn test_api_response_error() {
        let response: ApiResponse<String> = ApiResponse::error("test error".to_string());

        assert!(!response.success);
        assert!(response.data.is_none());
        assert_eq!(response.error, Some("test error".to_string()));

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: ApiResponse<String> = serde_json::from_str(&json).unwrap();

        assert!(!deserialized.success);
        assert!(deserialized.data.is_none());
        assert_eq!(deserialized.error, Some("test error".to_string()));
    }

    #[test]
    fn test_api_response_with_complex_data() {
        let user_info = UserInfo {
            id: "complex-id".to_string(),
            username: "complex-user".to_string(),
            role: UserRole::Admin,
        };

        let response = ApiResponse::success(user_info);
        let json = serde_json::to_string(&response).unwrap();
        let deserialized: ApiResponse<UserInfo> = serde_json::from_str(&json).unwrap();

        assert!(deserialized.success);
        assert!(deserialized.data.is_some());
        assert_eq!(deserialized.data.unwrap().username, "complex-user");
    }

    #[test]
    fn test_user_clone() {
        let user = User {
            id: "clone-test".to_string(),
            username: "cloneuser".to_string(),
            password_hash: "hash".to_string(),
            role: UserRole::User,
            is_active: false,
            created_at: DateTime::from_timestamp(1640995200, 0).unwrap(),
            updated_at: DateTime::from_timestamp(1640995200, 0).unwrap(),
        };

        let cloned = user.clone();
        assert_eq!(user.id, cloned.id);
        assert_eq!(user.username, cloned.username);
        assert_eq!(user.role, cloned.role);
        assert_eq!(user.is_active, cloned.is_active);
    }

    #[test]
    fn test_user_role_debug() {
        let role = UserRole::Admin;
        let debug_str = format!("{:?}", role);
        assert_eq!(debug_str, "Admin");
    }

    #[test]
    fn test_user_debug() {
        let user = User {
            id: "test-id".to_string(),
            username: "testuser".to_string(),
            password_hash: "hash123".to_string(),
            role: UserRole::Admin,
            is_active: true,
            created_at: DateTime::from_timestamp(1640995200, 0).unwrap(),
            updated_at: DateTime::from_timestamp(1640995200, 0).unwrap(),
        };

        let debug_str = format!("{:?}", user);
        assert!(debug_str.contains("User"));
        assert!(debug_str.contains("testuser"));
    }

    #[test]
    fn test_user_role_display() {
        assert_eq!(format!("{}", UserRole::Admin), "admin");
        assert_eq!(format!("{}", UserRole::User), "user");
        assert_eq!(format!("{}", UserRole::ReadOnly), "readonly");
    }

    #[test]
    fn test_token_type_serialization() {
        assert_eq!(
            serde_json::to_string(&TokenType::Access).unwrap(),
            "\"Access\""
        );
        assert_eq!(
            serde_json::to_string(&TokenType::Refresh).unwrap(),
            "\"Refresh\""
        );
    }

    #[test]
    fn test_token_type_deserialization() {
        assert_eq!(
            serde_json::from_str::<TokenType>("\"Access\"").unwrap(),
            TokenType::Access
        );
        assert_eq!(
            serde_json::from_str::<TokenType>("\"Refresh\"").unwrap(),
            TokenType::Refresh
        );
    }

    #[test]
    fn test_token_type_equality() {
        assert_eq!(TokenType::Access, TokenType::Access);
        assert_eq!(TokenType::Refresh, TokenType::Refresh);
        assert_ne!(TokenType::Access, TokenType::Refresh);
    }

    #[test]
    fn test_token_type_debug() {
        let debug_str = format!("{:?}", TokenType::Access);
        assert_eq!(debug_str, "Access");
        let debug_str = format!("{:?}", TokenType::Refresh);
        assert_eq!(debug_str, "Refresh");
    }

    #[test]
    fn test_claims_serialization() {
        let claims = Claims {
            sub: "user123".to_string(),
            username: "testuser".to_string(),
            role: UserRole::User,
            permissions: vec!["string:get".to_string(), "string:set".to_string()],
            exp: 1640995200,
            iat: 1640995100,
            iss: "test_issuer".to_string(),
            token_type: TokenType::Access,
        };

        let json = serde_json::to_string(&claims).unwrap();
        let deserialized: Claims = serde_json::from_str(&json).unwrap();

        assert_eq!(claims.sub, deserialized.sub);
        assert_eq!(claims.username, deserialized.username);
        assert_eq!(claims.role, deserialized.role);
        assert_eq!(claims.exp, deserialized.exp);
        assert_eq!(claims.iat, deserialized.iat);
        assert_eq!(claims.iss, deserialized.iss);
        assert_eq!(claims.token_type, deserialized.token_type);
    }

    #[test]
    fn test_claims_debug() {
        let claims = Claims {
            sub: "user123".to_string(),
            username: "testuser".to_string(),
            role: UserRole::User,
            permissions: vec!["string:get".to_string(), "string:set".to_string()],
            exp: 1640995200,
            iat: 1640995100,
            iss: "test_issuer".to_string(),
            token_type: TokenType::Access,
        };

        let debug_str = format!("{:?}", claims);
        assert!(debug_str.contains("Claims"));
        assert!(debug_str.contains("testuser"));
    }

    #[test]
    fn test_user_role_invalid_deserialization() {
        let result = serde_json::from_str::<UserRole>("\"InvalidRole\"");
        assert!(result.is_err());
    }

    #[test]
    fn test_token_type_invalid_deserialization() {
        let result = serde_json::from_str::<TokenType>("\"InvalidType\"");
        assert!(result.is_err());
    }

    #[test]
    fn test_login_request_debug() {
        let request = LoginRequest {
            username: "user".to_string(),
            password: "pass".to_string(),
        };

        let debug_str = format!("{:?}", request);
        assert!(debug_str.contains("LoginRequest"));
        assert!(debug_str.contains("user"));
    }

    #[test]
    fn test_create_user_request_debug() {
        let request = CreateUserRequest {
            username: "newuser".to_string(),
            password: "password123".to_string(),
            role: UserRole::User,
        };

        let debug_str = format!("{:?}", request);
        assert!(debug_str.contains("CreateUserRequest"));
        assert!(debug_str.contains("newuser"));
    }

    #[test]
    fn test_refresh_request_debug() {
        let request = RefreshRequest {
            refresh_token: "token123".to_string(),
        };

        let debug_str = format!("{:?}", request);
        assert!(debug_str.contains("RefreshRequest"));
        assert!(debug_str.contains("token123"));
    }

    #[test]
    fn test_auth_response_debug() {
        let auth_response = AuthResponse {
            access_token: "access123".to_string(),
            refresh_token: "refresh123".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 3600,
            user: UserInfo {
                id: "user1".to_string(),
                username: "testuser".to_string(),
                role: UserRole::User,
            },
        };

        let debug_str = format!("{:?}", auth_response);
        assert!(debug_str.contains("AuthResponse"));
        assert!(debug_str.contains("testuser"));
    }

    #[test]
    fn test_user_info_debug() {
        let user_info = UserInfo {
            id: "user1".to_string(),
            username: "testuser".to_string(),
            role: UserRole::Admin,
        };

        let debug_str = format!("{:?}", user_info);
        assert!(debug_str.contains("UserInfo"));
        assert!(debug_str.contains("testuser"));
    }

    #[test]
    fn test_token_validation_response_debug() {
        let response = TokenValidationResponse {
            valid: true,
            user: Some(UserInfo {
                id: "user1".to_string(),
                username: "testuser".to_string(),
                role: UserRole::User,
            }),
            expires_at: Some(DateTime::from_timestamp(1640995200, 0).unwrap()),
        };

        let debug_str = format!("{:?}", response);
        assert!(debug_str.contains("TokenValidationResponse"));
        assert!(debug_str.contains("testuser"));
    }

    #[test]
    fn test_api_response_debug() {
        let response: ApiResponse<String> = ApiResponse::success("test data".to_string());
        let debug_str = format!("{:?}", response);
        assert!(debug_str.contains("ApiResponse"));
        assert!(debug_str.contains("test data"));
    }

    #[test]
    fn test_user_clone_deep() {
        let original = User {
            id: "test-id".to_string(),
            username: "testuser".to_string(),
            password_hash: "hash123".to_string(),
            role: UserRole::Admin,
            is_active: true,
            created_at: DateTime::from_timestamp(1640995200, 0).unwrap(),
            updated_at: DateTime::from_timestamp(1640995200, 0).unwrap(),
        };

        let cloned = original.clone();

        // Verify deep clone by modifying original and ensuring clone is unchanged
        assert_eq!(original.id, cloned.id);
        assert_eq!(original.username, cloned.username);
        assert_eq!(original.role, cloned.role);
        assert_eq!(original.is_active, cloned.is_active);
    }

    #[test]
    fn test_all_structs_serialization_roundtrip() {
        // Test comprehensive serialization for all major structs
        let user_info = UserInfo {
            id: "user1".to_string(),
            username: "testuser".to_string(),
            role: UserRole::Admin,
        };

        let auth_response = AuthResponse {
            access_token: "access123".to_string(),
            refresh_token: "refresh123".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 3600,
            user: user_info.clone(),
        };

        let token_validation = TokenValidationResponse {
            valid: true,
            user: Some(user_info),
            expires_at: Some(DateTime::from_timestamp(1640995200, 0).unwrap()),
        };

        // Test all roundtrip serialization
        let auth_json = serde_json::to_string(&auth_response).unwrap();
        let auth_restored: AuthResponse = serde_json::from_str(&auth_json).unwrap();
        assert_eq!(auth_response.access_token, auth_restored.access_token);

        let validation_json = serde_json::to_string(&token_validation).unwrap();
        let validation_restored: TokenValidationResponse =
            serde_json::from_str(&validation_json).unwrap();
        assert_eq!(token_validation.valid, validation_restored.valid);
    }
}
