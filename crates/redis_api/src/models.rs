use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_user_role_serialization() {
        assert_eq!(serde_json::to_string(&UserRole::Admin).unwrap(), "\"Admin\"");
        assert_eq!(serde_json::to_string(&UserRole::User).unwrap(), "\"User\"");
        assert_eq!(serde_json::to_string(&UserRole::ReadOnly).unwrap(), "\"ReadOnly\"");
    }

    #[test]
    fn test_user_role_deserialization() {
        assert_eq!(serde_json::from_str::<UserRole>("\"Admin\"").unwrap(), UserRole::Admin);
        assert_eq!(serde_json::from_str::<UserRole>("\"User\"").unwrap(), UserRole::User);
        assert_eq!(serde_json::from_str::<UserRole>("\"ReadOnly\"").unwrap(), UserRole::ReadOnly);
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
            id: "debug-test".to_string(),
            username: "debuguser".to_string(),
            password_hash: "debughash".to_string(),
            role: UserRole::ReadOnly,
            is_active: true,
            created_at: DateTime::from_timestamp(1640995200, 0).unwrap(),
            updated_at: DateTime::from_timestamp(1640995200, 0).unwrap(),
        };

        let debug_str = format!("{:?}", user);
        assert!(debug_str.contains("debuguser"));
        assert!(debug_str.contains("ReadOnly"));
    }
}
