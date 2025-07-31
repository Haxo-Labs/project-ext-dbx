//! Model serialization and validation tests
//!
//! Tests for all API model types including serialization, deserialization,
//! validation, and business logic correctness.

use crate::models::*;
use chrono::DateTime;
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
        username: "testuser".to_string(),
        role: UserRole::Admin,
    };

    let json = serde_json::to_string(&user_info).unwrap();
    let deserialized: UserInfo = serde_json::from_str(&json).unwrap();

    assert_eq!(user_info.id, deserialized.id);
    assert_eq!(user_info.username, deserialized.username);
    assert_eq!(user_info.role, deserialized.role);
}

#[test]
fn test_auth_response() {
    let response = AuthResponse {
        access_token: "access123".to_string(),
        refresh_token: "refresh123".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        user: UserInfo {
            id: "user-id".to_string(),
            username: "testuser".to_string(),
            role: UserRole::User,
        },
    };

    let json = serde_json::to_string(&response).unwrap();
    let deserialized: AuthResponse = serde_json::from_str(&json).unwrap();

    assert_eq!(response.access_token, deserialized.access_token);
    assert_eq!(response.refresh_token, deserialized.refresh_token);
    assert_eq!(response.token_type, deserialized.token_type);
    assert_eq!(response.expires_in, deserialized.expires_in);
    assert_eq!(response.user.id, deserialized.user.id);
}

#[test]
fn test_api_key_serialization() {
    let api_key = ApiKey {
        id: "key-id".to_string(),
        name: "Test Key".to_string(),
        description: Some("Test description".to_string()),
        key_hash: "hash123".to_string(),
        key_prefix: "dbx_".to_string(),
        permission: ApiKeyPermission::ReadOnly,
        is_active: true,
        expires_at: Some(DateTime::from_timestamp(1640995200, 0).unwrap()),
        created_at: DateTime::from_timestamp(1640995200, 0).unwrap(),
        updated_at: DateTime::from_timestamp(1640995200, 0).unwrap(),
        owner_id: "owner-123".to_string(),
        owner_username: "testuser".to_string(),
        usage_stats: crate::models::ApiKeyUsageStats::default(),
        rate_limit_requests: Some(100),
        rate_limit_window_seconds: Some(3600),
    };

    let json = serde_json::to_string(&api_key).unwrap();
    let deserialized: ApiKey = serde_json::from_str(&json).unwrap();

    assert_eq!(api_key.id, deserialized.id);
    assert_eq!(api_key.name, deserialized.name);
    assert_eq!(api_key.permission, deserialized.permission);
    assert_eq!(api_key.is_active, deserialized.is_active);
}

#[test]
fn test_api_response_error() {
    let error = ApiResponse::<()>::error("Not found".to_string());

    assert!(!error.success);
    assert_eq!(error.error, Some("Not found".to_string()));
    assert!(error.data.is_none());
}

#[test]
fn test_api_response_success() {
    let data = vec!["item1", "item2"];
    let response = ApiResponse::success(data.clone());

    assert!(response.success);
    assert_eq!(response.data, Some(data));
    assert!(response.error.is_none());
}

#[test]
fn test_rate_limit_info() {
    let rate_limit = RateLimitInfo {
        allowed: true,
        limit: 100,
        remaining: 95,
        reset_time: DateTime::from_timestamp(1640995200, 0).unwrap(),
        retry_after: Some(60),
    };

    let json = serde_json::to_string(&rate_limit).unwrap();
    let deserialized: RateLimitInfo = serde_json::from_str(&json).unwrap();

    assert_eq!(rate_limit.allowed, deserialized.allowed);
    assert_eq!(rate_limit.limit, deserialized.limit);
    assert_eq!(rate_limit.remaining, deserialized.remaining);
    assert_eq!(rate_limit.retry_after, deserialized.retry_after);
}
