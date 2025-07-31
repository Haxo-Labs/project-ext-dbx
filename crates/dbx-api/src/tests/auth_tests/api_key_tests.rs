//! API key authentication tests

use crate::auth::api_keys::*;
use crate::models::{ApiKeyPermission, ApiKeyUsageStats, CreateApiKeyRequest, UserRole};

#[test]
fn test_generate_api_key() {
    let (key, prefix) = ApiKeyService::generate_api_key().unwrap();

    assert!(key.starts_with("dbx_"));
    assert!(key.len() >= 32);
    assert!(prefix.starts_with("dbx_"));
    assert!(prefix.ends_with("****"));
    assert!(ApiKeyService::validate_key_format(&key));
}

#[test]
fn test_hash_api_key() {
    let key = "dbx_test_key_12345678901234567890123456789";
    let hash1 = ApiKeyService::hash_api_key(key).unwrap();
    let hash2 = ApiKeyService::hash_api_key(key).unwrap();

    assert_eq!(hash1, hash2); // Same key should produce same hash
    assert!(hash1.len() == 64); // SHA256 produces 64-char hex string
}

#[test]
fn test_validate_key_format() {
    assert!(ApiKeyService::validate_key_format(
        "dbx_12345678901234567890123456789"
    ));
    assert!(!ApiKeyService::validate_key_format("invalid_key"));
    assert!(!ApiKeyService::validate_key_format("dbx_short"));
    assert!(!ApiKeyService::validate_key_format(
        "wrong_prefix_12345678901234567890123456789"
    ));
}

#[test]
fn test_extract_key_prefix() {
    let key = "dbx_abcdef1234567890123456789";
    let prefix = ApiKeyService::extract_key_prefix(&key);
    assert_eq!(prefix, "dbx_abcd****");
}

#[test]
fn test_api_key_permissions_conversion() {
    assert_eq!(
        UserRole::from(ApiKeyPermission::ReadOnly),
        UserRole::ReadOnly
    );
    assert_eq!(UserRole::from(ApiKeyPermission::ReadWrite), UserRole::User);
    assert_eq!(UserRole::from(ApiKeyPermission::Admin), UserRole::Admin);
}

#[test]
fn test_api_key_error_display() {
    let error = ApiKeyError::KeyNotFound;
    assert_eq!(error.to_string(), "API key not found");

    let error = ApiKeyError::ValidationError("Test validation error".to_string());
    assert_eq!(error.to_string(), "Validation error: Test validation error");
}

#[test]
fn test_create_api_key_request_validation() {
    let request = CreateApiKeyRequest {
        name: "Test API Key".to_string(),
        description: Some("Test description".to_string()),
        permission: ApiKeyPermission::ReadWrite,
        expires_in_days: Some(30),
        rate_limit_requests: Some(1000),
        rate_limit_window_seconds: Some(3600),
    };

    assert_eq!(request.name, "Test API Key");
    assert_eq!(request.permission, ApiKeyPermission::ReadWrite);
    assert_eq!(request.expires_in_days, Some(30));
    assert_eq!(request.rate_limit_requests, Some(1000));
    assert_eq!(request.rate_limit_window_seconds, Some(3600));
}

#[test]
fn test_api_key_usage_stats_default() {
    let stats = ApiKeyUsageStats::default();

    assert_eq!(stats.total_requests, 0);
    assert!(stats.last_used_at.is_none());
    assert_eq!(stats.requests_today, 0);
    assert_eq!(stats.requests_this_hour, 0);
}

#[test]
fn test_key_generation_multiple_keys() {
    let mut keys = Vec::new();
    for _ in 0..10 {
        let (key, _) = ApiKeyService::generate_api_key().unwrap();
        keys.push(key);
    }

    // All keys should be unique
    let mut sorted_keys = keys.clone();
    sorted_keys.sort();
    sorted_keys.dedup();
    assert_eq!(sorted_keys.len(), keys.len());

    // All keys should be valid format
    for key in &keys {
        assert!(ApiKeyService::validate_key_format(key));
    }
}

#[test]
fn test_hash_consistency() {
    let key = "dbx_test_key_consistent_12345678901234567890";
    let hash1 = ApiKeyService::hash_api_key(key).unwrap();
    let hash2 = ApiKeyService::hash_api_key(key).unwrap();
    let hash3 = ApiKeyService::hash_api_key(key).unwrap();

    assert_eq!(hash1, hash2);
    assert_eq!(hash2, hash3);
}

#[test]
fn test_hash_different_keys() {
    let key1 = "dbx_test_key1_12345678901234567890";
    let key2 = "dbx_test_key2_12345678901234567890";

    let hash1 = ApiKeyService::hash_api_key(key1).unwrap();
    let hash2 = ApiKeyService::hash_api_key(key2).unwrap();

    assert_ne!(hash1, hash2);
}

#[test]
fn test_prefix_extraction_edge_cases() {
    // Normal case
    assert_eq!(
        ApiKeyService::extract_key_prefix("dbx_abcdefghijk"),
        "dbx_abcd****"
    );

    // Short key after underscore
    assert_eq!(ApiKeyService::extract_key_prefix("dbx_ab"), "dbx_****");

    // No underscore
    assert_eq!(ApiKeyService::extract_key_prefix("dbxabcdefghijk"), "****");

    // Multiple underscores
    assert_eq!(
        ApiKeyService::extract_key_prefix("dbx_test_abcdefghijk"),
        "dbx_test****"
    );
}

#[test]
fn test_permission_to_string() {
    assert_eq!(ApiKeyPermission::ReadOnly.to_string(), "readonly");
    assert_eq!(ApiKeyPermission::ReadWrite.to_string(), "readwrite");
    assert_eq!(ApiKeyPermission::Admin.to_string(), "admin");
}

// Unit tests for API key operations

#[tokio::test]
async fn test_api_key_service_creation() {
    // Test API key request structure validation

    let request = CreateApiKeyRequest {
        name: "Test Key".to_string(),
        description: Some("Test description".to_string()),
        permission: ApiKeyPermission::ReadWrite,
        expires_in_days: Some(30),
        rate_limit_requests: None,
        rate_limit_window_seconds: None,
    };

    // Validation tests that don't require backend storage
    assert!(!request.name.is_empty());
    assert!(request.name.len() <= 100);
    assert_eq!(request.permission, ApiKeyPermission::ReadWrite);
}

#[tokio::test]
async fn test_validation_logic_without_backend() {
    // Test validation logic that doesn't require backend connection

    // Test key format validation
    let valid_key = "dbx_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    assert!(ApiKeyService::validate_key_format(valid_key));

    let invalid_key = "invalid_key";
    assert!(!ApiKeyService::validate_key_format(invalid_key));

    // Test hash generation
    let hash = ApiKeyService::hash_api_key(valid_key).unwrap();
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}
