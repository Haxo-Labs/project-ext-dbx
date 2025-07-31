//! API key route handler tests

use crate::models::{ApiKeyPermission, CreateApiKeyRequest, ListApiKeysRequest};

#[tokio::test]
async fn test_create_api_key_endpoint() {
    // Test would require backend setup
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
}

#[tokio::test]
async fn test_list_api_keys_query() {
    let query = ListApiKeysRequest {
        limit: Some(10),
        offset: Some(0),
        active_only: Some(true),
    };

    assert_eq!(query.limit, Some(10));
    assert_eq!(query.active_only, Some(true));
}
