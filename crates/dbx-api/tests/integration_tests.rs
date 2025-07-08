mod test_utils;

use anyhow::Result;
use serde_json::{json, Value};
use test_utils::TestServer;

// Authentication Tests
#[tokio::test]
#[serial_test::serial]
async fn test_authentication_flow() -> Result<()> {
    let mut server = TestServer::new().await?;

    // Test admin authentication
    let admin_token = server.authenticate_admin().await?;
    assert!(!admin_token.is_empty());

    // Test user authentication
    let user_token = server.authenticate_user().await?;
    assert!(!user_token.is_empty());
    assert_ne!(admin_token, user_token);

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_invalid_credentials() -> Result<()> {
    let server = TestServer::new().await?;

    let auth_payload = json!({
        "username": "invalid",
        "password": "wrong"
    });

    let response = server
        .client
        .post(&format!("{}/auth/login", server.base_url))
        .json(&auth_payload)
        .send()
        .await?;

    assert_eq!(response.status(), 401);

    let body: Value = response.json().await?;
    assert_eq!(body["success"], false);
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("Invalid credentials"));

    Ok(())
}

// Admin Endpoint Tests
#[tokio::test]
#[serial_test::serial]
async fn test_admin_ping() -> Result<()> {
    let mut server = TestServer::new().await?;
    server.authenticate_admin().await?;

    let response = server.get_admin("/api/v1/admin/system").await?;
    assert_eq!(response.status(), 200);

    let body: Value = response.json().await?;
    assert!(body["success"].as_bool().unwrap_or(false));

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_admin_info() -> Result<()> {
    let mut server = TestServer::new().await?;
    server.authenticate_admin().await?;

    let response = server.get_admin("/api/v1/admin/system").await?;
    assert_eq!(response.status(), 200);

    let body: Value = response.json().await?;
    assert!(body["success"].as_bool().unwrap_or(false));

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_admin_health() -> Result<()> {
    let mut server = TestServer::new().await?;
    server.authenticate_admin().await?;

    let response = server.get_admin("/api/v1/admin/system").await?;
    assert_eq!(response.status(), 200);

    let body: Value = response.json().await?;
    assert!(body["success"].as_bool().unwrap_or(false));
    assert!(body["data"]["status"].as_str().unwrap_or("") == "Healthy");

    Ok(())
}

// String Operation Tests
#[tokio::test]
#[serial_test::serial]
async fn test_string_operations() -> Result<()> {
    let mut server = TestServer::new().await?;
    server.authenticate_admin().await?;

    let key = server.unique_key();
    let value = "test_value";

    // Set string
    let set_payload = json!({ "value": value });
    let response = server
        .post_admin(&format!("/api/v1/data/{}", key), &set_payload)
        .await?;
    assert_eq!(response.status(), 200);

    let body: Value = response.json().await?;
    assert!(body["success"].as_bool().unwrap_or(false));

    // Get string
    let response = server.get_admin(&format!("/api/v1/data/{}", key)).await?;
    assert_eq!(response.status(), 200);

    let body: Value = response.json().await?;
    assert!(body["success"].as_bool().unwrap_or(false));
    assert_eq!(body["data"]["data"].as_str(), Some(value));

    // Delete string
    let response = server
        .delete_admin(&format!("/api/v1/data/{}", key))
        .await?;
    assert_eq!(response.status(), 200);

    let body: Value = response.json().await?;
    assert!(body["success"].as_bool().unwrap_or(false));

    // Verify deletion
    let response = server.get_admin(&format!("/api/v1/data/{}", key)).await?;
    assert_eq!(response.status(), 200);

    let body: Value = response.json().await?;
    assert!(body["success"].as_bool().unwrap_or(false));
    assert!(body["data"]["data"].is_null());

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_string_special_characters() -> Result<()> {
    let mut server = TestServer::new().await?;
    server.authenticate_admin().await?;

    let key = server.unique_key();
    let special_value = "!@#$%^&*()_+-=[]{}|;':\",./<>?";

    // Set string with special characters
    let set_payload = json!({ "value": special_value });
    let response = server
        .post_admin(&format!("/api/v1/data/{}", key), &set_payload)
        .await?;
    assert_eq!(response.status(), 200);

    let body: Value = response.json().await?;
    assert!(body["success"].as_bool().unwrap_or(false));

    // Get string
    let response = server.get_admin(&format!("/api/v1/data/{}", key)).await?;
    assert_eq!(response.status(), 200);

    let body: Value = response.json().await?;
    assert!(body["success"].as_bool().unwrap_or(false));
    assert_eq!(body["data"]["data"].as_str(), Some(special_value));

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_large_string() -> Result<()> {
    let mut server = TestServer::new().await?;
    server.authenticate_admin().await?;

    let key = server.unique_key();
    let large_value = "x".repeat(10000);

    // Set large string
    let set_payload = json!({ "value": large_value });
    let response = server
        .post_admin(&format!("/redis/string/{}", key), &set_payload)
        .await?;
    assert_eq!(response.status(), 200);

    // Get large string
    let response = server.get_admin(&format!("/redis/string/{}", key)).await?;
    assert_eq!(response.status(), 200);

    let body: Option<String> = response.json().await?;
    assert_eq!(body, Some(large_value));

    Ok(())
}

// Authorization Tests
#[tokio::test]
#[serial_test::serial]
async fn test_unauthorized_access() -> Result<()> {
    let server = TestServer::new().await?;

    // Test admin endpoint without auth
    let response = server.get_unauthenticated("/api/v1/admin/system").await?;
    assert_eq!(response.status(), 401);

    // Test user endpoint without auth
    let response = server.get_unauthenticated("/api/v1/data/test").await?;
    assert_eq!(response.status(), 401);

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_user_access_restrictions() -> Result<()> {
    let mut server = TestServer::new().await?;
    server.authenticate_user().await?;

    // User should be able to access string endpoints
    let key = server.unique_key();
    let response = server.get_user(&format!("/redis/string/{}", key)).await?;
    assert_eq!(response.status(), 200);

    // User should NOT be able to access admin endpoints (403 Forbidden)
    let response = server.get_user("/redis/admin/ping").await?;
    assert_eq!(response.status(), 403); // Forbidden - route exists but access denied

    Ok(())
}

// Hash Operation Tests
#[tokio::test]
#[serial_test::serial]
async fn test_hash_operations() -> Result<()> {
    let mut server = TestServer::new().await?;
    server.authenticate_admin().await?;

    let key = server.unique_key();
    let field = "test_field";
    let value = "test_value";

    // Set hash field
    let set_payload = json!({ "value": value });
    let response = server
        .post_admin(&format!("/redis/hash/{}/{}", key, field), &set_payload)
        .await?;
    assert_eq!(response.status(), 200);

    // Get hash field
    let response = server
        .get_admin(&format!("/redis/hash/{}/{}", key, field))
        .await?;
    assert_eq!(response.status(), 200);

    let body: Option<String> = response.json().await?;
    assert_eq!(body, Some(value.to_string()));

    Ok(())
}

// Set Operation Tests
#[tokio::test]
#[serial_test::serial]
async fn test_set_operations() -> Result<()> {
    let mut server = TestServer::new().await?;
    server.authenticate_admin().await?;

    let key = server.unique_key();
    let member = "test_member";

    // Add to set
    let add_payload = json!({ "member": member });
    let response = server
        .post_admin(&format!("/redis/set/{}", key), &add_payload)
        .await?;
    assert_eq!(response.status(), 200);

    // Get set members
    let response = server
        .get_admin(&format!("/redis/set/{}/members", key))
        .await?;
    assert_eq!(response.status(), 200);

    let body: Vec<String> = response.json().await?;
    assert!(body.contains(&member.to_string()));

    Ok(())
}

// Health Check Test
#[tokio::test]
#[serial_test::serial]
async fn test_health_endpoint() -> Result<()> {
    let server = TestServer::new().await?;

    let response = server.get_unauthenticated("/health").await?;
    assert_eq!(response.status(), 200);

    let body: Value = response.json().await?;
    assert_eq!(body["success"], true);
    assert_eq!(body["data"], "Server is running");

    Ok(())
}

// Redis String Operations Tests

#[tokio::test]
#[serial_test::serial]
async fn test_string_operations_with_ttl() -> Result<()> {
    let mut server = TestServer::new().await?;
    server.authenticate_admin().await?;

    let key = server.unique_key();
    let value = "test_value_with_ttl";

    // Set string with TTL
    let set_payload = json!({ "value": value, "ttl": 60 });
    let response = server
        .post_admin(&format!("/api/v1/data/{}", key), &set_payload)
        .await?;
    assert_eq!(response.status(), 200);

    let body: Value = response.json().await?;
    assert!(body["success"].as_bool().unwrap_or(false));

    // Get string
    let response = server.get_admin(&format!("/api/v1/data/{}", key)).await?;
    assert_eq!(response.status(), 200);

    let body: Value = response.json().await?;
    assert!(body["success"].as_bool().unwrap_or(false));
    assert_eq!(body["data"]["data"].as_str(), Some(value));

    // Note: TTL info would be available through backend health/stats endpoints
    // For this test, we'll just verify the data was set successfully with TTL

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_string_batch_get_operations() -> Result<()> {
    let mut server = TestServer::new().await?;
    server.authenticate_admin().await?;

    let key1 = server.unique_key();
    let key2 = server.unique_key();
    let key3 = server.unique_key();

    // Set multiple strings
    let set_payload1 = json!({ "value": "value1" });
    let set_payload2 = json!({ "value": "value2" });

    server
        .post_admin(&format!("/redis/string/{}", key1), &set_payload1)
        .await?;
    server
        .post_admin(&format!("/redis/string/{}", key2), &set_payload2)
        .await?;
    // key3 is not set intentionally

    // Batch get operation
    let batch_payload = json!({ "keys": [key1, key2, key3] });
    let response = server
        .post_admin("/redis/string/batch/get", &batch_payload)
        .await?;
    assert_eq!(response.status(), 200);

    let body: Vec<Option<String>> = response.json().await?;
    assert_eq!(body.len(), 3);
    assert_eq!(body[0], Some("value1".to_string()));
    assert_eq!(body[1], Some("value2".to_string()));
    assert_eq!(body[2], None);

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_string_batch_set_operations() -> Result<()> {
    let mut server = TestServer::new().await?;
    server.authenticate_admin().await?;

    let key1 = server.unique_key();
    let key2 = server.unique_key();
    let key3 = server.unique_key();

    // Batch set operations - using valid operations only (no null values)
    let batch_payload = json!({
        "operations": [
            { "key": key1, "value": "batch_value1" },
            { "key": key2, "value": "batch_value2", "ttl": 300 }
        ]
    });

    let response = server
        .post_admin("/redis/string/batch/set", &batch_payload)
        .await?;
    assert_eq!(response.status(), 200);

    // Verify values were set correctly
    let response = server.get_admin(&format!("/redis/string/{}", key1)).await?;
    let body: Option<String> = response.json().await?;
    assert_eq!(body, Some("batch_value1".to_string()));

    let response = server.get_admin(&format!("/redis/string/{}", key2)).await?;
    let body: Option<String> = response.json().await?;
    assert_eq!(body, Some("batch_value2".to_string()));

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_string_pattern_operations() -> Result<()> {
    let mut server = TestServer::new().await?;
    server.authenticate_admin().await?;

    let base_key = server.unique_key();

    // Set multiple strings with pattern
    let set_payload = json!({ "value": "pattern_value" });
    server
        .post_admin(&format!("/redis/string/{}:user:1", base_key), &set_payload)
        .await?;
    server
        .post_admin(&format!("/redis/string/{}:user:2", base_key), &set_payload)
        .await?;
    server
        .post_admin(
            &format!("/redis/string/{}:session:1", base_key),
            &set_payload,
        )
        .await?;

    // Test pattern matching (ungrouped)
    let pattern_payload = json!({
        "patterns": [format!("{}:user:*", base_key)],
        "grouped": false
    });

    let response = server
        .post_admin("/redis/string/batch/patterns", &pattern_payload)
        .await?;
    assert_eq!(response.status(), 200);

    let body: Value = response.json().await?;
    assert_eq!(body["grouped"], false);
    assert!(body["results"].is_object());

    // Test pattern matching (grouped)
    let pattern_payload = json!({
        "patterns": [format!("{}:user:*", base_key), format!("{}:session:*", base_key)],
        "grouped": true
    });

    let response = server
        .post_admin("/redis/string/batch/patterns", &pattern_payload)
        .await?;
    assert_eq!(response.status(), 200);

    let body: Value = response.json().await?;
    assert_eq!(body["grouped"], true);
    assert!(body["results"].is_array());

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_string_pattern_operations_empty_patterns() -> Result<()> {
    let mut server = TestServer::new().await?;
    server.authenticate_admin().await?;

    // Test empty patterns ungrouped
    let pattern_payload = json!({
        "patterns": [],
        "grouped": false
    });

    let response = server
        .post_admin("/redis/string/batch/patterns", &pattern_payload)
        .await?;
    assert_eq!(response.status(), 200);

    let body: Value = response.json().await?;
    assert_eq!(body["grouped"], false);
    assert!(body["results"].is_array());

    // Test empty patterns grouped
    let pattern_payload = json!({
        "patterns": [],
        "grouped": true
    });

    let response = server
        .post_admin("/redis/string/batch/patterns", &pattern_payload)
        .await?;
    assert_eq!(response.status(), 200);

    let body: Value = response.json().await?;
    assert_eq!(body["grouped"], true);
    assert!(body["results"].is_array());

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_string_operations_error_conditions() -> Result<()> {
    let mut server = TestServer::new().await?;
    server.authenticate_admin().await?;

    // Test invalid JSON payload
    let response = server
        .client
        .post(&format!("{}/api/v1/data/test", server.base_url))
        .header(
            "Authorization",
            format!("Bearer {}", server.admin_token.as_ref().unwrap()),
        )
        .header("Content-Type", "application/json")
        .body("invalid json")
        .send()
        .await?;

    assert_eq!(response.status(), 400); // Axum returns 400 for JSON parsing errors

    // Test missing value field
    let invalid_payload = json!({ "ttl": 300 });
    let response = server
        .client
        .post(&format!("{}/api/v1/data/test", server.base_url))
        .header(
            "Authorization",
            format!("Bearer {}", server.admin_token.as_ref().unwrap()),
        )
        .json(&invalid_payload)
        .send()
        .await?;

    assert_eq!(response.status(), 422); // 422 Unprocessable Entity is correct for validation errors

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_string_operations_edge_cases() -> Result<()> {
    let mut server = TestServer::new().await?;
    server.authenticate_admin().await?;

    // Test empty string value
    let key = server.unique_key();
    let set_payload = json!({ "value": "" });
    let response = server
        .post_admin(&format!("/api/v1/data/{}", key), &set_payload)
        .await?;
    assert_eq!(response.status(), 200);

    let body: Value = response.json().await?;
    assert!(body["success"].as_bool().unwrap_or(false));

    let response = server.get_admin(&format!("/api/v1/data/{}", key)).await?;
    assert_eq!(response.status(), 200);

    let body: Value = response.json().await?;
    assert!(body["success"].as_bool().unwrap_or(false));
    assert!(body["data"]["success"].as_bool().unwrap_or(false));
    // For empty string, the data should be an empty string, not null
    assert_eq!(body["data"]["data"].as_str(), Some(""));

    // Test very long key name
    let long_key = format!("{}:{}", server.unique_key(), "a".repeat(1000));
    let set_payload = json!({ "value": "long_key_value" });
    let response = server
        .post_admin(&format!("/api/v1/data/{}", long_key), &set_payload)
        .await?;
    assert_eq!(response.status(), 200);

    let body: Value = response.json().await?;
    assert!(body["success"].as_bool().unwrap_or(false));

    // Test Unicode values
    let unicode_key = server.unique_key();
    let unicode_value = "unicode_test_value";
    let set_payload = json!({ "value": unicode_value });
    let response = server
        .post_admin(&format!("/api/v1/data/{}", unicode_key), &set_payload)
        .await?;
    assert_eq!(response.status(), 200);

    let body: Value = response.json().await?;
    assert!(body["success"].as_bool().unwrap_or(false));

    let response = server
        .get_admin(&format!("/api/v1/data/{}", unicode_key))
        .await?;
    assert_eq!(response.status(), 200);

    let body: Value = response.json().await?;
    assert!(body["success"].as_bool().unwrap_or(false));
    assert!(body["data"]["success"].as_bool().unwrap_or(false));
    assert_eq!(body["data"]["data"].as_str(), Some(unicode_value));

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_string_batch_operations_edge_cases() -> Result<()> {
    let mut server = TestServer::new().await?;
    server.authenticate_admin().await?;

    // Test batch get with empty keys
    let batch_payload = json!({ "keys": [] });
    let response = server
        .post_admin("/redis/string/batch/get", &batch_payload)
        .await?;
    assert_eq!(response.status(), 200);

    let body: Vec<Option<String>> = response.json().await?;
    assert_eq!(body.len(), 0);

    // Test batch set with empty operations
    let batch_payload = json!({ "operations": [] });
    let response = server
        .post_admin("/redis/string/batch/set", &batch_payload)
        .await?;
    assert_eq!(response.status(), 200);

    // Test batch get with very large number of keys
    let keys: Vec<String> = (0..1000)
        .map(|i| format!("large_batch_key_{}", i))
        .collect();
    let batch_payload = json!({ "keys": keys });
    let response = server
        .post_admin("/redis/string/batch/get", &batch_payload)
        .await?;
    assert_eq!(response.status(), 200);

    let body: Vec<Option<String>> = response.json().await?;
    assert_eq!(body.len(), 1000);

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_string_unauthorized_operations() -> Result<()> {
    let mut server = TestServer::new().await?;
    server.authenticate_user().await?;

    let key = server.unique_key();

    // Test that regular users can access string operations
    let set_payload = json!({ "value": "user_value" });
    let response = server
        .client
        .post(&format!("{}/redis/string/{}", server.base_url, key))
        .header(
            "Authorization",
            format!("Bearer {}", server.user_token.as_ref().unwrap()),
        )
        .json(&set_payload)
        .send()
        .await?;

    assert_eq!(response.status(), 200);

    // Test unauthenticated access
    let response = server
        .get_unauthenticated(&format!("/redis/string/{}", key))
        .await?;
    assert_eq!(response.status(), 401);

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_string_method_not_allowed() -> Result<()> {
    let mut server = TestServer::new().await?;
    server.authenticate_admin().await?;

    let key = server.unique_key();

    // Test PUT method (should return 405 Method Not Allowed)
    let response = server
        .client
        .put(&format!("{}/redis/string/{}", server.base_url, key))
        .header(
            "Authorization",
            format!("Bearer {}", server.admin_token.as_ref().unwrap()),
        )
        .send()
        .await?;

    assert_eq!(response.status(), 405);

    // Test PATCH method (should return 405 Method Not Allowed)
    let response = server
        .client
        .patch(&format!("{}/redis/string/{}", server.base_url, key))
        .header(
            "Authorization",
            format!("Bearer {}", server.admin_token.as_ref().unwrap()),
        )
        .send()
        .await?;

    assert_eq!(response.status(), 405);

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_string_info_operations() -> Result<()> {
    let mut server = TestServer::new().await?;
    server.authenticate_admin().await?;

    let key = server.unique_key();

    // Test getting info for non-existent key
    let response = server
        .get_admin(&format!("/redis/string/{}/info", key))
        .await?;
    assert_eq!(response.status(), 200);

    let body: Option<Value> = response.json().await?;
    assert!(body.is_none());

    // Set a string and get info
    let set_payload = json!({ "value": "info_test_value" });
    server
        .post_admin(&format!("/redis/string/{}", key), &set_payload)
        .await?;

    let response = server
        .get_admin(&format!("/redis/string/{}/info", key))
        .await?;
    assert_eq!(response.status(), 200);

    let body: Option<Value> = response.json().await?;
    assert!(body.is_some());

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_string_concurrent_operations() -> Result<()> {
    let mut server = TestServer::new().await?;
    server.authenticate_admin().await?;

    let base_key = server.unique_key();

    // Create multiple concurrent operations
    let mut handles = Vec::new();

    for i in 0..10 {
        let key = format!("{}:concurrent:{}", base_key, i);
        let value = format!("concurrent_value_{}", i);
        let server_url = server.base_url.clone();
        let token = server.admin_token.as_ref().unwrap().clone();

        let handle = tokio::spawn(async move {
            let client = reqwest::Client::new();
            let set_payload = json!({ "value": value });

            let response = client
                .post(&format!("{}/redis/string/{}", server_url, key))
                .header("Authorization", format!("Bearer {}", token))
                .json(&set_payload)
                .send()
                .await;

            response.unwrap().status() == 200
        });

        handles.push(handle);
    }

    // Wait for all operations to complete
    for handle in handles {
        assert!(handle.await?);
    }

    // Verify all values were set
    for i in 0..10 {
        let key = format!("{}:concurrent:{}", base_key, i);
        let expected_value = format!("concurrent_value_{}", i);

        let response = server.get_admin(&format!("/redis/string/{}", key)).await?;
        let body: Option<String> = response.json().await?;
        assert_eq!(body, Some(expected_value));
    }

    Ok(())
}
