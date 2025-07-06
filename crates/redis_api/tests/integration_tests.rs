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
    assert!(body["error"].as_str().unwrap().contains("Invalid credentials"));
    
    Ok(())
}

// Admin Endpoint Tests
#[tokio::test]
#[serial_test::serial]
async fn test_admin_ping() -> Result<()> {
    let mut server = TestServer::new().await?;
    server.authenticate_admin().await?;
    
    let response = server.get_admin("/redis/admin/ping").await?;
    assert_eq!(response.status(), 200);
    
    let body: String = response.json().await?;
    assert_eq!(body, "PONG");
    
    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_admin_info() -> Result<()> {
    let mut server = TestServer::new().await?;
    server.authenticate_admin().await?;
    
    let response = server.get_admin("/redis/admin/info").await?;
    assert_eq!(response.status(), 200);
    
    let body: String = response.json().await?;
    assert!(body.contains("redis_version"));
    
    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_admin_health() -> Result<()> {
    let mut server = TestServer::new().await?;
    server.authenticate_admin().await?;
    
    let response = server.get_admin("/redis/admin/health").await?;
    assert_eq!(response.status(), 200);
    
    let body: Value = response.json().await?;
    assert_eq!(body["is_healthy"], true);
    assert_eq!(body["ping_response"], "PONG");
    
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
    let response = server.post_admin(&format!("/redis/string/{}", key), &set_payload).await?;
    assert_eq!(response.status(), 200);
    
    // Get string
    let response = server.get_admin(&format!("/redis/string/{}", key)).await?;
    assert_eq!(response.status(), 200);
    
    let body: Option<String> = response.json().await?;
    assert_eq!(body, Some(value.to_string()));
    
    // Delete string
    let response = server.delete_admin(&format!("/redis/string/{}", key)).await?;
    assert_eq!(response.status(), 200);
    
    let body: bool = response.json().await?;
    assert!(body);
    
    // Verify deletion
    let response = server.get_admin(&format!("/redis/string/{}", key)).await?;
    assert_eq!(response.status(), 200);
    
    let body: Option<String> = response.json().await?;
    assert_eq!(body, None);
    
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
    let response = server.post_admin(&format!("/redis/string/{}", key), &set_payload).await?;
    assert_eq!(response.status(), 200);
    
    // Get string
    let response = server.get_admin(&format!("/redis/string/{}", key)).await?;
    assert_eq!(response.status(), 200);
    
    let body: Option<String> = response.json().await?;
    assert_eq!(body, Some(special_value.to_string()));
    
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
    let response = server.post_admin(&format!("/redis/string/{}", key), &set_payload).await?;
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
    let response = server.get_unauthenticated("/redis/admin/ping").await?;
    assert_eq!(response.status(), 401);
    
    // Test user endpoint without auth
    let response = server.get_unauthenticated("/redis/string/test").await?;
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
    let response = server.post_admin(&format!("/redis/hash/{}/{}", key, field), &set_payload).await?;
    assert_eq!(response.status(), 200);
    
    // Get hash field
    let response = server.get_admin(&format!("/redis/hash/{}/{}", key, field)).await?;
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
    let response = server.post_admin(&format!("/redis/set/{}", key), &add_payload).await?;
    assert_eq!(response.status(), 200);
    
    // Get set members
    let response = server.get_admin(&format!("/redis/set/{}/members", key)).await?;
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
    
    let response = server.client
        .get(&format!("{}/health", server.base_url))
        .send()
        .await?;
    
    assert_eq!(response.status(), 200);
    
    let body: Value = response.json().await?;
    assert_eq!(body["success"], true);
    assert!(body["data"].as_str().unwrap().contains("Server is running"));
    
    Ok(())
} 