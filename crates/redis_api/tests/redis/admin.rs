use crate::common::TestContext;
use crate::get_test_base_url;
use serde_json::Value;

#[tokio::test]
async fn test_admin_ping() {
    let mut ctx = TestContext::new(get_test_base_url().await);
    ctx.authenticate_admin().await.expect("Failed to authenticate admin");

    let res = ctx
        .get_with_admin_auth(&format!("{}/redis/admin/ping", ctx.base_url))
        .await
        .expect("Failed to send request");

    assert_eq!(res.status().as_u16(), 200);
    let body: String = res.json().await.unwrap();
    assert_eq!(body, "PONG");
}

#[tokio::test]
async fn test_admin_info() {
    let mut ctx = TestContext::new(get_test_base_url().await);
    ctx.authenticate_admin().await.expect("Failed to authenticate admin");

    let res = ctx
        .get_with_admin_auth(&format!("{}/redis/admin/info", ctx.base_url))
        .await
        .expect("Failed to send request");

    assert_eq!(res.status().as_u16(), 200);
    let body: String = res.json().await.unwrap();
    assert!(body.contains("redis_version"));
}

#[tokio::test]
async fn test_admin_dbsize() {
    let mut ctx = TestContext::new(get_test_base_url().await);
    ctx.authenticate_admin().await.expect("Failed to authenticate admin");

    let res = ctx
        .get_with_admin_auth(&format!("{}/redis/admin/dbsize", ctx.base_url))
        .await
        .expect("Failed to send request");

    assert_eq!(res.status().as_u16(), 200);
    let body: i64 = res.json().await.unwrap();
    assert!(body >= 0);
}

#[tokio::test]
async fn test_admin_health() {
    let mut ctx = TestContext::new(get_test_base_url().await);
    ctx.authenticate_admin().await.expect("Failed to authenticate admin");

    let res = ctx
        .get_with_admin_auth(&format!("{}/redis/admin/health", ctx.base_url))
        .await
        .expect("Failed to send request");

    assert_eq!(res.status().as_u16(), 200);
    let body: Value = res.json().await.unwrap();
    assert!(body["is_healthy"].as_bool().unwrap_or(false));
    assert!(body["ping_response"].as_str().unwrap_or("") == "PONG");
}

#[tokio::test]
async fn test_admin_status() {
    let mut ctx = TestContext::new(get_test_base_url().await);
    ctx.authenticate_admin().await.expect("Failed to authenticate admin");

    let res = ctx
        .get_with_admin_auth(&format!("{}/redis/admin/status", ctx.base_url))
        .await
        .expect("Failed to send request");

    assert_eq!(res.status().as_u16(), 200);
    let body: Value = res.json().await.unwrap();
    assert!(body["uptime_seconds"].as_i64().unwrap_or(0) >= 0);
    assert!(body["version"].as_str().is_some());
}

#[tokio::test]
async fn test_admin_memory_stats() {
    let mut ctx = TestContext::new(get_test_base_url().await);
    ctx.authenticate_admin().await.expect("Failed to authenticate admin");

    let res = ctx
        .get_with_admin_auth(&format!("{}/redis/admin/stats/memory", ctx.base_url))
        .await
        .expect("Failed to send request");

    assert_eq!(res.status().as_u16(), 200);
    let body: Value = res.json().await.unwrap();
    assert!(body.get("used_memory").is_some());
}

#[tokio::test]
async fn test_admin_config_all() {
    let mut ctx = TestContext::new(get_test_base_url().await);
    ctx.authenticate_admin().await.expect("Failed to authenticate admin");

    let res = ctx
        .get_with_admin_auth(&format!("{}/redis/admin/config/all", ctx.base_url))
        .await
        .expect("Failed to send request");

    assert_eq!(res.status().as_u16(), 200);
    let body: Value = res.json().await.unwrap();
    assert!(body.get("maxmemory").is_some() || body.get("timeout").is_some());
}

#[tokio::test]
async fn test_admin_flushdb() {
    let mut ctx = TestContext::new(get_test_base_url().await);
    ctx.authenticate_admin().await.expect("Failed to authenticate admin");

    let res = ctx
        .delete_with_admin_auth(&format!("{}/redis/admin/flushdb", ctx.base_url))
        .await
        .expect("Failed to send request");

    assert_eq!(res.status().as_u16(), 200);
}
