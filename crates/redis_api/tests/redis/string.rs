use crate::common::TestContext;
use crate::get_test_base_url;
use serde_json::json;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn test_set_get_string_basic() {
    let mut ctx = TestContext::new(get_test_base_url().await);
    ctx.authenticate_admin()
        .await
        .expect("Failed to authenticate admin");

    let payload = json!({ "value": "test_value" });
    let res = ctx
        .post_with_admin_auth(&format!("{}/redis/string/test_key", ctx.base_url), &payload)
        .await
        .expect("Failed to send request");

    assert!(res.status().is_success());

    let res = ctx
        .get_with_admin_auth(&format!("{}/redis/string/test_key", ctx.base_url))
        .await
        .expect("Failed to send request");

    assert!(res.status().is_success());
    let body: Option<String> = res.json().await.unwrap();
    assert_eq!(body, Some("test_value".to_string()));
}

#[tokio::test]
async fn test_set_get_string_with_special_chars() {
    let mut ctx = TestContext::new(get_test_base_url().await);
    ctx.authenticate_admin()
        .await
        .expect("Failed to authenticate admin");

    let special_value = "!@#$%^&*()_+-=[]{}|;':\",./<>?";
    let payload = json!({ "value": special_value });
    let res = ctx
        .post_with_admin_auth(
            &format!("{}/redis/string/special_key", ctx.base_url),
            &payload,
        )
        .await
        .expect("Failed to send request");

    assert!(res.status().is_success());

    let res = ctx
        .get_with_admin_auth(&format!("{}/redis/string/special_key", ctx.base_url))
        .await
        .expect("Failed to send request");

    assert!(res.status().is_success());
    let body: Option<String> = res.json().await.unwrap();
    assert_eq!(body, Some(special_value.to_string()));
}

#[tokio::test]
async fn test_get_nonexistent_string() {
    let mut ctx = TestContext::new(get_test_base_url().await);
    ctx.authenticate_admin()
        .await
        .expect("Failed to authenticate admin");

    let res = ctx
        .get_with_admin_auth(&format!("{}/redis/string/nonexistent_key", ctx.base_url))
        .await
        .expect("Failed to send request");

    assert!(res.status().is_success());
    let body: Option<String> = res.json().await.unwrap();
    assert_eq!(body, None);
}

#[tokio::test]
async fn test_set_get_large_string() {
    let mut ctx = TestContext::new(get_test_base_url().await);
    ctx.authenticate_admin()
        .await
        .expect("Failed to authenticate admin");

    let large_value = "x".repeat(10000);
    let payload = json!({ "value": large_value });
    let res = ctx
        .post_with_admin_auth(
            &format!("{}/redis/string/large_key", ctx.base_url),
            &payload,
        )
        .await
        .expect("Failed to send request");

    assert!(res.status().is_success());

    let res = ctx
        .get_with_admin_auth(&format!("{}/redis/string/large_key", ctx.base_url))
        .await
        .expect("Failed to send request");

    assert!(res.status().is_success());
    let body: Option<String> = res.json().await.unwrap();
    assert_eq!(body, Some(large_value));
}

#[tokio::test]
async fn test_string_overwrite() {
    let mut ctx = TestContext::new(get_test_base_url().await);
    ctx.authenticate_admin()
        .await
        .expect("Failed to authenticate admin");

    let payload1 = json!({ "value": "original_value" });
    let res = ctx
        .post_with_admin_auth(
            &format!("{}/redis/string/overwrite_key", ctx.base_url),
            &payload1,
        )
        .await
        .expect("Failed to send request");

    assert!(res.status().is_success());

    let payload2 = json!({ "value": "new_value" });
    let res = ctx
        .post_with_admin_auth(
            &format!("{}/redis/string/overwrite_key", ctx.base_url),
            &payload2,
        )
        .await
        .expect("Failed to send request");

    assert!(res.status().is_success());

    let res = ctx
        .get_with_admin_auth(&format!("{}/redis/string/overwrite_key", ctx.base_url))
        .await
        .expect("Failed to send request");

    assert!(res.status().is_success());
    let body: Option<String> = res.json().await.unwrap();
    assert_eq!(body, Some("new_value".to_string()));
}

#[tokio::test]
async fn test_delete_string() {
    let mut ctx = TestContext::new(get_test_base_url().await);
    ctx.authenticate_admin()
        .await
        .expect("Failed to authenticate admin");

    let payload = json!({ "value": "to_be_deleted" });
    let res = ctx
        .post_with_admin_auth(
            &format!("{}/redis/string/delete_key", ctx.base_url),
            &payload,
        )
        .await
        .expect("Failed to send request");

    assert!(res.status().is_success());

    let res = ctx
        .delete_with_admin_auth(&format!("{}/redis/string/delete_key", ctx.base_url))
        .await
        .expect("Failed to send request");

    assert!(res.status().is_success());
    let body: bool = res.json().await.unwrap();
    assert!(body);

    let res = ctx
        .get_with_admin_auth(&format!("{}/redis/string/delete_key", ctx.base_url))
        .await
        .expect("Failed to send request");

    assert!(res.status().is_success());
    let body: Option<String> = res.json().await.unwrap();
    assert_eq!(body, None);
}

#[tokio::test]
async fn test_delete_nonexistent_string() {
    let mut ctx = TestContext::new(get_test_base_url().await);
    ctx.authenticate_admin()
        .await
        .expect("Failed to authenticate admin");

    let res = ctx
        .delete_with_admin_auth(&format!(
            "{}/redis/string/nonexistent_delete_key",
            ctx.base_url
        ))
        .await
        .expect("Failed to send request");

    assert!(res.status().is_success());
    let body: bool = res.json().await.unwrap();
    assert!(!body);
}

#[tokio::test]
async fn test_string_operations_with_ttl() {
    let mut ctx = TestContext::new(get_test_base_url().await);
    ctx.authenticate_admin()
        .await
        .expect("Failed to authenticate admin");

    let payload = json!({ "value": "ttl_value", "ttl": 2 });
    let res = ctx
        .post_with_admin_auth(&format!("{}/redis/string/ttl_key", ctx.base_url), &payload)
        .await
        .expect("Failed to send request");

    assert!(res.status().is_success());

    let res = ctx
        .get_with_admin_auth(&format!("{}/redis/string/ttl_key", ctx.base_url))
        .await
        .expect("Failed to send request");

    assert!(res.status().is_success());
    let body: Option<String> = res.json().await.unwrap();
    assert_eq!(body, Some("ttl_value".to_string()));

    sleep(Duration::from_secs(3)).await;

    let res = ctx
        .get_with_admin_auth(&format!("{}/redis/string/ttl_key", ctx.base_url))
        .await
        .expect("Failed to send request");

    assert!(res.status().is_success());
    let body: Option<String> = res.json().await.unwrap();
    assert_eq!(body, None);
}

#[tokio::test]
async fn test_batch_string_operations() {
    let mut ctx = TestContext::new(get_test_base_url().await);
    ctx.authenticate_admin()
        .await
        .expect("Failed to authenticate admin");

    let batch_payload = json!({
        "operations": [
            { "key": "batch_key1", "value": "batch_value1" },
            { "key": "batch_key2", "value": "batch_value2" },
            { "key": "batch_key3", "value": "batch_value3" }
        ]
    });
    let res = ctx
        .post_with_admin_auth(
            &format!("{}/redis/string/batch/set", ctx.base_url),
            &batch_payload,
        )
        .await
        .expect("Failed to send request");

    assert!(res.status().is_success());

    let get_payload = json!({
        "keys": ["batch_key1", "batch_key2", "batch_key3"]
    });
    let res = ctx
        .post_with_admin_auth(
            &format!("{}/redis/string/batch/get", ctx.base_url),
            &get_payload,
        )
        .await
        .expect("Failed to send request");

    assert!(res.status().is_success());
    let body: Vec<Option<String>> = res.json().await.unwrap();
    assert_eq!(body.len(), 3);
    assert_eq!(body[0], Some("batch_value1".to_string()));
    assert_eq!(body[1], Some("batch_value2".to_string()));
    assert_eq!(body[2], Some("batch_value3".to_string()));
}

#[tokio::test]
async fn test_batch_get_patterns() {
    let mut ctx = TestContext::new(get_test_base_url().await);
    ctx.authenticate_admin()
        .await
        .expect("Failed to authenticate admin");

    let batch_payload = json!({
        "operations": [
            { "key": "pattern_key1", "value": "pattern_value1" },
            { "key": "pattern_key2", "value": "pattern_value2" },
            { "key": "other_key", "value": "other_value" }
        ]
    });
    let res = ctx
        .post_with_admin_auth(
            &format!("{}/redis/string/batch/set", ctx.base_url),
            &batch_payload,
        )
        .await
        .expect("Failed to send request");

    assert!(res.status().is_success());

    let pattern_payload = json!({
        "pattern": "pattern_key*"
    });
    let res = ctx
        .post_with_admin_auth(
            &format!("{}/redis/string/batch/get/pattern", ctx.base_url),
            &pattern_payload,
        )
        .await
        .expect("Failed to send request");

    assert!(res.status().is_success());
    let body: Vec<(String, Option<String>)> = res.json().await.unwrap();
    assert!(body.len() >= 2);
    assert!(body.iter().any(|(key, _)| key == "pattern_key1"));
    assert!(body.iter().any(|(key, _)| key == "pattern_key2"));
}

#[tokio::test]
async fn test_concurrent_string_operations() {
    let mut ctx = TestContext::new(get_test_base_url().await);
    ctx.authenticate_admin()
        .await
        .expect("Failed to authenticate admin");

    let mut tasks = Vec::new();
    for i in 0..5 {
        let ctx_clone = ctx.clone();
        let task = tokio::spawn(async move {
            let payload = json!({ "value": format!("concurrent_value_{}", i) });
            let res = ctx_clone
                .post_with_admin_auth(
                    &format!("{}/redis/string/concurrent_key_{}", ctx_clone.base_url, i),
                    &payload,
                )
                .await
                .expect("Failed to send request");

            assert!(res.status().is_success());
        });
        tasks.push(task);
    }

    for task in tasks {
        task.await.unwrap();
    }

    for i in 0..5 {
        let res = ctx
            .get_with_admin_auth(&format!(
                "{}/redis/string/concurrent_key_{}",
                ctx.base_url, i
            ))
            .await
            .expect("Failed to send request");

        assert!(res.status().is_success());
        let body: Option<String> = res.json().await.unwrap();
        assert_eq!(body, Some(format!("concurrent_value_{}", i)));
    }
}

#[tokio::test]
async fn test_string_error_handling() {
    let mut ctx = TestContext::new(get_test_base_url().await);
    ctx.authenticate_admin()
        .await
        .expect("Failed to authenticate admin");

    let invalid_payload = json!({ "invalid_field": "value" });
    let res = ctx
        .post_with_admin_auth(
            &format!("{}/redis/string/error_key", ctx.base_url),
            &invalid_payload,
        )
        .await
        .expect("Failed to send request");

    assert!(res.status().is_client_error());
}
