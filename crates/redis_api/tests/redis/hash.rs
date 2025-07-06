use crate::common::TestContext;
use crate::get_test_base_url;
use serde_json::json;

#[tokio::test]
async fn test_hash_set_and_get() {
    let mut ctx = TestContext::new(get_test_base_url().await);
    ctx.authenticate_admin()
        .await
        .expect("Failed to authenticate admin");

    let payload = json!({
        "field": "test_field",
        "value": "test_value"
    });
    let res = ctx
        .post_with_admin_auth(&format!("{}/redis/hash/test_hash", ctx.base_url), &payload)
        .await
        .expect("Failed to send request");

    assert!(res.status().is_success());

    let res = ctx
        .get_with_admin_auth(&format!("{}/redis/hash/test_hash/test_field", ctx.base_url))
        .await
        .expect("Failed to send request");

    assert!(res.status().is_success());
    let body: Option<String> = res.json().await.unwrap();
    assert_eq!(body, Some("test_value".to_string()));

    let res = ctx
        .get_with_admin_auth(&format!("{}/redis/hash/test_hash", ctx.base_url))
        .await
        .expect("Failed to send request");

    assert!(res.status().is_success());
    let body: serde_json::Value = res.json().await.unwrap();
    assert!(body.get("test_field").is_some());
    assert_eq!(body["test_field"], "test_value");
}

#[tokio::test]
async fn test_hash_delete() {
    let mut ctx = TestContext::new(get_test_base_url().await);
    ctx.authenticate_admin()
        .await
        .expect("Failed to authenticate admin");

    let payload = json!({
        "field": "delete_field",
        "value": "delete_value"
    });
    let res = ctx
        .post_with_admin_auth(
            &format!("{}/redis/hash/delete_hash", ctx.base_url),
            &payload,
        )
        .await
        .expect("Failed to send request");

    assert!(res.status().is_success());

    let res = ctx
        .get_with_admin_auth(&format!(
            "{}/redis/hash/delete_hash/delete_field",
            ctx.base_url
        ))
        .await
        .expect("Failed to send request");

    assert!(res.status().is_success());
    let body: Option<String> = res.json().await.unwrap();
    assert_eq!(body, Some("delete_value".to_string()));

    let res = ctx
        .delete_with_admin_auth(&format!(
            "{}/redis/hash/delete_hash/delete_field",
            ctx.base_url
        ))
        .await
        .expect("Failed to send request");

    assert!(res.status().is_success());
    let body: bool = res.json().await.unwrap();
    assert!(body);

    let res = ctx
        .get_with_admin_auth(&format!(
            "{}/redis/hash/delete_hash/delete_field",
            ctx.base_url
        ))
        .await
        .expect("Failed to send request");

    assert!(res.status().is_success());
    let body: Option<String> = res.json().await.unwrap();
    assert_eq!(body, None);
}
