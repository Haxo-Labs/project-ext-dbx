use crate::common::TestContext;
use crate::get_test_base_url;
use serde_json::json;

#[tokio::test]
async fn test_set_add_and_members() {
    let mut ctx = TestContext::new(get_test_base_url().await);
    ctx.authenticate_admin()
        .await
        .expect("Failed to authenticate admin");

    let payload = json!({
        "members": ["member1", "member2", "member3"]
    });
    let res = ctx
        .post_with_admin_auth(&format!("{}/redis/set/test_set", ctx.base_url), &payload)
        .await
        .expect("Failed to send request");

    assert!(res.status().is_success());
    let body: i64 = res.json().await.unwrap();
    assert_eq!(body, 3);

    let res = ctx
        .get_with_admin_auth(&format!("{}/redis/set/test_set", ctx.base_url))
        .await
        .expect("Failed to send request");

    assert!(res.status().is_success());
    let body: Vec<String> = res.json().await.unwrap();
    assert_eq!(body.len(), 3);
    assert!(body.contains(&"member1".to_string()));
    assert!(body.contains(&"member2".to_string()));
    assert!(body.contains(&"member3".to_string()));
}

#[tokio::test]
async fn test_set_remove() {
    let mut ctx = TestContext::new(get_test_base_url().await);
    ctx.authenticate_admin()
        .await
        .expect("Failed to authenticate admin");

    let payload = json!({
        "members": ["member1", "member2", "member3"]
    });
    let res = ctx
        .post_with_admin_auth(&format!("{}/redis/set/remove_set", ctx.base_url), &payload)
        .await
        .expect("Failed to send request");

    assert!(res.status().is_success());

    let res = ctx
        .get_with_admin_auth(&format!("{}/redis/set/remove_set", ctx.base_url))
        .await
        .expect("Failed to send request");

    assert!(res.status().is_success());
    let body: Vec<String> = res.json().await.unwrap();
    assert_eq!(body.len(), 3);

    let res = ctx
        .delete_with_admin_auth(&format!("{}/redis/set/remove_set", ctx.base_url))
        .await
        .expect("Failed to send request");

    assert!(res.status().is_success());
    let body: i64 = res.json().await.unwrap();
    assert!(body >= 0);

    let res = ctx
        .get_with_admin_auth(&format!("{}/redis/set/remove_set", ctx.base_url))
        .await
        .expect("Failed to send request");

    assert!(res.status().is_success());
    let body: Vec<String> = res.json().await.unwrap();
    assert_eq!(body.len(), 0);
}
