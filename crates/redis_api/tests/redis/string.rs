use crate::common::{
    assert_status_ok, batch_get_strings, batch_set_strings, cleanup_test_keys, create_http_client,
    delete_string, generate_large_value, generate_special_chars_value, generate_test_key,
    generate_test_value, get_string, set_string, ttl_delay,
    get_auth_header, REDIS_BASE_URL,
};
use serde_json::json;
use tokio::time::sleep;

#[tokio::test]
async fn test_set_get_string_basic() -> Result<(), anyhow::Error> {
    let client = create_http_client();
    let key = generate_test_key("basic_test", None);
    let value = generate_test_value("basic_value", None);

    // Set string
    set_string(&client, REDIS_BASE_URL, &key, &value).await?;

    // Get string
    let result = get_string(&client, REDIS_BASE_URL, &key).await?;
    assert_eq!(result, Some(value.clone()));

    // Cleanup
    cleanup_test_keys(&client, REDIS_BASE_URL, &[&key]).await;
    Ok(())
}

#[tokio::test]
async fn test_set_get_string_with_special_chars() -> Result<(), anyhow::Error> {
    let client = create_http_client();
    let key = generate_test_key("special_chars_test", None);
    let value = generate_special_chars_value();

    // Set string with special characters
    set_string(&client, REDIS_BASE_URL, &key, &value).await?;

    // Get string
    let result = get_string(&client, REDIS_BASE_URL, &key).await?;
    assert_eq!(result, Some(value));

    // Cleanup
    cleanup_test_keys(&client, REDIS_BASE_URL, &[&key]).await;
    Ok(())
}

#[tokio::test]
async fn test_set_get_large_string() -> Result<(), anyhow::Error> {
    let client = create_http_client();
    let key = generate_test_key("large_string_test", None);
    let value = generate_large_value(1000);

    // Set large string
    set_string(&client, REDIS_BASE_URL, &key, &value).await?;

    // Get string
    let result = get_string(&client, REDIS_BASE_URL, &key).await?;
    assert_eq!(result, Some(value));

    // Cleanup
    cleanup_test_keys(&client, REDIS_BASE_URL, &[&key]).await;
    Ok(())
}

#[tokio::test]
async fn test_get_nonexistent_string() -> Result<(), anyhow::Error> {
    let client = create_http_client();
    let key = generate_test_key("nonexistent_test", None);

    // Get nonexistent string
    let result = get_string(&client, REDIS_BASE_URL, &key).await?;
    assert_eq!(result, None);

    Ok(())
}

#[tokio::test]
async fn test_delete_string() -> Result<(), anyhow::Error> {
    let client = create_http_client();
    let key = generate_test_key("delete_test", None);
    let value = generate_test_value("delete_value", None);

    // Set string
    set_string(&client, REDIS_BASE_URL, &key, &value).await?;

    // Verify it exists
    let result = get_string(&client, REDIS_BASE_URL, &key).await?;
    assert_eq!(result, Some(value));

    // Delete string
    let deleted = delete_string(&client, REDIS_BASE_URL, &key).await?;
    assert!(deleted, "String should be deleted");

    // Verify it's gone
    let result = get_string(&client, REDIS_BASE_URL, &key).await?;
    assert_eq!(result, None);

    Ok(())
}

#[tokio::test]
async fn test_delete_nonexistent_string() -> Result<(), anyhow::Error> {
    let client = create_http_client();
    let key = generate_test_key("delete_nonexistent_test", None);

    // Delete nonexistent string
    let deleted = delete_string(&client, REDIS_BASE_URL, &key).await?;
    assert!(!deleted, "Nonexistent string should not be deleted");

    Ok(())
}

#[tokio::test]
async fn test_string_overwrite() -> Result<(), anyhow::Error> {
    let client = create_http_client();
    let key = generate_test_key("overwrite_test", None);
    let value1 = generate_test_value("original_value", None);
    let value2 = generate_test_value("new_value", None);

    // Set original string
    set_string(&client, REDIS_BASE_URL, &key, &value1).await?;

    // Verify original value
    let result = get_string(&client, REDIS_BASE_URL, &key).await?;
    assert_eq!(result, Some(value1));

    // Overwrite with new value
    set_string(&client, REDIS_BASE_URL, &key, &value2).await?;

    // Verify new value
    let result = get_string(&client, REDIS_BASE_URL, &key).await?;
    assert_eq!(result, Some(value2));

    // Cleanup
    cleanup_test_keys(&client, REDIS_BASE_URL, &[&key]).await;
    Ok(())
}

#[tokio::test]
async fn test_concurrent_string_operations() -> Result<(), anyhow::Error> {
    let client = create_http_client();
    let base_key = "concurrent_test";
    let num_operations = 10;

    // Create concurrent set operations
    let mut set_handles = Vec::new();
    for i in 0..num_operations {
        let client_clone = client.clone();
        let key = generate_test_key(base_key, Some(i));
        let value = generate_test_value("concurrent_value", Some(i));

        let handle = tokio::spawn(async move {
            set_string(&client_clone, REDIS_BASE_URL, &key, &value)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to set string: {}", e))
        });
        set_handles.push(handle);
    }

    // Wait for all operations to complete
    for handle in set_handles {
        handle.await??;
    }

    // Verify all values were set correctly
    for i in 0..num_operations {
        let key = generate_test_key(base_key, Some(i));
        let expected_value = generate_test_value("concurrent_value", Some(i));
        let result = get_string(&client, REDIS_BASE_URL, &key).await?;
        assert_eq!(result, Some(expected_value));
    }

    // Cleanup
    let cleanup_keys: Vec<String> = (0..num_operations)
        .map(|i| generate_test_key(base_key, Some(i)))
        .collect();
    let cleanup_refs: Vec<&str> = cleanup_keys.iter().map(|s| s.as_str()).collect();
    cleanup_test_keys(&client, REDIS_BASE_URL, &cleanup_refs).await;

    Ok(())
}

#[tokio::test]
async fn test_string_error_handling() -> Result<(), anyhow::Error> {
    let client = create_http_client();
    let auth_header = get_auth_header().await?;

    // Test with invalid endpoint
    let res = client
        .post(&format!("{}/redis/string/invalid/endpoint", REDIS_BASE_URL))
        .header("Authorization", auth_header)
        .json(&json!({ "value": "test" }))
        .send()
        .await?;

    // Should return 404 Not Found
    assert_eq!(res.status(), 404);

    Ok(())
}

#[tokio::test]
async fn test_batch_string_operations() -> Result<(), anyhow::Error> {
    let client = create_http_client();
    let base_key = "batch_test";
    let num_operations = 5;

    // Prepare batch operations with owned strings
    let mut keys = Vec::new();
    let mut values = Vec::new();
    for i in 0..num_operations {
        keys.push(generate_test_key(base_key, Some(i)));
        values.push(generate_test_value("batch_value", Some(i)));
    }

    // Create operations with string references
    let operations: Vec<(&str, &str)> = keys
        .iter()
        .zip(values.iter())
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    // Batch set
    batch_set_strings(&client, REDIS_BASE_URL, operations).await?;

    // Batch get
    let results = batch_get_strings(&client, REDIS_BASE_URL, &keys).await?;

    // Verify results
    for (i, result) in results.iter().enumerate() {
        let expected_value = generate_test_value("batch_value", Some(i));
        assert_eq!(result, &Some(expected_value));
    }

    // Cleanup
    let cleanup_refs: Vec<&str> = keys.iter().map(|s| s.as_str()).collect();
    cleanup_test_keys(&client, REDIS_BASE_URL, &cleanup_refs).await;

    Ok(())
}

#[tokio::test]
async fn test_batch_get_patterns() -> Result<(), anyhow::Error> {
    let client = create_http_client();
    let base_key = "pattern_test";
    let num_keys = 3;

    // Set up test data
    for i in 0..num_keys {
        let key = generate_test_key(base_key, Some(i));
        let value = generate_test_value("pattern_value", Some(i));
        set_string(&client, REDIS_BASE_URL, &key, &value).await?;
    }

    // Test batch get with existing and non-existing keys
    let keys = vec![
        generate_test_key(base_key, Some(0)),
        generate_test_key("nonexistent", None),
        generate_test_key(base_key, Some(1)),
        generate_test_key(base_key, Some(2)),
    ];

    let results = batch_get_strings(&client, REDIS_BASE_URL, &keys).await?;

    // Verify results
    assert_eq!(results.len(), 4);
    assert_eq!(results[0], Some(generate_test_value("pattern_value", Some(0))));
    assert_eq!(results[1], None); // nonexistent key
    assert_eq!(results[2], Some(generate_test_value("pattern_value", Some(1))));
    assert_eq!(results[3], Some(generate_test_value("pattern_value", Some(2))));

    // Cleanup
    let cleanup_keys: Vec<String> = (0..num_keys)
        .map(|i| generate_test_key(base_key, Some(i)))
        .collect();
    let cleanup_refs: Vec<&str> = cleanup_keys.iter().map(|s| s.as_str()).collect();
    cleanup_test_keys(&client, REDIS_BASE_URL, &cleanup_refs).await;

    Ok(())
}

#[tokio::test]
async fn test_string_operations_with_ttl() -> Result<(), anyhow::Error> {
    let client = create_http_client();
    let key = generate_test_key("ttl_test", None);
    let value = generate_test_value("ttl_value", None);
    let auth_header = get_auth_header().await?;

    // Set string with TTL
    let res = client
        .post(&format!("{}/redis/string/{}", REDIS_BASE_URL, key))
        .header("Authorization", auth_header.clone())
        .json(&json!({ "value": value, "ttl": 1 }))
        .send()
        .await?;

    assert_status_ok(res.status().as_u16());

    // Verify it exists immediately
    let result = get_string(&client, REDIS_BASE_URL, &key).await?;
    assert_eq!(result, Some(value));

    // Wait for TTL to expire
    sleep(ttl_delay()).await;

    // Verify it's expired
    let result = get_string(&client, REDIS_BASE_URL, &key).await?;
    assert_eq!(result, None);

    Ok(())
}
