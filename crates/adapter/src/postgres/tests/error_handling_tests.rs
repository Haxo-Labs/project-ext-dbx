//! PostgreSQL error handling and edge case tests

use uuid::Uuid;

use super::utils::{self, skip_if_no_postgres};
use dbx_core::{DataOperation, DataValue};

#[tokio::test]
async fn test_nonexistent_key_operations() {
    skip_if_no_postgres!();

    let backend = utils::create_test_backend().await.unwrap();
    let nonexistent_key = format!("test:nonexistent:{}", Uuid::new_v4());

    // GET nonexistent key
    let get_op = DataOperation::Get {
        key: nonexistent_key.clone(),
        fields: None,
    };
    let result = backend.execute_data(get_op).await.unwrap();
    assert!(result.is_success());
    assert_eq!(result.data, Some(DataValue::Null));

    // DELETE nonexistent key (should succeed)
    let delete_op = DataOperation::Delete {
        key: nonexistent_key.clone(),
        fields: None,
    };
    let result = backend.execute_data(delete_op).await.unwrap();
    assert!(result.is_success());

    // EXISTS nonexistent key
    let exists_op = DataOperation::Exists {
        key: nonexistent_key,
        fields: None,
    };
    let result = backend.execute_data(exists_op).await.unwrap();
    assert!(result.is_success());
    assert_eq!(result.data, Some(DataValue::Bool(false)));
}

#[tokio::test]
async fn test_invalid_operations() {
    skip_if_no_postgres!();

    let backend = utils::create_test_backend().await.unwrap();
    let test_key = format!("test:invalid:{}", Uuid::new_v4());

    // Set a string value
    let set_op = DataOperation::Set {
        key: test_key.clone(),
        value: DataValue::String("not_a_number".to_string()),
        ttl: None,
    };
    let result = backend.execute_data(set_op).await.unwrap();
    assert!(result.is_success());

    // Try to increment a string (should handle gracefully)
    let inc_op = DataOperation::Increment {
        key: test_key.clone(),
        amount: 1,
    };
    let result = backend.execute_data(inc_op).await;

    // The operation might fail or succeed depending on implementation
    // The important thing is that it doesn't panic
    match result {
        Ok(_) => {
            // Implementation successfully handled the type mismatch
        }
        Err(_) => {
            // Implementation returned an error, which is also acceptable
        }
    }

    // Cleanup
    let delete_op = DataOperation::Delete {
        key: test_key,
        fields: None,
    };
    let _ = backend.execute_data(delete_op).await;
}

#[tokio::test]
async fn test_large_value_handling() {
    skip_if_no_postgres!();

    let backend = utils::create_test_backend().await.unwrap();
    let test_key = format!("test:large:{}", Uuid::new_v4());

    // Create a large string (1MB)
    let large_value = "x".repeat(1024 * 1024);

    let set_op = DataOperation::Set {
        key: test_key.clone(),
        value: DataValue::String(large_value.clone()),
        ttl: None,
    };

    let result = backend.execute_data(set_op).await;

    match result {
        Ok(res) => {
            assert!(res.is_success());

            // Try to retrieve it
            let get_op = DataOperation::Get {
                key: test_key.clone(),
                fields: None,
            };
            let get_result = backend.execute_data(get_op).await.unwrap();
            assert!(get_result.is_success());
            assert_eq!(get_result.data, Some(DataValue::String(large_value)));
        }
        Err(_) => {
            // Large values might be rejected, which is acceptable
            println!("Large value was rejected by the backend");
        }
    }

    // Cleanup
    let delete_op = DataOperation::Delete {
        key: test_key,
        fields: None,
    };
    let _ = backend.execute_data(delete_op).await;
}

#[tokio::test]
async fn test_empty_and_special_keys() {
    skip_if_no_postgres!();

    let backend = utils::create_test_backend().await.unwrap();

    // Test keys with special characters
    let special_keys = vec![
        "test:key with spaces".to_string(),
        "test:key-with-dashes".to_string(),
        "test:key_with_underscores".to_string(),
        "test:key.with.dots".to_string(),
        "test:key:with:colons".to_string(),
        "test:UPPERCASE".to_string(),
        "test:123numbers".to_string(),
        "test:unicode_测试".to_string(),
        format!("test:very_long_key_{}", "x".repeat(100)),
    ];

    for key in &special_keys {
        let set_op = DataOperation::Set {
            key: key.clone(),
            value: DataValue::String(format!("value_for_{}", key)),
            ttl: None,
        };

        let result = backend.execute_data(set_op).await;

        match result {
            Ok(res) => {
                assert!(res.is_success(), "Failed to set key: {}", key);

                // Try to retrieve it
                let get_op = DataOperation::Get {
                    key: key.clone(),
                    fields: None,
                };
                let get_result = backend.execute_data(get_op).await.unwrap();
                assert!(get_result.is_success());

                // Cleanup
                let delete_op = DataOperation::Delete {
                    key: key.clone(),
                    fields: None,
                };
                let _ = backend.execute_data(delete_op).await;
            }
            Err(_) => {
                // Some special characters might be rejected, which is acceptable
                println!("Special key was rejected: {}", key);
            }
        }
    }
}

#[tokio::test]
async fn test_extreme_ttl_values() {
    skip_if_no_postgres!();

    let backend = utils::create_test_backend().await.unwrap();
    let base_key = format!("test:extreme_ttl:{}", Uuid::new_v4());

    // Test extreme TTL values
    let ttl_values = [
        1,          // Minimum
        86400,      // 1 day
        2147483647, // Max i32
    ];

    for (i, ttl) in ttl_values.iter().enumerate() {
        let key = format!("{}:{}", base_key, i);

        let set_op = DataOperation::Set {
            key: key.clone(),
            value: DataValue::String(format!("value_with_ttl_{}", ttl)),
            ttl: Some(*ttl),
        };

        let result = backend.execute_data(set_op).await;

        match result {
            Ok(res) => {
                assert!(res.is_success(), "Failed to set TTL: {}", ttl);

                // Cleanup
                let delete_op = DataOperation::Delete {
                    key: key.clone(),
                    fields: None,
                };
                let _ = backend.execute_data(delete_op).await;
            }
            Err(_) => {
                // Extreme TTL values might be rejected, which is acceptable
                println!("Extreme TTL was rejected: {}", ttl);
            }
        }
    }
}

#[tokio::test]
async fn test_malformed_data_handling() {
    skip_if_no_postgres!();

    let backend = utils::create_test_backend().await.unwrap();
    let test_key = format!("test:malformed:{}", Uuid::new_v4());

    // Test with various data types that might cause issues
    let test_values = [
        DataValue::String("".to_string()),           // Empty string
        DataValue::String("\0".to_string()),         // Null byte
        DataValue::String("\"quotes\"".to_string()), // Quoted string
        DataValue::String("'single quotes'".to_string()),
        DataValue::String("\\backslashes\\".to_string()),
        DataValue::String("{\"json\": \"like\"}".to_string()),
        DataValue::Float(f64::INFINITY),
        DataValue::Float(f64::NEG_INFINITY),
        DataValue::Float(f64::NAN),
        DataValue::Int(i64::MAX),
        DataValue::Int(i64::MIN),
    ];

    for (i, value) in test_values.iter().enumerate() {
        let key = format!("{}:{}", test_key, i);

        let set_op = DataOperation::Set {
            key: key.clone(),
            value: value.clone(),
            ttl: None,
        };

        let result = backend.execute_data(set_op).await;

        match result {
            Ok(res) => {
                if res.is_success() {
                    // If set succeeded, try to get it back
                    let get_op = DataOperation::Get {
                        key: key.clone(),
                        fields: None,
                    };
                    let get_result = backend.execute_data(get_op).await;

                    match get_result {
                        Ok(_) => {
                            // Successfully handled the data
                        }
                        Err(_) => {
                            println!("Get failed for value: {:?}", value);
                        }
                    }
                }

                // Cleanup
                let delete_op = DataOperation::Delete {
                    key: key.clone(),
                    fields: None,
                };
                let _ = backend.execute_data(delete_op).await;
            }
            Err(_) => {
                // Some malformed data might be rejected, which is acceptable
                println!("Malformed data was rejected: {:?}", value);
            }
        }
    }
}
