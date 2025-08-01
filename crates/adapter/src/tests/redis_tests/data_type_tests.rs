//! Redis backend data type preservation tests

use crate::redis::backend::RedisBackend;
use dbx_core::{DataOperation, DataValue, UniversalBackend};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

async fn create_test_backend() -> Arc<RedisBackend> {
    let redis_url = std::env::var("TEST_REDIS_URL").unwrap_or("redis://localhost:6379".to_string());
    let backend = RedisBackend::from_url(&redis_url, "test_redis".to_string(), 5)
        .await
        .expect("Failed to create Redis backend");
    Arc::new(backend)
}

macro_rules! skip_if_no_redis {
    () => {
        let redis_url =
            std::env::var("TEST_REDIS_URL").unwrap_or("redis://localhost:6379".to_string());
        if redis::Client::open(redis_url.as_str()).is_err() {
            println!("Skipping test: Redis not available");
            return;
        }
    };
}

#[tokio::test]
async fn test_boolean_integer_preservation() {
    skip_if_no_redis!();

    let backend = create_test_backend().await;

    let test_cases = vec![
        ("test:int:0", DataValue::Int(0)),
        ("test:int:1", DataValue::Int(1)),
        ("test:bool:true", DataValue::Bool(true)),
        ("test:bool:false", DataValue::Bool(false)),
    ];

    for (key, expected_value) in test_cases {
        let test_key = format!("{}:{}", key, Uuid::new_v4());

        let set_op = DataOperation::Set {
            key: test_key.clone(),
            value: expected_value.clone(),
            ttl: None,
        };

        let result = backend.execute_data(set_op).await.unwrap();
        assert!(result.is_success());

        let get_op = DataOperation::Get {
            key: test_key.clone(),
            fields: None,
        };

        let result = backend.execute_data(get_op).await.unwrap();
        assert!(result.is_success());

        match (&expected_value, &result.data) {
            (DataValue::Int(expected), Some(DataValue::Int(actual))) => {
                assert_eq!(expected, actual);
                assert!(matches!(result.data, Some(DataValue::Int(_))));
            }
            (DataValue::Bool(expected), Some(DataValue::Bool(actual))) => {
                assert_eq!(expected, actual);
                assert!(matches!(result.data, Some(DataValue::Bool(_))));
            }
            _ => {
                panic!(
                    "Type preservation failed! Key: {}, Expected: {:?}, Got: {:?}",
                    test_key, expected_value, result.data
                );
            }
        }

        let delete_op = DataOperation::Delete {
            key: test_key,
            fields: None,
        };
        let _ = backend.execute_data(delete_op).await;
    }
}

#[tokio::test]
async fn test_all_data_type_preservation() {
    skip_if_no_redis!();

    let backend = create_test_backend().await;

    let test_cases = vec![
        ("null", DataValue::Null),
        ("bool_true", DataValue::Bool(true)),
        ("bool_false", DataValue::Bool(false)),
        ("int_positive", DataValue::Int(42)),
        ("int_negative", DataValue::Int(-42)),
        ("int_zero", DataValue::Int(0)),
        ("int_one", DataValue::Int(1)),
        ("float_positive", DataValue::Float(3.14)),
        ("float_negative", DataValue::Float(-2.71)),
        ("string_empty", DataValue::String("".to_string())),
        (
            "string_text",
            DataValue::String("Hello, World!".to_string()),
        ),
        ("string_numbers", DataValue::String("123".to_string())),
        ("string_booleans", DataValue::String("true".to_string())),
        ("bytes", DataValue::Bytes(vec![1, 2, 3, 4, 5])),
        (
            "array",
            DataValue::Array(vec![
                DataValue::Int(1),
                DataValue::Bool(true),
                DataValue::String("test".to_string()),
            ]),
        ),
        (
            "object",
            DataValue::Object({
                let mut obj = HashMap::new();
                obj.insert("number".to_string(), DataValue::Int(42));
                obj.insert("flag".to_string(), DataValue::Bool(false));
                obj.insert("text".to_string(), DataValue::String("value".to_string()));
                obj
            }),
        ),
    ];

    for (key_suffix, expected_value) in test_cases {
        let test_key = format!("test:type:{}:{}", key_suffix, Uuid::new_v4());

        let set_op = DataOperation::Set {
            key: test_key.clone(),
            value: expected_value.clone(),
            ttl: None,
        };

        let result = backend.execute_data(set_op).await.unwrap();
        assert!(
            result.is_success(),
            "Set operation failed for key: {}",
            test_key
        );

        let get_op = DataOperation::Get {
            key: test_key.clone(),
            fields: None,
        };

        let result = backend.execute_data(get_op).await.unwrap();
        assert!(
            result.is_success(),
            "Get operation failed for key: {}",
            test_key
        );

        assert_eq!(
            result.data,
            Some(expected_value.clone()),
            "Type preservation failed for key: {}",
            test_key
        );

        match &expected_value {
            DataValue::Int(_) => assert!(matches!(result.data, Some(DataValue::Int(_)))),
            DataValue::Bool(_) => assert!(matches!(result.data, Some(DataValue::Bool(_)))),
            DataValue::Float(_) => assert!(matches!(result.data, Some(DataValue::Float(_)))),
            DataValue::String(_) => assert!(matches!(result.data, Some(DataValue::String(_)))),
            DataValue::Bytes(_) => assert!(matches!(result.data, Some(DataValue::Bytes(_)))),
            DataValue::Array(_) => assert!(matches!(result.data, Some(DataValue::Array(_)))),
            DataValue::Object(_) => assert!(matches!(result.data, Some(DataValue::Object(_)))),
            DataValue::Null => assert!(matches!(result.data, Some(DataValue::Null))),
        }

        let delete_op = DataOperation::Delete {
            key: test_key,
            fields: None,
        };
        let _ = backend.execute_data(delete_op).await;
    }
}
