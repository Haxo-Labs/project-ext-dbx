//! PostgreSQL data operation tests (CRUD)

use std::collections::HashMap;
use uuid::Uuid;

use super::utils::{self, skip_if_no_postgres};
use dbx_core::{DataOperation, DataValue};

#[tokio::test]
async fn test_basic_crud_operations() {
    skip_if_no_postgres!();

    let backend = utils::create_test_backend().await.unwrap();
    let test_key = format!("test:crud:{}", Uuid::new_v4());

    // Test SET
    let set_op = DataOperation::Set {
        key: test_key.clone(),
        value: DataValue::String("test_value".to_string()),
        ttl: None,
    };
    let result = backend.execute_data(set_op).await.unwrap();
    assert!(result.is_success());

    // Test GET
    let get_op = DataOperation::Get {
        key: test_key.clone(),
        fields: None,
    };
    let result = backend.execute_data(get_op).await.unwrap();
    assert!(result.is_success());
    assert_eq!(
        result.data,
        Some(DataValue::String("test_value".to_string()))
    );

    // Test EXISTS
    let exists_op = DataOperation::Exists {
        key: test_key.clone(),
        fields: None,
    };
    let result = backend.execute_data(exists_op).await.unwrap();
    assert!(result.is_success());
    assert_eq!(result.data, Some(DataValue::Bool(true)));

    // Test DELETE
    let delete_op = DataOperation::Delete {
        key: test_key.clone(),
        fields: None,
    };
    let result = backend.execute_data(delete_op).await.unwrap();
    assert!(result.is_success());

    // Verify deletion
    let get_after_delete = DataOperation::Get {
        key: test_key,
        fields: None,
    };
    let result = backend.execute_data(get_after_delete).await.unwrap();
    assert!(result.is_success());
    assert_eq!(result.data, Some(DataValue::Null));
}

#[tokio::test]
async fn test_data_type_operations() {
    skip_if_no_postgres!();

    let backend = utils::create_test_backend().await.unwrap();
    let test_data = utils::generate_test_data();

    // Test setting all data types
    for (key, value) in &test_data {
        let set_op = DataOperation::Set {
            key: key.clone(),
            value: value.clone(),
            ttl: None,
        };
        let result = backend.execute_data(set_op).await.unwrap();
        assert!(result.is_success(), "Failed to set {}: {:?}", key, value);
    }

    // Test getting all data types
    for (key, expected_value) in &test_data {
        let get_op = DataOperation::Get {
            key: key.clone(),
            fields: None,
        };
        let result = backend.execute_data(get_op).await.unwrap();
        assert!(result.is_success(), "Failed to get {}", key);
        assert_eq!(
            result.data,
            Some(expected_value.clone()),
            "Mismatch for {}",
            key
        );
    }

    // Cleanup
    utils::cleanup_test_data(backend.as_ref(), "test").await;
}

#[tokio::test]
async fn test_numeric_operations() {
    skip_if_no_postgres!();

    let backend = utils::create_test_backend().await.unwrap();
    let test_key = format!("test:numeric:{}", Uuid::new_v4());

    // Set initial value
    let set_op = DataOperation::Set {
        key: test_key.clone(),
        value: DataValue::Int(10),
        ttl: None,
    };
    let result = backend.execute_data(set_op).await.unwrap();
    assert!(result.is_success());

    // Test increment
    let inc_op = DataOperation::Increment {
        key: test_key.clone(),
        amount: 5,
    };
    let result = backend.execute_data(inc_op).await.unwrap();
    assert!(result.is_success());
    assert_eq!(result.data, Some(DataValue::Int(15)));

    // Test decrement
    let dec_op = DataOperation::Decrement {
        key: test_key.clone(),
        amount: 3,
    };
    let result = backend.execute_data(dec_op).await.unwrap();
    assert!(result.is_success());
    assert_eq!(result.data, Some(DataValue::Int(12)));

    // Cleanup
    let delete_op = DataOperation::Delete {
        key: test_key,
        fields: None,
    };
    let _ = backend.execute_data(delete_op).await;
}

#[tokio::test]
async fn test_string_operations() {
    skip_if_no_postgres!();

    let backend = utils::create_test_backend().await.unwrap();
    let test_key = format!("test:string:{}", Uuid::new_v4());

    // Set initial string
    let set_op = DataOperation::Set {
        key: test_key.clone(),
        value: DataValue::String("Hello".to_string()),
        ttl: None,
    };
    let result = backend.execute_data(set_op).await.unwrap();
    assert!(result.is_success());

    // Test append
    let append_op = DataOperation::Append {
        key: test_key.clone(),
        value: " World".to_string(),
    };
    let result = backend.execute_data(append_op).await.unwrap();
    assert!(result.is_success());

    // Verify appended string
    let get_op = DataOperation::Get {
        key: test_key.clone(),
        fields: None,
    };
    let result = backend.execute_data(get_op).await.unwrap();
    assert!(result.is_success());
    assert_eq!(
        result.data,
        Some(DataValue::String("Hello World".to_string()))
    );

    // Test length
    let length_op = DataOperation::Length {
        key: test_key.clone(),
    };
    let result = backend.execute_data(length_op).await.unwrap();
    assert!(result.is_success());
    assert_eq!(result.data, Some(DataValue::Int(11))); // "Hello World".len()

    // Cleanup
    let delete_op = DataOperation::Delete {
        key: test_key,
        fields: None,
    };
    let _ = backend.execute_data(delete_op).await;
}

#[tokio::test]
async fn test_update_operations() {
    skip_if_no_postgres!();

    let backend = utils::create_test_backend().await.unwrap();
    let test_key = format!("test:update:{}", Uuid::new_v4());

    // Set initial object
    let mut initial_object = HashMap::new();
    initial_object.insert("name".to_string(), DataValue::String("John".to_string()));
    initial_object.insert("age".to_string(), DataValue::Int(30));

    let set_op = DataOperation::Set {
        key: test_key.clone(),
        value: DataValue::Object(initial_object),
        ttl: None,
    };
    let result = backend.execute_data(set_op).await.unwrap();
    assert!(result.is_success());

    // Update specific fields
    let mut update_fields = HashMap::new();
    update_fields.insert("age".to_string(), DataValue::Int(31));
    update_fields.insert(
        "city".to_string(),
        DataValue::String("New York".to_string()),
    );

    let update_op = DataOperation::Update {
        key: test_key.clone(),
        fields: update_fields,
        ttl: None,
    };
    let result = backend.execute_data(update_op).await.unwrap();
    assert!(result.is_success());

    // Verify updated object
    let get_op = DataOperation::Get {
        key: test_key.clone(),
        fields: None,
    };
    let result = backend.execute_data(get_op).await.unwrap();
    assert!(result.is_success());

    if let Some(DataValue::Object(obj)) = result.data {
        assert_eq!(
            obj.get("name"),
            Some(&DataValue::String("John".to_string()))
        );
        assert_eq!(obj.get("age"), Some(&DataValue::Int(31)));
        assert_eq!(
            obj.get("city"),
            Some(&DataValue::String("New York".to_string()))
        );
    } else {
        panic!("Expected object data");
    }

    // Cleanup
    let delete_op = DataOperation::Delete {
        key: test_key,
        fields: None,
    };
    let _ = backend.execute_data(delete_op).await;
}

#[tokio::test]
async fn test_batch_operations() {
    skip_if_no_postgres!();

    let backend = utils::create_test_backend().await.unwrap();
    let base_key = format!("test:batch:{}", Uuid::new_v4());

    // Create batch operations
    let operations = vec![
        DataOperation::Set {
            key: format!("{}:1", base_key),
            value: DataValue::String("value1".to_string()),
            ttl: None,
        },
        DataOperation::Set {
            key: format!("{}:2", base_key),
            value: DataValue::Int(42),
            ttl: None,
        },
        DataOperation::Set {
            key: format!("{}:3", base_key),
            value: DataValue::Bool(true),
            ttl: None,
        },
    ];

    // Execute batch
    let batch_op = DataOperation::Batch { operations };
    let result = backend.execute_data(batch_op).await.unwrap();
    assert!(result.is_success());

    // Verify results
    if let Some(DataValue::Array(results)) = result.data {
        assert_eq!(results.len(), 3);
        // Each operation should have succeeded
        for result_item in results {
            if let DataValue::Bool(success) = result_item {
                assert!(success);
            }
        }
    }

    // Cleanup
    for i in 1..=3 {
        let delete_op = DataOperation::Delete {
            key: format!("{}:{}", base_key, i),
            fields: None,
        };
        let _ = backend.execute_data(delete_op).await;
    }
}
