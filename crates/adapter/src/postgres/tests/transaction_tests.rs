//! PostgreSQL transaction and consistency tests

use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use super::utils::{self, skip_if_no_postgres};
use dbx_core::{DataOperation, DataValue};

#[tokio::test]
async fn test_compare_and_swap() {
    skip_if_no_postgres!();

    let backend = utils::create_test_backend().await.unwrap();
    let test_key = format!("test:cas:{}", Uuid::new_v4());

    // Set initial value
    let set_op = DataOperation::Set {
        key: test_key.clone(),
        value: DataValue::String("initial".to_string()),
        ttl: None,
    };
    let result = backend.execute_data(set_op).await.unwrap();
    assert!(result.is_success());

    // Successful CAS
    let cas_op = DataOperation::CompareAndSwap {
        key: test_key.clone(),
        expected_value: "initial".to_string(),
        new_value: "updated".to_string(),
        ttl: None,
    };
    let result = backend.execute_data(cas_op).await.unwrap();
    assert!(result.is_success());
    assert_eq!(result.data, Some(DataValue::Bool(true)));

    // Failed CAS (wrong expected value)
    let failed_cas = DataOperation::CompareAndSwap {
        key: test_key.clone(),
        expected_value: "wrong".to_string(),
        new_value: "should_not_update".to_string(),
        ttl: None,
    };
    let result = backend.execute_data(failed_cas).await.unwrap();
    assert!(result.is_success());
    assert_eq!(result.data, Some(DataValue::Bool(false)));

    // Verify value wasn't changed
    let get_op = DataOperation::Get {
        key: test_key.clone(),
        fields: None,
    };
    let result = backend.execute_data(get_op).await.unwrap();
    assert!(result.is_success());
    assert_eq!(result.data, Some(DataValue::String("updated".to_string())));

    // Cleanup
    let delete_op = DataOperation::Delete {
        key: test_key,
        fields: None,
    };
    let _ = backend.execute_data(delete_op).await;
}

#[tokio::test]
async fn test_concurrent_counter_increment() {
    skip_if_no_postgres!();

    let backend = Arc::new(utils::create_test_backend().await.unwrap());
    let test_key = format!("test:concurrent_counter:{}", Uuid::new_v4());

    // Set initial counter value
    let set_op = DataOperation::Set {
        key: test_key.clone(),
        value: DataValue::Int(0),
        ttl: None,
    };
    let result = backend.execute_data(set_op).await.unwrap();
    assert!(result.is_success());

    // Simulate concurrent counter increments using CAS
    let mut handles = vec![];
    for _i in 0..5 {
        let backend_clone = Arc::clone(&backend);
        let key_clone = test_key.clone();

        let handle = tokio::spawn(async move {
            for attempt in 0..5 {
                // Read current value
                let get_op = DataOperation::Get {
                    key: key_clone.clone(),
                    fields: None,
                };
                let result = backend_clone.execute_data(get_op).await.unwrap();

                if let Some(DataValue::Int(current_value)) = result.data {
                    // Try to increment with CAS
                    let new_value = current_value + 1;
                    let cas_op = DataOperation::CompareAndSwap {
                        key: key_clone.clone(),
                        expected_value: current_value.to_string(),
                        new_value: new_value.to_string(),
                        ttl: None,
                    };

                    let cas_result = backend_clone.execute_data(cas_op).await.unwrap();
                    if let Some(DataValue::Bool(success)) = cas_result.data {
                        if success {
                            // CAS succeeded, we're done
                            return Ok(());
                        }
                    }
                }

                // CAS failed, retry with backoff
                tokio::time::sleep(Duration::from_millis(10 * attempt as u64)).await;
            }

            Err::<(), Box<dyn std::error::Error + Send + Sync>>("CAS failed after retries".into())
        });
        handles.push(handle);
    }

    // Wait for all increment attempts
    let mut successful_increments = 0;
    for handle in handles {
        if handle.await.unwrap().is_ok() {
            successful_increments += 1;
        }
    }

    // Check final value
    let get_final = DataOperation::Get {
        key: test_key.clone(),
        fields: None,
    };
    let result = backend.execute_data(get_final).await.unwrap();
    assert!(result.is_success());

    if let Some(DataValue::Int(final_value)) = result.data {
        // Final value should reflect the successful increments
        assert!(final_value > 0);
        assert!(final_value <= 5); // At most 5 increments
        println!(
            "Final counter value: {}, Successful increments: {}",
            final_value, successful_increments
        );
    }

    // Cleanup
    let delete_op = DataOperation::Delete {
        key: test_key,
        fields: None,
    };
    let _ = backend.execute_data(delete_op).await;
}

#[tokio::test]
async fn test_cas_with_ttl() {
    skip_if_no_postgres!();

    let backend = utils::create_test_backend().await.unwrap();
    let test_key = format!("test:cas_ttl:{}", Uuid::new_v4());

    // Set initial value
    let set_op = DataOperation::Set {
        key: test_key.clone(),
        value: DataValue::String("initial".to_string()),
        ttl: None,
    };
    let result = backend.execute_data(set_op).await.unwrap();
    assert!(result.is_success());

    // CAS with TTL
    let cas_op = DataOperation::CompareAndSwap {
        key: test_key.clone(),
        expected_value: "initial".to_string(),
        new_value: "updated_with_ttl".to_string(),
        ttl: Some(300), // 5 minutes
    };
    let result = backend.execute_data(cas_op).await.unwrap();
    assert!(result.is_success());
    assert_eq!(result.data, Some(DataValue::Bool(true)));

    // Verify value was updated
    let get_op = DataOperation::Get {
        key: test_key.clone(),
        fields: None,
    };
    let result = backend.execute_data(get_op).await.unwrap();
    assert!(result.is_success());
    assert_eq!(
        result.data,
        Some(DataValue::String("updated_with_ttl".to_string()))
    );

    // Verify TTL was set
    let get_ttl_op = DataOperation::GetTtl {
        key: test_key.clone(),
    };
    let result = backend.execute_data(get_ttl_op).await.unwrap();
    assert!(result.is_success());
    if let Some(DataValue::Int(ttl)) = result.data {
        assert!(ttl > 0 && ttl <= 300);
    }

    // Cleanup
    let delete_op = DataOperation::Delete {
        key: test_key,
        fields: None,
    };
    let _ = backend.execute_data(delete_op).await;
}

#[tokio::test]
async fn test_cas_nonexistent_key() {
    skip_if_no_postgres!();

    let backend = utils::create_test_backend().await.unwrap();
    let test_key = format!("test:cas_nonexistent:{}", Uuid::new_v4());

    // CAS on nonexistent key expecting empty value
    let cas_op = DataOperation::CompareAndSwap {
        key: test_key.clone(),
        expected_value: "".to_string(), // Expect empty/null
        new_value: "new_value".to_string(),
        ttl: None,
    };
    let result = backend.execute_data(cas_op).await.unwrap();
    assert!(result.is_success());
    assert_eq!(result.data, Some(DataValue::Bool(true)));

    // Verify value was set
    let get_op = DataOperation::Get {
        key: test_key.clone(),
        fields: None,
    };
    let result = backend.execute_data(get_op).await.unwrap();
    assert!(result.is_success());
    assert_eq!(
        result.data,
        Some(DataValue::String("new_value".to_string()))
    );

    // Cleanup
    let delete_op = DataOperation::Delete {
        key: test_key,
        fields: None,
    };
    let _ = backend.execute_data(delete_op).await;
}
