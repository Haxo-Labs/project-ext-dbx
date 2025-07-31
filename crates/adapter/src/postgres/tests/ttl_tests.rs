//! PostgreSQL TTL functionality tests

use tokio::time::{sleep, Duration};
use uuid::Uuid;

use super::utils::{self, skip_if_no_postgres};
use dbx_core::{DataOperation, DataValue};

#[tokio::test]
async fn test_ttl_expiration() {
    skip_if_no_postgres!();

    let backend = utils::create_test_backend().await.unwrap();
    let test_key = format!("test:ttl:{}", Uuid::new_v4());

    // Set with 2 second TTL
    let set_op = DataOperation::Set {
        key: test_key.clone(),
        value: DataValue::String("expires_soon".to_string()),
        ttl: Some(2),
    };
    let result = backend.execute_data(set_op).await.unwrap();
    assert!(result.is_success());

    // Verify it exists immediately
    let get_op = DataOperation::Get {
        key: test_key.clone(),
        fields: None,
    };
    let result = backend.execute_data(get_op).await.unwrap();
    assert!(result.is_success());
    assert_eq!(
        result.data,
        Some(DataValue::String("expires_soon".to_string()))
    );

    // Wait for expiration
    sleep(Duration::from_secs(3)).await;

    // Verify it's expired
    let get_after_expiry = DataOperation::Get {
        key: test_key,
        fields: None,
    };
    let result = backend.execute_data(get_after_expiry).await.unwrap();
    assert!(result.is_success());
    assert_eq!(result.data, Some(DataValue::Null));
}

#[tokio::test]
async fn test_ttl_operations() {
    skip_if_no_postgres!();

    let backend = utils::create_test_backend().await.unwrap();
    let test_key = format!("test:ttl_ops:{}", Uuid::new_v4());

    // Set without TTL
    let set_op = DataOperation::Set {
        key: test_key.clone(),
        value: DataValue::String("no_ttl".to_string()),
        ttl: None,
    };
    let result = backend.execute_data(set_op).await.unwrap();
    assert!(result.is_success());

    // Check initial TTL (should be -1 for no expiry)
    let get_ttl_op = DataOperation::GetTtl {
        key: test_key.clone(),
    };
    let result = backend.execute_data(get_ttl_op).await.unwrap();
    assert!(result.is_success());
    if let Some(DataValue::Int(ttl)) = result.data {
        assert!(ttl == -1 || ttl > 0); // -1 means no expiry, >0 means has expiry
    }

    // Set TTL
    let set_ttl_op = DataOperation::SetTtl {
        key: test_key.clone(),
        ttl: 300, // 5 minutes
    };
    let result = backend.execute_data(set_ttl_op).await.unwrap();
    assert!(result.is_success());

    // Verify TTL was set
    let get_ttl_after_set = DataOperation::GetTtl {
        key: test_key.clone(),
    };
    let result = backend.execute_data(get_ttl_after_set).await.unwrap();
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
async fn test_ttl_with_different_values() {
    skip_if_no_postgres!();

    let backend = utils::create_test_backend().await.unwrap();
    let base_key = format!("test:ttl_values:{}", Uuid::new_v4());

    // Test different TTL values
    let ttl_values = [1, 5, 10, 60]; // seconds

    for (i, ttl) in ttl_values.iter().enumerate() {
        let key = format!("{}:{}", base_key, i);

        let set_op = DataOperation::Set {
            key: key.clone(),
            value: DataValue::String(format!("expires_in_{}", ttl)),
            ttl: Some(*ttl),
        };
        let result = backend.execute_data(set_op).await.unwrap();
        assert!(result.is_success());

        // Verify TTL is set correctly
        let get_ttl_op = DataOperation::GetTtl { key: key.clone() };
        let result = backend.execute_data(get_ttl_op).await.unwrap();
        assert!(result.is_success());

        if let Some(DataValue::Int(actual_ttl)) = result.data {
            assert!(actual_ttl > 0 && actual_ttl <= *ttl as i64);
        }
    }

    // Cleanup
    for i in 0..ttl_values.len() {
        let delete_op = DataOperation::Delete {
            key: format!("{}:{}", base_key, i),
            fields: None,
        };
        let _ = backend.execute_data(delete_op).await;
    }
}

#[tokio::test]
async fn test_ttl_update_preservation() {
    skip_if_no_postgres!();

    let backend = utils::create_test_backend().await.unwrap();
    let test_key = format!("test:ttl_update:{}", Uuid::new_v4());

    // Set with TTL
    let set_op = DataOperation::Set {
        key: test_key.clone(),
        value: DataValue::String("original".to_string()),
        ttl: Some(300), // 5 minutes
    };
    let result = backend.execute_data(set_op).await.unwrap();
    assert!(result.is_success());

    // Get initial TTL
    let get_ttl_op = DataOperation::GetTtl {
        key: test_key.clone(),
    };
    let result = backend.execute_data(get_ttl_op).await.unwrap();
    let initial_ttl = if let Some(DataValue::Int(ttl)) = result.data {
        ttl
    } else {
        panic!("Expected TTL value");
    };

    // Update value without specifying TTL (should preserve existing TTL)
    let update_op = DataOperation::Set {
        key: test_key.clone(),
        value: DataValue::String("updated".to_string()),
        ttl: None,
    };
    let result = backend.execute_data(update_op).await.unwrap();
    assert!(result.is_success());

    // Verify TTL is still set (though might be slightly less due to time passage)
    let get_ttl_after_update = DataOperation::GetTtl {
        key: test_key.clone(),
    };
    let result = backend.execute_data(get_ttl_after_update).await.unwrap();
    assert!(result.is_success());

    if let Some(DataValue::Int(ttl_after_update)) = result.data {
        // TTL should still be positive and not too different from initial
        assert!(ttl_after_update > 0);
        assert!(ttl_after_update <= initial_ttl);
        assert!(initial_ttl - ttl_after_update < 10); // Allow for some time passage
    }

    // Cleanup
    let delete_op = DataOperation::Delete {
        key: test_key,
        fields: None,
    };
    let _ = backend.execute_data(delete_op).await;
}
