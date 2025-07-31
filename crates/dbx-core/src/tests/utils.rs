//! Shared test utilities for DBX Core tests

use crate::*;
use std::collections::HashMap;
use uuid::Uuid;

/// Create a test DataValue with complex nested structure
pub fn create_test_data_value() -> DataValue {
    let mut object = HashMap::new();
    object.insert(
        "string_field".to_string(),
        DataValue::String("test".to_string()),
    );
    object.insert("int_field".to_string(), DataValue::Int(42));
    object.insert("bool_field".to_string(), DataValue::Bool(true));
    object.insert(
        "array_field".to_string(),
        DataValue::Array(vec![
            DataValue::String("item1".to_string()),
            DataValue::Int(100),
        ]),
    );

    DataValue::Object(object)
}

/// Create a test DataOperation for various scenarios
pub fn create_test_set_operation(key: &str, value: DataValue) -> DataOperation {
    DataOperation::Set {
        key: key.to_string(),
        value,
        ttl: None,
    }
}

/// Create a test QueryOperation
pub fn create_test_query_operation() -> QueryOperation {
    QueryOperation {
        id: Uuid::new_v4(),
        filter: QueryFilter::KeyPattern {
            pattern: "test:*".to_string(),
        },
        limit: Some(10),
        offset: Some(0),
        sort: None,
    }
}

/// Create a test StreamOperation
pub fn create_test_stream_operation() -> StreamOperation {
    StreamOperation::Publish {
        channel: "test_channel".to_string(),
        message: DataValue::String("test_message".to_string()),
    }
}

/// Assert that a DataResult represents success
pub fn assert_success(result: &DataResult) {
    assert!(
        result.success,
        "Expected successful result, got: {:?}",
        result
    );
    assert!(
        result.error.is_none(),
        "Expected no error, got: {:?}",
        result.error
    );
}

/// Assert that a DataResult represents an error
pub fn assert_error(result: &DataResult) {
    assert!(
        !result.success,
        "Expected error result, got success: {:?}",
        result
    );
    assert!(
        result.error.is_some(),
        "Expected error, got none: {:?}",
        result
    );
}
