use dbx_adapter::redis::primitives::hash::RedisHash;
use redis::Connection;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HashOperation {
    pub key: String,
    pub field: String,
    pub value: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HashResponse {
    pub success: bool,
    pub data: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HashInfo {
    pub key: String,
    pub field: String,
    pub value: String,
    pub ttl: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HashField {
    pub field: String,
    pub value: String,
}

fn redis_hash(conn: Arc<Mutex<Connection>>) -> RedisHash {
    RedisHash::new(conn)
}

// =========================
// Single Field Operations
// =========================

pub fn get_hash_field(
    conn: Arc<Mutex<Connection>>,
    key: &str,
    field: &str,
) -> redis::RedisResult<Option<String>> {
    redis_hash(conn).hget(key, field)
}

pub fn set_hash_field(
    conn: Arc<Mutex<Connection>>,
    key: &str,
    field: &str,
    value: &str,
) -> redis::RedisResult<bool> {
    redis_hash(conn).hset(key, field, value)
}

pub fn delete_hash_field(
    conn: Arc<Mutex<Connection>>,
    key: &str,
    field: &str,
) -> redis::RedisResult<bool> {
    let deleted = redis_hash(conn).hdel(key, &[field])?;
    Ok(deleted > 0)
}

pub fn hash_exists(
    conn: Arc<Mutex<Connection>>,
    key: &str,
    field: &str,
) -> redis::RedisResult<bool> {
    redis_hash(conn).hexists(key, field)
}

// =========================
// Hash Operations
// =========================

pub fn get_all_hash_fields(
    conn: Arc<Mutex<Connection>>,
    key: &str,
) -> redis::RedisResult<std::collections::HashMap<String, String>> {
    redis_hash(conn).hgetall(key)
}

pub fn get_hash_fields(
    conn: Arc<Mutex<Connection>>,
    key: &str,
    fields: &[&str],
) -> redis::RedisResult<Vec<Option<String>>> {
    redis_hash(conn).hmget(key, fields)
}

pub fn set_multiple_hash_fields(
    conn: Arc<Mutex<Connection>>,
    key: &str,
    fields: &[(&str, &str)],
) -> redis::RedisResult<()> {
    redis_hash(conn).hmset(key, fields)
}

pub fn get_hash_length(conn: Arc<Mutex<Connection>>, key: &str) -> redis::RedisResult<usize> {
    redis_hash(conn).hlen(key)
}

pub fn get_hash_keys(conn: Arc<Mutex<Connection>>, key: &str) -> redis::RedisResult<Vec<String>> {
    redis_hash(conn).hkeys(key)
}

pub fn get_hash_values(conn: Arc<Mutex<Connection>>, key: &str) -> redis::RedisResult<Vec<String>> {
    redis_hash(conn).hvals(key)
}

pub fn increment_hash_field(
    conn: Arc<Mutex<Connection>>,
    key: &str,
    field: &str,
    increment: i64,
) -> redis::RedisResult<i64> {
    redis_hash(conn).hincrby(key, field, increment)
}

pub fn increment_hash_field_float(
    conn: Arc<Mutex<Connection>>,
    key: &str,
    field: &str,
    increment: f64,
) -> redis::RedisResult<f64> {
    redis_hash(conn).hincrbyfloat(key, field, increment)
}

pub fn set_hash_field_if_not_exists(
    conn: Arc<Mutex<Connection>>,
    key: &str,
    field: &str,
    value: &str,
) -> redis::RedisResult<bool> {
    redis_hash(conn).hsetnx(key, field, value)
}

pub fn get_random_hash_field(
    conn: Arc<Mutex<Connection>>,
    key: &str,
) -> redis::RedisResult<Option<String>> {
    redis_hash(conn).hrandfield(key)
}

pub fn get_random_hash_fields(
    conn: Arc<Mutex<Connection>>,
    key: &str,
    count: isize,
) -> redis::RedisResult<Vec<String>> {
    redis_hash(conn).hrandfield_count(key, count)
}

pub fn get_random_hash_fields_with_values(
    conn: Arc<Mutex<Connection>>,
    key: &str,
    count: isize,
) -> redis::RedisResult<Vec<(String, String)>> {
    redis_hash(conn).hrandfield_withvalues(key, count)
}

// =========================
// Hash Management
// =========================

pub fn delete_hash(conn: Arc<Mutex<Connection>>, key: &str) -> redis::RedisResult<bool> {
    let exists = redis_hash(conn.clone()).exists(key)?;
    if exists {
        redis_hash(conn).del(key)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

pub fn hash_exists_key(conn: Arc<Mutex<Connection>>, key: &str) -> redis::RedisResult<bool> {
    redis_hash(conn).exists(key)
}

pub fn get_hash_ttl(conn: Arc<Mutex<Connection>>, key: &str) -> redis::RedisResult<i64> {
    redis_hash(conn).ttl(key)
}

pub fn set_hash_ttl(conn: Arc<Mutex<Connection>>, key: &str, ttl: u64) -> redis::RedisResult<bool> {
    redis_hash(conn).expire(key, ttl)
}

// =========================
// Batch Operations
// =========================

pub fn get_multiple_hash_fields(
    conn: Arc<Mutex<Connection>>,
    hash_fields: Vec<(&str, &str)>,
) -> redis::RedisResult<Vec<Option<String>>> {
    redis_hash(conn).hget_many(hash_fields)
}

pub fn set_multiple_hashes(
    conn: Arc<Mutex<Connection>>,
    hash_operations: Vec<(&str, Vec<(&str, &str)>)>,
) -> redis::RedisResult<Vec<bool>> {
    redis_hash(conn).hset_many(hash_operations)
}

pub fn delete_multiple_hash_fields(
    conn: Arc<Mutex<Connection>>,
    hash_fields: Vec<(&str, Vec<&str>)>,
) -> redis::RedisResult<Vec<usize>> {
    redis_hash(conn).hdel_many(hash_fields)
}

pub fn check_multiple_hash_fields(
    conn: Arc<Mutex<Connection>>,
    hash_fields: Vec<(&str, &str)>,
) -> redis::RedisResult<Vec<bool>> {
    redis_hash(conn).hexists_many(hash_fields)
}

pub fn get_multiple_hash_lengths(
    conn: Arc<Mutex<Connection>>,
    keys: Vec<&str>,
) -> redis::RedisResult<Vec<usize>> {
    redis_hash(conn).hlen_many(keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_hash_operation_structure() {
        let operation = HashOperation {
            key: "user:123".to_string(),
            field: "name".to_string(),
            value: Some("Alice".to_string()),
        };
        assert_eq!(operation.key, "user:123");
        assert_eq!(operation.field, "name");
        assert_eq!(operation.value, Some("Alice".to_string()));

        // Test serialization
        let json = serde_json::to_string(&operation).unwrap();
        assert!(json.contains("user:123"));
        assert!(json.contains("name"));
        assert!(json.contains("Alice"));

        // Test deserialization
        let deserialized: HashOperation = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.key, "user:123");
        assert_eq!(deserialized.field, "name");
        assert_eq!(deserialized.value, Some("Alice".to_string()));
    }

    #[test]
    fn test_hash_operation_with_none_value() {
        let operation = HashOperation {
            key: "empty".to_string(),
            field: "field".to_string(),
            value: None,
        };
        assert!(operation.value.is_none());

        let json = serde_json::to_string(&operation).unwrap();
        let deserialized: HashOperation = serde_json::from_str(&json).unwrap();
        assert!(deserialized.value.is_none());
    }

    #[test]
    fn test_hash_response_structure() {
        // Test success response
        let success_response = HashResponse {
            success: true,
            data: Some("field_value".to_string()),
            error: None,
        };
        assert!(success_response.success);
        assert!(success_response.data.is_some());
        assert!(success_response.error.is_none());

        // Test error response
        let error_response = HashResponse {
            success: false,
            data: None,
            error: Some("Field not found".to_string()),
        };
        assert!(!error_response.success);
        assert!(error_response.data.is_none());
        assert!(error_response.error.is_some());

        // Test serialization
        let json = serde_json::to_string(&success_response).unwrap();
        let deserialized: HashResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.success, true);
        assert_eq!(deserialized.data, Some("field_value".to_string()));
    }

    #[test]
    fn test_hash_info_structure() {
        let info = HashInfo {
            key: "user:456".to_string(),
            field: "email".to_string(),
            value: "alice@example.com".to_string(),
            ttl: Some(3600),
        };
        assert_eq!(info.key, "user:456");
        assert_eq!(info.field, "email");
        assert_eq!(info.value, "alice@example.com");
        assert_eq!(info.ttl, Some(3600));

        // Test with no TTL
        let info_no_ttl = HashInfo {
            key: "persistent".to_string(),
            field: "data".to_string(),
            value: "value".to_string(),
            ttl: None,
        };
        assert!(info_no_ttl.ttl.is_none());

        // Test serialization
        let json = serde_json::to_string(&info).unwrap();
        let deserialized: HashInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.key, "user:456");
        assert_eq!(deserialized.field, "email");
        assert_eq!(deserialized.value, "alice@example.com");
        assert_eq!(deserialized.ttl, Some(3600));
    }

    #[test]
    fn test_hash_field_structure() {
        let field = HashField {
            field: "age".to_string(),
            value: "30".to_string(),
        };
        assert_eq!(field.field, "age");
        assert_eq!(field.value, "30");

        // Test serialization
        let json = serde_json::to_string(&field).unwrap();
        assert!(json.contains("age"));
        assert!(json.contains("30"));

        let deserialized: HashField = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.field, "age");
        assert_eq!(deserialized.value, "30");
    }

    #[test]
    fn test_debug_implementations() {
        let operation = HashOperation {
            key: "test".to_string(),
            field: "field".to_string(),
            value: Some("value".to_string()),
        };
        let debug_str = format!("{:?}", operation);
        assert!(debug_str.contains("HashOperation"));
        assert!(debug_str.contains("test"));
        assert!(debug_str.contains("field"));
        assert!(debug_str.contains("value"));

        let response = HashResponse {
            success: true,
            data: None,
            error: None,
        };
        let debug_str = format!("{:?}", response);
        assert!(debug_str.contains("HashResponse"));
        assert!(debug_str.contains("true"));

        let info = HashInfo {
            key: "key".to_string(),
            field: "field".to_string(),
            value: "value".to_string(),
            ttl: Some(100),
        };
        let debug_str = format!("{:?}", info);
        assert!(debug_str.contains("HashInfo"));
        assert!(debug_str.contains("100"));

        let field = HashField {
            field: "name".to_string(),
            value: "value".to_string(),
        };
        let debug_str = format!("{:?}", field);
        assert!(debug_str.contains("HashField"));
        assert!(debug_str.contains("name"));
    }

    #[test]
    fn test_clone_implementations() {
        let original_operation = HashOperation {
            key: "original".to_string(),
            field: "field".to_string(),
            value: Some("value".to_string()),
        };
        let cloned_operation = original_operation.clone();
        assert_eq!(original_operation.key, cloned_operation.key);
        assert_eq!(original_operation.field, cloned_operation.field);
        assert_eq!(original_operation.value, cloned_operation.value);

        let original_response = HashResponse {
            success: true,
            data: Some("data".to_string()),
            error: None,
        };
        let cloned_response = original_response.clone();
        assert_eq!(original_response.success, cloned_response.success);
        assert_eq!(original_response.data, cloned_response.data);

        let original_info = HashInfo {
            key: "key".to_string(),
            field: "field".to_string(),
            value: "value".to_string(),
            ttl: Some(600),
        };
        let cloned_info = original_info.clone();
        assert_eq!(original_info.key, cloned_info.key);
        assert_eq!(original_info.field, cloned_info.field);
        assert_eq!(original_info.value, cloned_info.value);
        assert_eq!(original_info.ttl, cloned_info.ttl);

        let original_field = HashField {
            field: "test".to_string(),
            value: "data".to_string(),
        };
        let cloned_field = original_field.clone();
        assert_eq!(original_field.field, cloned_field.field);
        assert_eq!(original_field.value, cloned_field.value);
    }

    #[test]
    fn test_edge_case_values() {
        // Test empty strings
        let empty_operation = HashOperation {
            key: "".to_string(),
            field: "".to_string(),
            value: Some("".to_string()),
        };
        let json = serde_json::to_string(&empty_operation).unwrap();
        let deserialized: HashOperation = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.key, "");
        assert_eq!(deserialized.field, "");
        assert_eq!(deserialized.value, Some("".to_string()));

        // Test unicode values
        let unicode_operation = HashOperation {
            key: "user:123_test".to_string(),
            field: "name_field".to_string(),
            value: Some("test_value_unicode".to_string()),
        };
        let json = serde_json::to_string(&unicode_operation).unwrap();
        let deserialized: HashOperation = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.key, "user:123_test");
        assert_eq!(deserialized.field, "name_field");
        assert_eq!(deserialized.value, Some("test_value_unicode".to_string()));

        // Test very long strings
        let long_key = "k".repeat(1000);
        let long_field = "f".repeat(1000);
        let long_value = "v".repeat(1000);
        let long_operation = HashOperation {
            key: long_key.clone(),
            field: long_field.clone(),
            value: Some(long_value.clone()),
        };
        let json = serde_json::to_string(&long_operation).unwrap();
        let deserialized: HashOperation = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.key.len(), 1000);
        assert_eq!(deserialized.field.len(), 1000);
        assert_eq!(deserialized.value.unwrap().len(), 1000);
    }

    #[test]
    fn test_hash_response_with_complex_data() {
        // Test with JSON data as string
        let json_data = serde_json::json!({
            "nested": {
                "array": [1, 2, 3],
                "object": {"key": "value"}
            }
        })
        .to_string();

        let response = HashResponse {
            success: true,
            data: Some(json_data.clone()),
            error: None,
        };

        let serialized = serde_json::to_string(&response).unwrap();
        let deserialized: HashResponse = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.data, Some(json_data));
    }

    #[test]
    fn test_hash_info_with_edge_cases() {
        // Test with negative TTL
        let info_negative_ttl = HashInfo {
            key: "expiring".to_string(),
            field: "field".to_string(),
            value: "value".to_string(),
            ttl: Some(-1),
        };
        let json = serde_json::to_string(&info_negative_ttl).unwrap();
        let deserialized: HashInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.ttl, Some(-1));

        // Test with very large TTL
        let info_large_ttl = HashInfo {
            key: "long_lived".to_string(),
            field: "field".to_string(),
            value: "value".to_string(),
            ttl: Some(i64::MAX),
        };
        let json = serde_json::to_string(&info_large_ttl).unwrap();
        let deserialized: HashInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.ttl, Some(i64::MAX));
    }

    #[test]
    fn test_hash_field_special_characters() {
        // Test with special characters in field and value
        let special_field = HashField {
            field: "field:with@special#characters$".to_string(),
            value: "value with spaces\tand\nnewlines".to_string(),
        };

        let json = serde_json::to_string(&special_field).unwrap();
        let deserialized: HashField = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.field, "field:with@special#characters$");
        assert_eq!(deserialized.value, "value with spaces\tand\nnewlines");
    }

    #[test]
    fn test_serialization_consistency() {
        // Test that all structures can be serialized and deserialized consistently
        let operation = HashOperation {
            key: "consistency_test".to_string(),
            field: "test_field".to_string(),
            value: Some("test_value".to_string()),
        };

        let json1 = serde_json::to_string(&operation).unwrap();
        let deserialized1: HashOperation = serde_json::from_str(&json1).unwrap();
        let json2 = serde_json::to_string(&deserialized1).unwrap();

        // Second serialization should match first
        assert_eq!(json1, json2);

        // Test the same for other structures
        let response = HashResponse {
            success: false,
            data: None,
            error: Some("test error".to_string()),
        };

        let resp_json1 = serde_json::to_string(&response).unwrap();
        let resp_deserialized1: HashResponse = serde_json::from_str(&resp_json1).unwrap();
        let resp_json2 = serde_json::to_string(&resp_deserialized1).unwrap();
        assert_eq!(resp_json1, resp_json2);
    }
}
