use crate::routes::common::hash::{
    check_multiple_hash_fields, delete_hash, delete_hash_field, delete_multiple_hash_fields,
    get_all_hash_fields, get_hash_field, get_hash_fields, get_hash_keys, get_hash_length,
    get_hash_ttl, get_hash_values, get_multiple_hash_fields, get_multiple_hash_lengths,
    get_random_hash_field, get_random_hash_fields, get_random_hash_fields_with_values, hash_exists,
    hash_exists_key, increment_hash_field, increment_hash_field_float, set_hash_field,
    set_hash_field_if_not_exists, set_hash_ttl, set_multiple_hash_fields, set_multiple_hashes,
};
use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
    routing::{delete, get, post},
    Router,
};
use dbx_adapter::redis::client::RedisPool;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Deserialize, Serialize)]
struct SetHashFieldRequest {
    value: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct SetMultipleHashFieldsRequest {
    fields: std::collections::HashMap<String, String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct GetHashFieldsRequest {
    fields: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct IncrementHashFieldRequest {
    increment: i64,
}

#[derive(Debug, Deserialize, Serialize)]
struct IncrementHashFieldFloatRequest {
    increment: f64,
}

#[derive(Debug, Deserialize, Serialize)]
struct GetRandomHashFieldsRequest {
    count: isize,
}

#[derive(Debug, Deserialize, Serialize)]
struct GetRandomHashFieldsWithValuesRequest {
    count: isize,
}

#[derive(Debug, Deserialize, Serialize)]
struct SetHashTtlRequest {
    ttl: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct BatchGetHashFieldsRequest {
    hash_fields: Vec<(String, String)>, // (key, field) pairs
}

#[derive(Debug, Deserialize, Serialize)]
struct BatchSetHashFieldsRequest {
    hash_operations: Vec<(String, Vec<(String, String)>)>, // (key, [(field, value)]) pairs
}

#[derive(Debug, Deserialize, Serialize)]
struct BatchDeleteHashFieldsRequest {
    hash_fields: Vec<(String, Vec<String>)>, // (key, [fields]) pairs
}

#[derive(Debug, Deserialize, Serialize)]
struct BatchCheckHashFieldsRequest {
    hash_fields: Vec<(String, String)>, // (key, field) pairs
}

#[derive(Debug, Deserialize, Serialize)]
struct BatchGetHashLengthsRequest {
    keys: Vec<String>,
}

// Single field operations
async fn get_hash_field_handler(
    State(pool): State<Arc<RedisPool>>,
    Path((key, field)): Path<(String, String)>,
) -> Result<Json<Option<String>>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let value =
        get_hash_field(conn_arc, &key, &field).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(value))
}

async fn set_hash_field_handler(
    State(pool): State<Arc<RedisPool>>,
    Path((key, field)): Path<(String, String)>,
    Json(payload): Json<SetHashFieldRequest>,
) -> Result<Json<bool>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let result = set_hash_field(conn_arc, &key, &field, &payload.value)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(result))
}

async fn delete_hash_field_handler(
    State(pool): State<Arc<RedisPool>>,
    Path((key, field)): Path<(String, String)>,
) -> Result<Json<bool>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let deleted =
        delete_hash_field(conn_arc, &key, &field).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(deleted))
}

async fn hash_exists_handler(
    State(pool): State<Arc<RedisPool>>,
    Path((key, field)): Path<(String, String)>,
) -> Result<Json<bool>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let exists =
        hash_exists(conn_arc, &key, &field).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(exists))
}

// Hash operations
async fn get_all_hash_fields_handler(
    State(pool): State<Arc<RedisPool>>,
    Path(key): Path<String>,
) -> Result<Json<std::collections::HashMap<String, String>>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let fields =
        get_all_hash_fields(conn_arc, &key).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(fields))
}

async fn get_hash_fields_handler(
    State(pool): State<Arc<RedisPool>>,
    Path(key): Path<String>,
    Json(payload): Json<GetHashFieldsRequest>,
) -> Result<Json<Vec<Option<String>>>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let field_refs: Vec<&str> = payload.fields.iter().map(|f| f.as_str()).collect();
    let values = get_hash_fields(conn_arc, &key, &field_refs)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(values))
}

async fn set_multiple_hash_fields_handler(
    State(pool): State<Arc<RedisPool>>,
    Path(key): Path<String>,
    Json(payload): Json<SetMultipleHashFieldsRequest>,
) -> Result<StatusCode, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let field_values: Vec<(&str, &str)> = payload
        .fields
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    set_multiple_hash_fields(conn_arc, &key, &field_values)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::OK)
}

async fn get_hash_length_handler(
    State(pool): State<Arc<RedisPool>>,
    Path(key): Path<String>,
) -> Result<Json<usize>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let length = get_hash_length(conn_arc, &key).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(length))
}

async fn get_hash_keys_handler(
    State(pool): State<Arc<RedisPool>>,
    Path(key): Path<String>,
) -> Result<Json<Vec<String>>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let keys = get_hash_keys(conn_arc, &key).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(keys))
}

async fn get_hash_values_handler(
    State(pool): State<Arc<RedisPool>>,
    Path(key): Path<String>,
) -> Result<Json<Vec<String>>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let values = get_hash_values(conn_arc, &key).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(values))
}

async fn increment_hash_field_handler(
    State(pool): State<Arc<RedisPool>>,
    Path((key, field)): Path<(String, String)>,
    Json(payload): Json<IncrementHashFieldRequest>,
) -> Result<Json<i64>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let result = increment_hash_field(conn_arc, &key, &field, payload.increment)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(result))
}

async fn increment_hash_field_float_handler(
    State(pool): State<Arc<RedisPool>>,
    Path((key, field)): Path<(String, String)>,
    Json(payload): Json<IncrementHashFieldFloatRequest>,
) -> Result<Json<f64>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let result = increment_hash_field_float(conn_arc, &key, &field, payload.increment)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(result))
}

async fn set_hash_field_if_not_exists_handler(
    State(pool): State<Arc<RedisPool>>,
    Path((key, field)): Path<(String, String)>,
    Json(payload): Json<SetHashFieldRequest>,
) -> Result<Json<bool>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let result = set_hash_field_if_not_exists(conn_arc, &key, &field, &payload.value)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(result))
}

async fn get_random_hash_field_handler(
    State(pool): State<Arc<RedisPool>>,
    Path(key): Path<String>,
) -> Result<Json<Option<String>>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let field =
        get_random_hash_field(conn_arc, &key).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(field))
}

async fn get_random_hash_fields_handler(
    State(pool): State<Arc<RedisPool>>,
    Path(key): Path<String>,
    Json(payload): Json<GetRandomHashFieldsRequest>,
) -> Result<Json<Vec<String>>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let fields = get_random_hash_fields(conn_arc, &key, payload.count)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(fields))
}

async fn get_random_hash_fields_with_values_handler(
    State(pool): State<Arc<RedisPool>>,
    Path(key): Path<String>,
    Json(payload): Json<GetRandomHashFieldsWithValuesRequest>,
) -> Result<Json<Vec<(String, String)>>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let fields = get_random_hash_fields_with_values(conn_arc, &key, payload.count)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(fields))
}

// Hash management
async fn delete_hash_handler(
    State(pool): State<Arc<RedisPool>>,
    Path(key): Path<String>,
) -> Result<Json<bool>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let deleted = delete_hash(conn_arc, &key).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(deleted))
}

async fn hash_exists_key_handler(
    State(pool): State<Arc<RedisPool>>,
    Path(key): Path<String>,
) -> Result<Json<bool>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let exists = hash_exists_key(conn_arc, &key).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(exists))
}

async fn get_hash_ttl_handler(
    State(pool): State<Arc<RedisPool>>,
    Path(key): Path<String>,
) -> Result<Json<i64>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let ttl = get_hash_ttl(conn_arc, &key).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(ttl))
}

async fn set_hash_ttl_handler(
    State(pool): State<Arc<RedisPool>>,
    Path(key): Path<String>,
    Json(payload): Json<SetHashTtlRequest>,
) -> Result<Json<bool>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let result =
        set_hash_ttl(conn_arc, &key, payload.ttl).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(result))
}

// Batch operations
async fn batch_get_hash_fields_handler(
    State(pool): State<Arc<RedisPool>>,
    Json(payload): Json<BatchGetHashFieldsRequest>,
) -> Result<Json<Vec<Option<String>>>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let hash_fields: Vec<(&str, &str)> = payload
        .hash_fields
        .iter()
        .map(|(k, f)| (k.as_str(), f.as_str()))
        .collect();
    let values = get_multiple_hash_fields(conn_arc, hash_fields)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(values))
}

async fn batch_set_hash_fields_handler(
    State(pool): State<Arc<RedisPool>>,
    Json(payload): Json<BatchSetHashFieldsRequest>,
) -> Result<Json<Vec<bool>>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let hash_operations: Vec<(&str, Vec<(&str, &str)>)> = payload
        .hash_operations
        .iter()
        .map(|(k, fields)| {
            let field_values: Vec<(&str, &str)> = fields
                .iter()
                .map(|(f, v)| (f.as_str(), v.as_str()))
                .collect();
            (k.as_str(), field_values)
        })
        .collect();
    let results = set_multiple_hashes(conn_arc, hash_operations)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(results))
}

async fn batch_delete_hash_fields_handler(
    State(pool): State<Arc<RedisPool>>,
    Json(payload): Json<BatchDeleteHashFieldsRequest>,
) -> Result<Json<Vec<usize>>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let hash_fields: Vec<(&str, Vec<&str>)> = payload
        .hash_fields
        .iter()
        .map(|(k, fields)| {
            let field_refs: Vec<&str> = fields.iter().map(|f| f.as_str()).collect();
            (k.as_str(), field_refs)
        })
        .collect();
    let results = delete_multiple_hash_fields(conn_arc, hash_fields)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(results))
}

async fn batch_check_hash_fields_handler(
    State(pool): State<Arc<RedisPool>>,
    Json(payload): Json<BatchCheckHashFieldsRequest>,
) -> Result<Json<Vec<bool>>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let hash_fields: Vec<(&str, &str)> = payload
        .hash_fields
        .iter()
        .map(|(k, f)| (k.as_str(), f.as_str()))
        .collect();
    let results = check_multiple_hash_fields(conn_arc, hash_fields)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(results))
}

async fn batch_get_hash_lengths_handler(
    State(pool): State<Arc<RedisPool>>,
    Json(payload): Json<BatchGetHashLengthsRequest>,
) -> Result<Json<Vec<usize>>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let key_refs: Vec<&str> = payload.keys.iter().map(|k| k.as_str()).collect();
    let lengths = get_multiple_hash_lengths(conn_arc, key_refs)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(lengths))
}

pub fn create_redis_hash_routes(pool: Arc<RedisPool>) -> Router {
    Router::new()
        // Single field operations
        .route("/hash/:key/:field", get(get_hash_field_handler))
        .route("/hash/:key/:field", post(set_hash_field_handler))
        .route("/hash/:key/:field", delete(delete_hash_field_handler))
        .route("/hash/:key/:field/exists", get(hash_exists_handler))
        .route(
            "/hash/:key/:field/increment",
            post(increment_hash_field_handler),
        )
        .route(
            "/hash/:key/:field/increment_float",
            post(increment_hash_field_float_handler),
        )
        .route(
            "/hash/:key/:field/setnx",
            post(set_hash_field_if_not_exists_handler),
        )
        // Hash operations
        .route("/hash/:key", get(get_all_hash_fields_handler))
        .route("/hash/:key/fields", post(get_hash_fields_handler))
        .route("/hash/:key/batch", post(set_multiple_hash_fields_handler))
        .route("/hash/:key/length", get(get_hash_length_handler))
        .route("/hash/:key/keys", get(get_hash_keys_handler))
        .route("/hash/:key/values", get(get_hash_values_handler))
        .route("/hash/:key/random", get(get_random_hash_field_handler))
        .route(
            "/hash/:key/random_fields",
            post(get_random_hash_fields_handler),
        )
        .route(
            "/hash/:key/random_fields_with_values",
            post(get_random_hash_fields_with_values_handler),
        )
        // Hash management
        .route("/hash/:key", delete(delete_hash_handler))
        .route("/hash/:key/exists", get(hash_exists_key_handler))
        .route("/hash/:key/ttl", get(get_hash_ttl_handler))
        .route("/hash/:key/ttl", post(set_hash_ttl_handler))
        // Batch operations
        .route("/hash/batch/get", post(batch_get_hash_fields_handler))
        .route("/hash/batch/set", post(batch_set_hash_fields_handler))
        .route("/hash/batch/delete", post(batch_delete_hash_fields_handler))
        .route("/hash/batch/exists", post(batch_check_hash_fields_handler))
        .route("/hash/batch/lengths", post(batch_get_hash_lengths_handler))
        .with_state(pool)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use dbx_adapter::redis::client::RedisPool;
    use std::sync::Arc;

    // Helper function to create a test app with routes
    fn create_test_app() -> Router {
        let pool = Arc::new(RedisPool::new("redis://localhost:6379", 1).unwrap());
        create_redis_hash_routes(pool)
    }

    #[test]
    fn test_set_hash_field_request_structure() {
        let request = SetHashFieldRequest {
            value: "test_value".to_string(),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("test_value"));

        let deserialized: SetHashFieldRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.value, "test_value");
    }

    #[test]
    fn test_set_multiple_hash_fields_request_structure() {
        let mut fields = std::collections::HashMap::new();
        fields.insert("field1".to_string(), "value1".to_string());
        fields.insert("field2".to_string(), "value2".to_string());

        let request = SetMultipleHashFieldsRequest { fields };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: SetMultipleHashFieldsRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.fields.len(), 2);
        assert_eq!(
            deserialized.fields.get("field1"),
            Some(&"value1".to_string())
        );
    }

    #[test]
    fn test_get_hash_fields_request_structure() {
        let request = GetHashFieldsRequest {
            fields: vec!["field1".to_string(), "field2".to_string()],
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: GetHashFieldsRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.fields, vec!["field1", "field2"]);
    }

    #[test]
    fn test_increment_hash_field_request_structure() {
        let request = IncrementHashFieldRequest { increment: 42 };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: IncrementHashFieldRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.increment, 42);

        // Test negative increment
        let request = IncrementHashFieldRequest { increment: -10 };
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: IncrementHashFieldRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.increment, -10);
    }

    #[test]
    fn test_increment_hash_field_float_request_structure() {
        let request = IncrementHashFieldFloatRequest { increment: 3.14 };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: IncrementHashFieldFloatRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.increment, 3.14);

        // Test negative float increment
        let request = IncrementHashFieldFloatRequest { increment: -2.5 };
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: IncrementHashFieldFloatRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.increment, -2.5);
    }

    #[test]
    fn test_get_random_hash_fields_request_structure() {
        let request = GetRandomHashFieldsRequest { count: 5 };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: GetRandomHashFieldsRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.count, 5);

        // Test negative count
        let request = GetRandomHashFieldsRequest { count: -3 };
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: GetRandomHashFieldsRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.count, -3);
    }

    #[test]
    fn test_get_random_hash_fields_with_values_request_structure() {
        let request = GetRandomHashFieldsWithValuesRequest { count: 10 };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: GetRandomHashFieldsWithValuesRequest =
            serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.count, 10);
    }

    #[test]
    fn test_set_hash_ttl_request_structure() {
        let request = SetHashTtlRequest { ttl: 3600 };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: SetHashTtlRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.ttl, 3600);

        // Test zero TTL
        let request = SetHashTtlRequest { ttl: 0 };
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: SetHashTtlRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.ttl, 0);
    }

    #[test]
    fn test_batch_get_hash_fields_request_structure() {
        let request = BatchGetHashFieldsRequest {
            hash_fields: vec![
                ("hash1".to_string(), "field1".to_string()),
                ("hash2".to_string(), "field2".to_string()),
            ],
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: BatchGetHashFieldsRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.hash_fields.len(), 2);
        assert_eq!(
            deserialized.hash_fields[0],
            ("hash1".to_string(), "field1".to_string())
        );
    }

    #[test]
    fn test_batch_set_hash_fields_request_structure() {
        let request = BatchSetHashFieldsRequest {
            hash_operations: vec![
                (
                    "hash1".to_string(),
                    vec![
                        ("field1".to_string(), "value1".to_string()),
                        ("field2".to_string(), "value2".to_string()),
                    ],
                ),
                (
                    "hash2".to_string(),
                    vec![("field3".to_string(), "value3".to_string())],
                ),
            ],
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: BatchSetHashFieldsRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.hash_operations.len(), 2);
        assert_eq!(deserialized.hash_operations[0].0, "hash1");
        assert_eq!(deserialized.hash_operations[0].1.len(), 2);
    }

    #[test]
    fn test_batch_delete_hash_fields_request_structure() {
        let request = BatchDeleteHashFieldsRequest {
            hash_fields: vec![
                (
                    "hash1".to_string(),
                    vec!["field1".to_string(), "field2".to_string()],
                ),
                ("hash2".to_string(), vec!["field3".to_string()]),
            ],
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: BatchDeleteHashFieldsRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.hash_fields.len(), 2);
        assert_eq!(deserialized.hash_fields[0].1.len(), 2);
    }

    #[test]
    fn test_batch_check_hash_fields_request_structure() {
        let request = BatchCheckHashFieldsRequest {
            hash_fields: vec![
                ("hash1".to_string(), "field1".to_string()),
                ("hash2".to_string(), "field2".to_string()),
            ],
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: BatchCheckHashFieldsRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.hash_fields.len(), 2);
    }

    #[test]
    fn test_batch_get_hash_lengths_request_structure() {
        let request = BatchGetHashLengthsRequest {
            keys: vec![
                "hash1".to_string(),
                "hash2".to_string(),
                "hash3".to_string(),
            ],
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: BatchGetHashLengthsRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.keys, vec!["hash1", "hash2", "hash3"]);
    }

    #[test]
    fn test_request_deserialization_errors() {
        // Test invalid JSON for SetHashFieldRequest
        let invalid_json = r#"{"value": 123}"#;
        let result = serde_json::from_str::<SetHashFieldRequest>(invalid_json);
        assert!(result.is_err());

        // Test missing required fields
        let incomplete_json = r#"{}"#;
        let result = serde_json::from_str::<SetHashFieldRequest>(incomplete_json);
        assert!(result.is_err());

        // Test invalid increment type
        let invalid_increment = r#"{"increment": "not_a_number"}"#;
        let result = serde_json::from_str::<IncrementHashFieldRequest>(invalid_increment);
        assert!(result.is_err());
    }

    #[test]
    fn test_debug_implementations() {
        let set_request = SetHashFieldRequest {
            value: "debug_test".to_string(),
        };
        let debug_str = format!("{:?}", set_request);
        assert!(debug_str.contains("SetHashFieldRequest"));
        assert!(debug_str.contains("debug_test"));

        let increment_request = IncrementHashFieldRequest { increment: 42 };
        let debug_str = format!("{:?}", increment_request);
        assert!(debug_str.contains("IncrementHashFieldRequest"));
        assert!(debug_str.contains("42"));

        let float_request = IncrementHashFieldFloatRequest { increment: 3.14 };
        let debug_str = format!("{:?}", float_request);
        assert!(debug_str.contains("IncrementHashFieldFloatRequest"));
        assert!(debug_str.contains("3.14"));
    }

    #[test]
    fn test_edge_case_values() {
        // Test empty field name and value
        let request = SetHashFieldRequest {
            value: "".to_string(),
        };
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: SetHashFieldRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.value, "");

        // Test empty fields array
        let request = GetHashFieldsRequest { fields: vec![] };
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: GetHashFieldsRequest = serde_json::from_str(&json).unwrap();
        assert!(deserialized.fields.is_empty());

        // Test zero count
        let request = GetRandomHashFieldsRequest { count: 0 };
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: GetRandomHashFieldsRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.count, 0);
    }

    #[test]
    fn test_special_characters_in_hash_fields() {
        let mut fields = std::collections::HashMap::new();
        fields.insert("field:with:colons".to_string(), "value1".to_string());
        fields.insert("field-with-dashes".to_string(), "value2".to_string());
        fields.insert("field_with_underscores".to_string(), "value3".to_string());
        fields.insert("field.with.dots".to_string(), "value4".to_string());

        let request = SetMultipleHashFieldsRequest { fields };
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: SetMultipleHashFieldsRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.fields.len(), 4);
        assert!(deserialized.fields.contains_key("field:with:colons"));
        assert!(deserialized.fields.contains_key("field.with.dots"));
    }

    #[test]
    fn test_unicode_hash_values() {
        let request = SetHashFieldRequest {
            value: "Hello 世界 🌍 Здравствуй мир".to_string(),
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: SetHashFieldRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.value, "Hello 世界 🌍 Здравствуй мир");
    }

    #[test]
    fn test_large_batch_hash_operations() {
        // Test large number of hash operations
        let mut hash_operations = Vec::new();
        for i in 0..100 {
            let mut fields = Vec::new();
            for j in 0..10 {
                fields.push((format!("field_{}", j), format!("value_{}_{}", i, j)));
            }
            hash_operations.push((format!("hash_{}", i), fields));
        }

        let request = BatchSetHashFieldsRequest { hash_operations };
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: BatchSetHashFieldsRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.hash_operations.len(), 100);
        assert_eq!(deserialized.hash_operations[0].1.len(), 10);
    }

    #[test]
    fn test_extreme_numeric_values() {
        // Test maximum i64 value
        let request = IncrementHashFieldRequest {
            increment: i64::MAX,
        };
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: IncrementHashFieldRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.increment, i64::MAX);

        // Test minimum i64 value
        let request = IncrementHashFieldRequest {
            increment: i64::MIN,
        };
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: IncrementHashFieldRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.increment, i64::MIN);

        // Test extreme float values
        let request = IncrementHashFieldFloatRequest {
            increment: f64::MAX,
        };
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: IncrementHashFieldFloatRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.increment, f64::MAX);
    }

    #[test]
    fn test_empty_hash_operations() {
        // Test empty hash operations
        let request = BatchSetHashFieldsRequest {
            hash_operations: vec![],
        };
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: BatchSetHashFieldsRequest = serde_json::from_str(&json).unwrap();
        assert!(deserialized.hash_operations.is_empty());

        // Test empty hash fields for deletion
        let request = BatchDeleteHashFieldsRequest {
            hash_fields: vec![],
        };
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: BatchDeleteHashFieldsRequest = serde_json::from_str(&json).unwrap();
        assert!(deserialized.hash_fields.is_empty());
    }

    #[test]
    fn test_mixed_data_types_in_values() {
        let mut fields = std::collections::HashMap::new();
        fields.insert("number_field".to_string(), "42".to_string());
        fields.insert("boolean_field".to_string(), "true".to_string());
        fields.insert("json_field".to_string(), r#"{"key": "value"}"#.to_string());
        fields.insert("empty_field".to_string(), "".to_string());

        let request = SetMultipleHashFieldsRequest { fields };
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: SetMultipleHashFieldsRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(
            deserialized.fields.get("number_field"),
            Some(&"42".to_string())
        );
        assert_eq!(
            deserialized.fields.get("json_field"),
            Some(&r#"{"key": "value"}"#.to_string())
        );
    }
}
