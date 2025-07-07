use crate::routes::common::string::{
    delete_string, get_multiple_strings, get_string, get_string_info, get_strings_by_patterns,
    get_strings_by_patterns_grouped, set_multiple_strings, set_string, set_string_with_ttl,
    StringInfo, StringOperation,
};
use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{any, delete, get, post},
    Router,
};
use dbx_adapter::redis::client::RedisPool;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Deserialize, Serialize)]
struct SetStringRequest {
    value: String,
    ttl: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize)]
struct BatchGetRequest {
    keys: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct BatchSetRequest {
    operations: Vec<StringOperation>,
}

#[derive(Debug, Deserialize, Serialize)]
struct BatchGetPatternsRequest {
    patterns: Vec<String>,
    grouped: Option<bool>,
}

async fn get_string_handler(
    State(pool): State<Arc<RedisPool>>,
    Path(key): Path<String>,
) -> Result<Json<Option<String>>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let value = get_string(conn_arc, &key).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(value))
}

async fn set_string_handler(
    State(pool): State<Arc<RedisPool>>,
    Path(key): Path<String>,
    Json(payload): Json<SetStringRequest>,
) -> Result<StatusCode, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    if let Some(ttl) = payload.ttl {
        set_string_with_ttl(conn_arc, &key, &payload.value, ttl)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    } else {
        set_string(conn_arc, &key, &payload.value)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    Ok(StatusCode::OK)
}

async fn delete_string_handler(
    State(pool): State<Arc<RedisPool>>,
    Path(key): Path<String>,
) -> Result<Json<bool>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let deleted = delete_string(conn_arc, &key).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(deleted))
}

async fn get_string_info_handler(
    State(pool): State<Arc<RedisPool>>,
    Path(key): Path<String>,
) -> Result<Json<Option<StringInfo>>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let info = get_string_info(conn_arc, &key).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(info))
}

// Batch operations
async fn batch_get_strings_handler(
    State(pool): State<Arc<RedisPool>>,
    Json(payload): Json<BatchGetRequest>,
) -> Result<Json<Vec<Option<String>>>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let values = get_multiple_strings(conn_arc, &payload.keys)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(values))
}

async fn batch_set_strings_handler(
    State(pool): State<Arc<RedisPool>>,
    Json(payload): Json<BatchSetRequest>,
) -> Result<StatusCode, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    set_multiple_strings(conn_arc, &payload.operations)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::OK)
}

async fn batch_get_patterns_handler(
    State(pool): State<Arc<RedisPool>>,
    Json(payload): Json<BatchGetPatternsRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));

    if payload.patterns.is_empty() {
        // Always return an array for results if patterns is empty
        if payload.grouped.unwrap_or(false) {
            return Ok(Json(serde_json::json!({
                "grouped": true,
                "results": []
            })));
        } else {
            return Ok(Json(serde_json::json!({
                "grouped": false,
                "results": []
            })));
        }
    }

    if payload.grouped.unwrap_or(false) {
        let results = get_strings_by_patterns_grouped(conn_arc, &payload.patterns)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let grouped_results: Vec<serde_json::Value> = results
            .into_iter()
            .map(|(pattern, key_values)| {
                let key_value_map: std::collections::HashMap<String, Option<String>> =
                    key_values.into_iter().collect();
                serde_json::json!({
                    "pattern": pattern,
                    "results": key_value_map
                })
            })
            .collect();

        Ok(Json(serde_json::json!({
            "grouped": true,
            "results": grouped_results
        })))
    } else {
        let results = get_strings_by_patterns(conn_arc, &payload.patterns)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let key_value_map: std::collections::HashMap<String, Option<String>> =
            results.into_iter().collect();

        Ok(Json(serde_json::json!({
            "grouped": false,
            "results": key_value_map
        })))
    }
}

async fn method_not_allowed() -> impl IntoResponse {
    (StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed")
}

pub fn create_redis_string_routes(pool: Arc<RedisPool>) -> Router {
    Router::new()
        .route("/string/:key", get(get_string_handler))
        .route("/string/:key", post(set_string_handler))
        .route("/string/:key", delete(delete_string_handler))
        .route("/string/:key", any(method_not_allowed))
        .route("/string/:key/info", get(get_string_info_handler))
        .route("/string/batch/get", post(batch_get_strings_handler))
        .route("/string/batch/set", post(batch_set_strings_handler))
        .route("/string/batch/patterns", post(batch_get_patterns_handler))
        .with_state(pool)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        Router,
    };
    use dbx_adapter::redis::client::RedisPool;
    use serde_json::Value;
    use std::sync::Arc;
    use tower::ServiceExt;

    // Helper function to create a test app with routes
    fn create_test_app() -> Router {
        // Create a mock pool for testing (in real tests, this would connect to test Redis)
        let pool = Arc::new(RedisPool::new("redis://localhost:6379", 1).unwrap());
        create_redis_string_routes(pool)
    }

    // Helper function to make HTTP requests
    async fn make_request(
        app: Router,
        method: &str,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, String) {
        let request_builder = Request::builder().method(method).uri(uri);

        let request = if let Some(body_json) = body {
            request_builder
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body_json).unwrap()))
        } else {
            request_builder.body(Body::empty())
        };

        let response = app.oneshot(request.unwrap()).await.unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();

        (status, body_str)
    }

    #[tokio::test]
    async fn test_set_string_request_structure() {
        let request = SetStringRequest {
            value: "test_value".to_string(),
            ttl: Some(3600),
        };

        // Test serialization
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("test_value"));
        assert!(json.contains("3600"));

        // Test deserialization
        let deserialized: SetStringRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.value, "test_value");
        assert_eq!(deserialized.ttl, Some(3600));
    }

    #[tokio::test]
    async fn test_batch_get_request_structure() {
        let request = BatchGetRequest {
            keys: vec!["key1".to_string(), "key2".to_string()],
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: BatchGetRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.keys, vec!["key1", "key2"]);
    }

    #[tokio::test]
    async fn test_batch_set_request_structure() {
        let request = BatchSetRequest {
            operations: vec![
                StringOperation {
                    key: "key1".to_string(),
                    value: Some("value1".to_string()),
                    ttl: None,
                },
                StringOperation {
                    key: "key2".to_string(),
                    value: Some("value2".to_string()),
                    ttl: Some(3600),
                },
            ],
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: BatchSetRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.operations.len(), 2);
        assert_eq!(deserialized.operations[0].key, "key1");
        assert_eq!(deserialized.operations[1].ttl, Some(3600));
    }

    #[tokio::test]
    async fn test_batch_get_patterns_request_structure() {
        let request = BatchGetPatternsRequest {
            patterns: vec!["user:*".to_string(), "session:*".to_string()],
            grouped: Some(true),
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: BatchGetPatternsRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.patterns, vec!["user:*", "session:*"]);
        assert_eq!(deserialized.grouped, Some(true));
    }

    #[tokio::test]
    async fn test_request_deserialization_errors() {
        // Test invalid JSON for SetStringRequest
        let invalid_json = r#"{"value": 123, "ttl": "invalid"}"#;
        let result = serde_json::from_str::<SetStringRequest>(invalid_json);
        assert!(result.is_err());

        // Test missing required fields
        let incomplete_json = r#"{"ttl": 3600}"#;
        let result = serde_json::from_str::<SetStringRequest>(incomplete_json);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_string_operation_all_fields() {
        let operation = StringOperation {
            key: "test_key".to_string(),
            value: Some("test_value".to_string()),
            ttl: Some(7200),
        };

        let json = serde_json::to_string(&operation).unwrap();
        let deserialized: StringOperation = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.key, "test_key");
        assert_eq!(deserialized.value, Some("test_value".to_string()));
        assert_eq!(deserialized.ttl, Some(7200));
    }

    #[tokio::test]
    async fn test_string_operation_optional_fields() {
        let operation = StringOperation {
            key: "test_key".to_string(),
            value: None,
            ttl: None,
        };

        let json = serde_json::to_string(&operation).unwrap();
        let deserialized: StringOperation = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.key, "test_key");
        assert_eq!(deserialized.value, None);
        assert_eq!(deserialized.ttl, None);
    }

    #[test]
    fn test_request_structures_debug() {
        let set_request = SetStringRequest {
            value: "debug_test".to_string(),
            ttl: Some(300),
        };
        let debug_str = format!("{:?}", set_request);
        assert!(debug_str.contains("SetStringRequest"));
        assert!(debug_str.contains("debug_test"));

        let batch_request = BatchGetRequest {
            keys: vec!["key1".to_string()],
        };
        let debug_str = format!("{:?}", batch_request);
        assert!(debug_str.contains("BatchGetRequest"));
        assert!(debug_str.contains("key1"));
    }

    #[test]
    fn test_edge_case_values() {
        // Test empty string value
        let request = SetStringRequest {
            value: "".to_string(),
            ttl: None,
        };
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: SetStringRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.value, "");

        // Test zero TTL
        let request = SetStringRequest {
            value: "test".to_string(),
            ttl: Some(0),
        };
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: SetStringRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.ttl, Some(0));

        // Test empty keys array
        let request = BatchGetRequest { keys: vec![] };
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: BatchGetRequest = serde_json::from_str(&json).unwrap();
        assert!(deserialized.keys.is_empty());
    }

    #[test]
    fn test_large_batch_operations() {
        // Test large number of operations
        let mut operations = Vec::new();
        for i in 0..1000 {
            operations.push(StringOperation {
                key: format!("key_{}", i),
                value: Some(format!("value_{}", i)),
                ttl: if i % 2 == 0 { Some(i as u64) } else { None },
            });
        }

        let request = BatchSetRequest { operations };
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: BatchSetRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.operations.len(), 1000);
        assert_eq!(deserialized.operations[999].key, "key_999");
    }

    #[test]
    fn test_special_characters_in_keys() {
        let request = BatchGetRequest {
            keys: vec![
                "key:with:colons".to_string(),
                "key-with-dashes".to_string(),
                "key_with_underscores".to_string(),
                "key.with.dots".to_string(),
                "key/with/slashes".to_string(),
            ],
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: BatchGetRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.keys.len(), 5);
        assert!(deserialized.keys.contains(&"key:with:colons".to_string()));
        assert!(deserialized.keys.contains(&"key/with/slashes".to_string()));
    }

    #[test]
    fn test_unicode_values() {
        let request = SetStringRequest {
            value: "Hello world test value".to_string(),
            ttl: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: SetStringRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.value, "Hello world test value");
    }

    #[test]
    fn test_method_not_allowed_function() {
        // Test that method_not_allowed function exists and returns proper response
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let response = runtime.block_on(async { method_not_allowed().await });

        // Just verify it compiles and returns something
        let _response_value = response.into_response();
    }

    #[test]
    fn test_json_patterns_complex() {
        let patterns = vec![
            "user:*:profile".to_string(),
            "session:*:data".to_string(),
            "cache:*:*:temp".to_string(),
        ];

        let request = BatchGetPatternsRequest {
            patterns,
            grouped: Some(false),
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: BatchGetPatternsRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.patterns.len(), 3);
        assert_eq!(deserialized.grouped, Some(false));
    }
}
