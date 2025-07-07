use crate::routes::common::admin::{
    config_get, config_get_all, config_reset_statistics, config_rewrite, config_set,
    flush_all_databases, flush_current_database, get_client_stats, get_database_size,
    get_memory_stats, get_server_info, get_server_info_section, get_server_stats, get_server_time,
    get_server_version, health_check, ping_server, server_status,
};
use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
    routing::{get, post},
    Router,
};
use dbx_adapter::redis::client::RedisPool;
use dbx_adapter::redis::primitives::admin::{HealthCheck, ServerStatus};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
struct ConfigSetPayload {
    parameter: String,
    value: String,
}

// =========================
// Basic Health & Status Handlers
// =========================

async fn ping_handler(State(pool): State<Arc<RedisPool>>) -> Result<Json<String>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let response = ping_server(conn_arc).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(response))
}

async fn info_handler(State(pool): State<Arc<RedisPool>>) -> Result<Json<String>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let info = get_server_info(conn_arc).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(info))
}

async fn info_section_handler(
    State(pool): State<Arc<RedisPool>>,
    Path(section): Path<String>,
) -> Result<Json<String>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let info = get_server_info_section(conn_arc, &section)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(info))
}

async fn dbsize_handler(State(pool): State<Arc<RedisPool>>) -> Result<Json<i64>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let size = get_database_size(conn_arc).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(size))
}

async fn time_handler(State(pool): State<Arc<RedisPool>>) -> Result<Json<(i64, i64)>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let time = get_server_time(conn_arc).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(time))
}

async fn version_handler(State(pool): State<Arc<RedisPool>>) -> Result<Json<String>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let version = get_server_version(conn_arc).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(version))
}

// =========================
// Health Check Handlers
// =========================

async fn health_check_handler(
    State(pool): State<Arc<RedisPool>>,
) -> Result<Json<HealthCheck>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let health = health_check(conn_arc).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(health))
}

async fn server_status_handler(
    State(pool): State<Arc<RedisPool>>,
) -> Result<Json<ServerStatus>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let status = server_status(conn_arc).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(status))
}

// =========================
// Statistics Handlers
// =========================

async fn memory_stats_handler(
    State(pool): State<Arc<RedisPool>>,
) -> Result<Json<HashMap<String, String>>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let stats = get_memory_stats(conn_arc).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(stats))
}

async fn client_stats_handler(
    State(pool): State<Arc<RedisPool>>,
) -> Result<Json<HashMap<String, String>>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let stats = get_client_stats(conn_arc).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(stats))
}

async fn server_stats_handler(
    State(pool): State<Arc<RedisPool>>,
) -> Result<Json<HashMap<String, String>>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let stats = get_server_stats(conn_arc).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(stats))
}

// =========================
// Configuration Handlers
// =========================

async fn config_set_handler(
    State(pool): State<Arc<RedisPool>>,
    Json(payload): Json<ConfigSetPayload>,
) -> Result<StatusCode, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    config_set(conn_arc, &payload.parameter, &payload.value)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::OK)
}

async fn config_get_handler(
    State(pool): State<Arc<RedisPool>>,
    Path(parameter): Path<String>,
) -> Result<Json<String>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let value = config_get(conn_arc, &parameter).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(value))
}

async fn config_get_all_handler(
    State(pool): State<Arc<RedisPool>>,
) -> Result<Json<HashMap<String, String>>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let config = config_get_all(conn_arc).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(config))
}

async fn config_reset_statistics_handler(
    State(pool): State<Arc<RedisPool>>,
) -> Result<StatusCode, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    config_reset_statistics(conn_arc).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::OK)
}

async fn config_rewrite_handler(
    State(pool): State<Arc<RedisPool>>,
) -> Result<StatusCode, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    config_rewrite(conn_arc).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::OK)
}

// =========================
// Database Management Handlers
// =========================

async fn flush_current_database_handler(
    State(pool): State<Arc<RedisPool>>,
) -> Result<StatusCode, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    flush_current_database(conn_arc).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::OK)
}

async fn flush_all_databases_handler(
    State(pool): State<Arc<RedisPool>>,
) -> Result<StatusCode, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    flush_all_databases(conn_arc).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::OK)
}

pub fn create_redis_admin_routes(pool: Arc<RedisPool>) -> Router {
    Router::new()
        .route("/ping", post(ping_handler))
        .route("/info", post(info_handler))
        .route("/info/:section", get(info_section_handler))
        .route("/dbsize", get(dbsize_handler))
        .route("/time", get(time_handler))
        .route("/version", get(version_handler))
        .route("/health", get(health_check_handler))
        .route("/status", get(server_status_handler))
        .route("/stats/memory", get(memory_stats_handler))
        .route("/stats/client", get(client_stats_handler))
        .route("/stats/server", get(server_stats_handler))
        .route("/config/set", post(config_set_handler))
        .route("/config/get/:parameter", get(config_get_handler))
        .route("/config/all", get(config_get_all_handler))
        .route("/config/resetstat", post(config_reset_statistics_handler))
        .route("/config/rewrite", post(config_rewrite_handler))
        .route("/flushdb", post(flush_current_database_handler))
        .route("/flushall", post(flush_all_databases_handler))
        .with_state(pool)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use dbx_adapter::redis::client::RedisPool;
    use serde_json::json;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn create_test_app() -> Router {
        let pool = Arc::new(RedisPool::new("redis://localhost:6379", 10).unwrap());
        create_redis_admin_routes(pool)
    }

    #[tokio::test]
    async fn test_ping_endpoint_success() {
        let app = create_test_app();
        let request = Request::builder()
            .method(Method::POST)
            .uri("/ping")
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_info_endpoint_success() {
        let app = create_test_app();
        let request = Request::builder()
            .method(Method::POST)
            .uri("/info")
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_info_section_endpoint() {
        let app = create_test_app();
        let request = Request::builder()
            .method(Method::GET)
            .uri("/info/server")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_dbsize_endpoint() {
        let app = create_test_app();
        let request = Request::builder()
            .method(Method::GET)
            .uri("/dbsize")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_time_endpoint() {
        let app = create_test_app();
        let request = Request::builder()
            .method(Method::GET)
            .uri("/time")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_version_endpoint() {
        let app = create_test_app();
        let request = Request::builder()
            .method(Method::GET)
            .uri("/version")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let app = create_test_app();
        let request = Request::builder()
            .method(Method::GET)
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_status_endpoint() {
        let app = create_test_app();
        let request = Request::builder()
            .method(Method::GET)
            .uri("/status")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_memory_stats_endpoint() {
        let app = create_test_app();
        let request = Request::builder()
            .method(Method::GET)
            .uri("/stats/memory")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_client_stats_endpoint() {
        let app = create_test_app();
        let request = Request::builder()
            .method(Method::GET)
            .uri("/stats/client")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_server_stats_endpoint() {
        let app = create_test_app();
        let request = Request::builder()
            .method(Method::GET)
            .uri("/stats/server")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_config_set_endpoint() {
        let app = create_test_app();
        let payload = json!({
            "parameter": "timeout",
            "value": "300"
        });
        let request = Request::builder()
            .method(Method::POST)
            .uri("/config/set")
            .header("content-type", "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_config_get_endpoint() {
        let app = create_test_app();
        let request = Request::builder()
            .method(Method::GET)
            .uri("/config/get/timeout")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_config_get_all_endpoint() {
        let app = create_test_app();
        let request = Request::builder()
            .method(Method::GET)
            .uri("/config/all")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_config_resetstat_endpoint() {
        let app = create_test_app();
        let request = Request::builder()
            .method(Method::POST)
            .uri("/config/resetstat")
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_config_rewrite_endpoint() {
        let app = create_test_app();
        let request = Request::builder()
            .method(Method::POST)
            .uri("/config/rewrite")
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_flushdb_endpoint() {
        let app = create_test_app();
        let request = Request::builder()
            .method(Method::POST)
            .uri("/flushdb")
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_flushall_endpoint() {
        let app = create_test_app();
        let request = Request::builder()
            .method(Method::POST)
            .uri("/flushall")
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_route_creation() {
        let pool = Arc::new(RedisPool::new("redis://localhost:6379", 10).unwrap());
        let _router = create_redis_admin_routes(pool);
        assert!(true);
    }

    #[tokio::test]
    async fn test_invalid_config_parameter() {
        let app = create_test_app();
        let request = Request::builder()
            .method(Method::GET)
            .uri("/config/get/invalid_parameter_name_12345")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        // Should still return OK but with empty or error response
        assert!(response.status().is_success() || response.status().is_client_error());
    }

    #[tokio::test]
    async fn test_config_set_invalid_json() {
        let app = create_test_app();
        let request = Request::builder()
            .method(Method::POST)
            .uri("/config/set")
            .header("content-type", "application/json")
            .body(Body::from("invalid json"))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_ping_invalid_json() {
        let app = create_test_app();
        let request = Request::builder()
            .method(Method::POST)
            .uri("/ping")
            .header("content-type", "application/json")
            .body(Body::from("invalid json"))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_method_not_allowed() {
        let app = create_test_app();
        let request = Request::builder()
            .method(Method::DELETE)
            .uri("/ping")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
}
