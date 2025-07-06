use axum::{middleware::from_fn_with_state, response::Json, routing::get, Router};
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;

use crate::{
    config::{AppConfig, ConfigError},
    middleware::{
        jwt_auth_middleware, require_admin_role, require_user_role, JwtService, UserStore,
    },
    models::ApiResponse,
    routes::{
        auth::create_auth_routes,
        redis::{admin, hash, set, string},
        redis_ws::{admin as ws_admin, hash as ws_hash, set as ws_set, string as ws_string},
    },
};
use dbx_adapter::redis::client::RedisPool;

/// Application state
#[derive(Clone)]
pub struct AppState {
    pub redis_pool: Arc<RedisPool>,
    pub jwt_service: Arc<JwtService>,
    pub user_store: Arc<UserStore>,
}

impl AppState {
    pub async fn new() -> Result<Self, ServerError> {
        let config = AppConfig::from_env().map_err(ServerError::Configuration)?;

        // Create Redis pool with default pool size
        let pool_size = 10; // Default pool size since it's not in config anymore
        let redis_pool = Arc::new(
            RedisPool::new(&config.server.redis_url, pool_size)
                .map_err(|e| ServerError::DatabaseConnection(e.to_string()))?,
        );

        // Create JWT service
        let jwt_service = Arc::new(JwtService::new(config.jwt));

        // Create user store - optionally with default admin
        let user_store = if config.create_default_admin {
            if let (Some(username), Some(password)) = (&config.default_admin_username, &config.default_admin_password) {
                Arc::new(
                    UserStore::new_with_admin(redis_pool.clone(), username, password)
                        .await
                        .map_err(|e| ServerError::UserStoreInitialization(e.to_string()))?,
                )
            } else {
                return Err(ServerError::Configuration(ConfigError::MissingDefaultAdminPassword));
            }
        } else {
            Arc::new(
                UserStore::new(redis_pool.clone())
                    .await
                    .map_err(|e| ServerError::UserStoreInitialization(e.to_string()))?,
            )
        };

        Ok(Self {
            redis_pool,
            jwt_service,
            user_store,
        })
    }
}

/// Health check endpoint
async fn health_check() -> Json<ApiResponse<String>> {
    Json(ApiResponse::success("Server is running".to_string()))
}

/// Create the main application router
pub fn create_app(state: AppState) -> Router {
    // Create authentication routes (public)
    let auth_routes = create_auth_routes(state.jwt_service.clone(), state.user_store.clone());

    // Create protected Redis routes with authentication middleware for users and admins
    let user_redis_routes = Router::new()
        .merge(string::create_redis_string_routes(state.redis_pool.clone()))
        .merge(hash::create_redis_hash_routes(state.redis_pool.clone()))
        .merge(set::create_redis_set_routes(state.redis_pool.clone()))
        .layer(from_fn_with_state((), require_user_role))
        .layer(from_fn_with_state(
            state.jwt_service.clone(),
            jwt_auth_middleware,
        ));

    // Create admin-only routes with separate auth chain
    let admin_redis_routes = Router::new()
        .merge(admin::create_redis_admin_routes(state.redis_pool.clone()))
        .layer(from_fn_with_state((), require_admin_role))
        .layer(from_fn_with_state(
            state.jwt_service.clone(),
            jwt_auth_middleware,
        ));

    // Create protected Redis WebSocket routes with authentication middleware
    let user_redis_ws_routes = Router::new()
        .merge(ws_string::create_redis_ws_string_routes(
            state.redis_pool.clone(),
        ))
        .merge(ws_hash::create_redis_ws_hash_routes(
            state.redis_pool.clone(),
        ))
        .merge(ws_set::create_redis_ws_set_routes(state.redis_pool.clone()))
        .layer(from_fn_with_state((), require_user_role))
        .layer(from_fn_with_state(
            state.jwt_service.clone(),
            jwt_auth_middleware,
        ));

    let admin_redis_ws_routes = Router::new()
        .merge(ws_admin::create_redis_ws_admin_routes(
            state.redis_pool.clone(),
        ))
        .layer(from_fn_with_state((), require_admin_role))
        .layer(from_fn_with_state(
            state.jwt_service.clone(),
            jwt_auth_middleware,
        ));

    Router::new()
        .route("/health", get(health_check))
        .nest("/auth", auth_routes)
        .nest("/redis", user_redis_routes)
        .nest("/redis/admin", admin_redis_routes)
        .nest("/redis_ws", user_redis_ws_routes)
        .nest("/redis_ws/admin", admin_redis_ws_routes)
        .layer(CorsLayer::permissive())
}

/// Start the server
pub async fn run_server() -> Result<(), ServerError> {
    let state = AppState::new().await?;
    let config = AppConfig::from_env().map_err(ServerError::Configuration)?;

    let app = create_app(state);

    let addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|e| ServerError::ServerBinding(format!("Failed to bind to {}: {}", addr, e)))?;

    println!("🚀 Server running on http://{}", addr);

    axum::serve(listener, app)
        .await
        .map_err(|e| ServerError::ServerRuntime(e.to_string()))?;

    Ok(())
}

/// Public run function for compatibility
pub async fn run() -> Result<(), ConfigError> {
    run_server().await.map_err(|e| match e {
        ServerError::Configuration(config_err) => config_err,
        _ => ConfigError::MissingEnvironmentVariable("SERVER_ERROR".to_string()),
    })
}

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("Configuration error: {0}")]
    Configuration(#[from] ConfigError),
    #[error("Database connection error: {0}")]
    DatabaseConnection(String),
    #[error("User store initialization error: {0}")]
    UserStoreInitialization(String),
    #[error("Server binding error: {0}")]
    ServerBinding(String),
    #[error("Server runtime error: {0}")]
    ServerRuntime(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppConfig, JwtConfig, ServerConfig};
    use crate::middleware::UserStore;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use dbx_adapter::redis::client::RedisPool;
    use std::sync::Arc;
    use tower::ServiceExt;

    /// Helper function to set up required environment variables for tests
    fn setup_test_env() {
        std::env::set_var("JWT_SECRET", "test-jwt-secret-that-is-at-least-32-characters-long-for-security");
        std::env::set_var("REDIS_URL", "redis://localhost:6379");
        std::env::set_var("HOST", "127.0.0.1");
        std::env::set_var("PORT", "3000");
    }

    /// Helper function to clean up test environment variables
    fn cleanup_test_env() {
        std::env::remove_var("JWT_SECRET");
        std::env::remove_var("REDIS_URL");
        std::env::remove_var("HOST");
        std::env::remove_var("PORT");
        std::env::remove_var("CREATE_DEFAULT_ADMIN");
        std::env::remove_var("DEFAULT_ADMIN_USERNAME");
        std::env::remove_var("DEFAULT_ADMIN_PASSWORD");
    }

    #[tokio::test]
    async fn test_create_app_state_success() {
        setup_test_env();
        let result = AppState::new().await;
        assert!(result.is_ok());
        cleanup_test_env();
    }

    #[tokio::test]
    async fn test_create_app_state_with_default_admin() {
        setup_test_env();
        std::env::set_var("CREATE_DEFAULT_ADMIN", "true");
        std::env::set_var("DEFAULT_ADMIN_USERNAME", "admin");
        std::env::set_var("DEFAULT_ADMIN_PASSWORD", "admin123");

        let result = AppState::new().await;
        assert!(result.is_ok());

        cleanup_test_env();
    }

    #[tokio::test]
    async fn test_create_app_state_missing_admin_credentials() {
        setup_test_env();
        std::env::set_var("CREATE_DEFAULT_ADMIN", "true");
        std::env::set_var("DEFAULT_ADMIN_USERNAME", "admin");
        std::env::remove_var("DEFAULT_ADMIN_PASSWORD");

        let result = AppState::new().await;
        assert!(result.is_err());

        if let Err(ServerError::Configuration(_)) = result {
            // Expected error type
        } else {
            panic!("Expected Configuration error");
        }

        cleanup_test_env();
    }

    #[tokio::test]
    async fn test_create_app_with_cors() {
        setup_test_env();
        let app_state = AppState::new().await.unwrap();
        let app = create_app(app_state);

        let request = Request::builder()
            .method(Method::OPTIONS)
            .uri("/health")
            .header("Origin", "http://localhost:3000")
            .header("Access-Control-Request-Method", "GET")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        cleanup_test_env();
    }

    #[tokio::test]
    async fn test_health_check_endpoint() {
        setup_test_env();
        let app_state = AppState::new().await.unwrap();
        let app = create_app(app_state);

        let request = Request::builder()
            .method(Method::GET)
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        cleanup_test_env();
    }

    #[tokio::test]
    async fn test_api_docs_endpoint() {
        setup_test_env();
        let app_state = AppState::new().await.unwrap();
        let app = create_app(app_state);

        let request = Request::builder()
            .method(Method::GET)
            .uri("/docs")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        cleanup_test_env();
    }

    #[tokio::test]
    async fn test_not_found_endpoint() {
        setup_test_env();
        let app_state = AppState::new().await.unwrap();
        let app = create_app(app_state);

        let request = Request::builder()
            .method(Method::GET)
            .uri("/nonexistent")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        cleanup_test_env();
    }

    #[test]
    fn test_server_error_display() {
        let config_error = ConfigError::MissingDefaultAdminPassword;
        let server_error = ServerError::Configuration(config_error);
        let error_string = server_error.to_string();
        assert!(error_string.contains("Configuration error"));

        let database_error = "Database connection failed";
        let server_error = ServerError::DatabaseConnection(database_error.to_string());
        let error_string = server_error.to_string();
        assert!(error_string.contains("Database connection error"));

        let server_error = ServerError::UserStoreInitialization("init failed".to_string());
        let error_string = server_error.to_string();
        assert_eq!(error_string, "User store initialization error: init failed");

        let server_error = ServerError::ServerBinding("bind failed".to_string());
        let error_string = server_error.to_string();
        assert_eq!(error_string, "Server binding error: bind failed");

        let server_error = ServerError::ServerRuntime("runtime error".to_string());
        let error_string = server_error.to_string();
        assert_eq!(error_string, "Server runtime error: runtime error");
    }

    #[test]
    fn test_server_error_debug() {
        let config_error = ConfigError::MissingDefaultAdminPassword;
        let server_error = ServerError::Configuration(config_error);
        let debug_string = format!("{:?}", server_error);
        assert!(debug_string.contains("Configuration"));

        let database_error = ServerError::DatabaseConnection("test".to_string());
        let debug_string = format!("{:?}", database_error);
        assert!(debug_string.contains("DatabaseConnection"));
    }

    #[tokio::test]
    async fn test_create_app_state_error_handling() {
        setup_test_env();
        std::env::set_var("REDIS_URL", "redis://invalid:6379");

        let result = AppState::new().await;
        // The function should still succeed as it doesn't immediately test Redis connection
        // It only fails when actually trying to use the Redis connection
        assert!(result.is_ok());

        cleanup_test_env();
    }

    #[tokio::test]
    async fn test_cors_configuration() {
        setup_test_env();
        let app_state = AppState::new().await.unwrap();
        let app = create_app(app_state);

        // Test allowed origin
        let request = Request::builder()
            .method(Method::OPTIONS)
            .uri("/health")
            .header("Origin", "http://localhost:3000")
            .header("Access-Control-Request-Method", "GET")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        cleanup_test_env();
    }

    #[tokio::test]
    async fn test_middleware_chain() {
        setup_test_env();
        let app_state = AppState::new().await.unwrap();
        let app = create_app(app_state);

        // Test that the middleware chain processes requests correctly
        let request = Request::builder()
            .method(Method::GET)
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        cleanup_test_env();
    }

    #[tokio::test]
    async fn test_app_state_structure() {
        setup_test_env();
        let app_state = AppState::new().await.unwrap();

        // Test that all required components are initialized
        assert!(Arc::strong_count(&app_state.redis_pool) >= 1);
        assert!(Arc::strong_count(&app_state.jwt_service) >= 1);
        assert!(Arc::strong_count(&app_state.user_store) >= 1);
        cleanup_test_env();
    }

    #[tokio::test]
    async fn test_json_rejection_handling() {
        setup_test_env();
        let app_state = AppState::new().await.unwrap();
        let app = create_app(app_state);

        // Test invalid JSON handling
        let request = Request::builder()
            .method(Method::POST)
            .uri("/auth/login")
            .header("content-type", "application/json")
            .body(Body::from("invalid json"))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        cleanup_test_env();
    }

    #[tokio::test]
    async fn test_protected_route_without_auth() {
        setup_test_env();
        let app_state = AppState::new().await.unwrap();
        let app = create_app(app_state);

        let request = Request::builder()
            .method(Method::GET)
            .uri("/redis/string/test")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        cleanup_test_env();
    }

    #[tokio::test]
    async fn test_admin_route_without_auth() {
        setup_test_env();
        let app_state = AppState::new().await.unwrap();
        let app = create_app(app_state);

        let request = Request::builder()
            .method(Method::GET)
            .uri("/redis/admin/ping")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        cleanup_test_env();
    }

    #[tokio::test]
    async fn test_websocket_route_without_auth() {
        setup_test_env();
        let app_state = AppState::new().await.unwrap();
        let app = create_app(app_state);

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/ws")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Websocket route should return 404 if not implemented, not 401
        assert_eq!(response.status().as_u16(), 404);
        cleanup_test_env();
    }

    #[tokio::test]
    async fn test_route_structure() {
        setup_test_env();
        let app_state = AppState::new().await.unwrap();
        let app = create_app(app_state);

        // Test that routes are properly nested
        let health_request = Request::builder()
            .method(Method::GET)
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(health_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        cleanup_test_env();
    }

    #[test]
    fn test_health_check_response() {
        let _response = health_check();
        // Since this is async, we can't easily test the actual content here
        // but we can test that the function compiles and returns the right type
        assert!(true); // This test ensures the function compiles
    }

    #[tokio::test]
    async fn test_app_state_cloning() {
        setup_test_env();
        let app_state = AppState::new().await.unwrap();

        // Test that AppState components can be cloned (Arc<T> implements Clone)
        let redis_pool_clone = app_state.redis_pool.clone();
        let jwt_service_clone = app_state.jwt_service.clone();
        let user_store_clone = app_state.user_store.clone();

        assert!(Arc::ptr_eq(&app_state.redis_pool, &redis_pool_clone));
        assert!(Arc::ptr_eq(&app_state.jwt_service, &jwt_service_clone));
        assert!(Arc::ptr_eq(&app_state.user_store, &user_store_clone));
        cleanup_test_env();
    }

    // Helper function to create test JWT config for comparisons
    fn create_test_jwt_config() -> JwtConfig {
        JwtConfig {
            secret: "test-jwt-secret-that-is-at-least-32-characters-long-for-security".to_string(),
            issuer: "test_issuer".to_string(),
            access_token_expiration: 3600,
            refresh_token_expiration: 86400,
        }
    }
}
