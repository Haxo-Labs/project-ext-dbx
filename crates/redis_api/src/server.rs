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
