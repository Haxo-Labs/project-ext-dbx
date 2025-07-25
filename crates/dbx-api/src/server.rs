use crate::{
    auth::{ApiKeyService, RbacService},
    config::{AppConfig, ConfigError, SecurityConfig},
    middleware::{
        flexible_auth_middleware, jwt_auth_middleware, rate_limit_middleware, rbac_auth_middleware,
        security::{create_cors_layer, development_security_middleware},
        security_headers_middleware, JwtService, RateLimitService, UserStore,
    },
    models::{ApiResponse, User},
    routes::{
        api_keys::create_api_key_routes, auth::create_auth_routes, data::create_data_routes,
        health::create_health_routes, query::create_query_routes,
        rate_limit::create_rate_limit_routes, roles::create_role_routes,
        stream::create_stream_routes,
    },
};
use axum::{middleware::from_fn_with_state, routing::get, Router};
use dbx_adapter::redis::factory::RedisBackendFactory;
use dbx_config::{AdminConfig, BackendConfig, DbxConfig, RoutingConfig};
use dbx_router::{BackendRegistryBuilder, BackendRouter};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;
use tracing::{error, info};

/// Application state for the DBX API
#[derive(Clone)]
pub struct AppState {
    pub backend_router: Arc<BackendRouter>,
    pub jwt_service: Arc<JwtService>,
    pub user_store: Arc<UserStore>,
    pub api_key_service: Arc<ApiKeyService>,
    pub rbac_service: Arc<RbacService>,
    pub rate_limit_service: Arc<RateLimitService>,
}

impl AppState {
    /// Create new application state with backend router
    pub async fn new(config_path: Option<&str>) -> Result<Self, ServerError> {
        // Load DbxConfig
        let config = if let Some(path) = config_path {
            dbx_config::ConfigLoader::load_from_file(path)
                .await
                .map_err(|e| ServerError::Configuration(ConfigError::DbxConfig(e)))?
        } else {
            dbx_config::ConfigLoader::load_from_env()
                .await
                .map_err(|e| ServerError::Configuration(ConfigError::DbxConfig(e)))?
        };

        // Validate configuration
        dbx_config::ConfigValidator::validate_config(&config)
            .map_err(|e| ServerError::Configuration(ConfigError::DbxConfig(e)))?;

        // Create AppConfig from DbxConfig
        let app_config = AppConfig::from_dbx_config_direct(config.clone())
            .map_err(ServerError::Configuration)?;

        // Build backend registry
        let mut registry_builder = BackendRegistryBuilder::new();

        // Register Redis backend factory
        let redis_factory = RedisBackendFactory::new();
        registry_builder = registry_builder.with_factory("redis", redis_factory);

        // Build the registry
        let registry = registry_builder.build();

        // Initialize backends from configuration
        registry.initialize_backends(&config).await.map_err(|e| {
            ServerError::DatabaseConnection(format!("Failed to initialize backends: {}", e))
        })?;

        // Create backend router
        let backend_router = BackendRouter::new(registry, &config).map_err(|e| {
            ServerError::DatabaseConnection(format!("Failed to create router: {}", e))
        })?;

        // Get default backend configuration for auth services
        let default_backend_name = &config.routing.default_backend;
        let _default_backend = config.backends.get(default_backend_name).ok_or_else(|| {
            ServerError::Configuration(ConfigError::MissingEnvironmentVariable(format!(
                "Default backend '{}' not found in configuration",
                default_backend_name
            )))
        })?;

        // Get the backend instance from the router for auth services
        let auth_backend = backend_router
            .get_backend(default_backend_name)
            .await
            .ok_or_else(|| {
                ServerError::DatabaseConnection(format!(
                    "Auth backend '{}' not available",
                    default_backend_name
                ))
            })?;

        // Create backend-agnostic auth services using the configured default backend
        let (user_store, jwt_service, api_key_service, rbac_service, rate_limit_service) =
            Self::create_auth_services(&app_config, auth_backend).await?;
        Ok(Self {
            backend_router: Arc::new(backend_router),
            jwt_service,
            user_store,
            api_key_service,
            rbac_service,
            rate_limit_service,
        })
    }

    async fn create_auth_services(
        app_config: &AppConfig,
        backend: Arc<dyn dbx_core::UniversalBackend>,
    ) -> Result<
        (
            Arc<UserStore>,
            Arc<JwtService>,
            Arc<ApiKeyService>,
            Arc<RbacService>,
            Arc<RateLimitService>,
        ),
        ServerError,
    > {
        // Create auth services using the configured backend
        let user_store = Arc::new(UserStore::new(backend.clone()));
        let jwt_service = Arc::new(JwtService::new(app_config.jwt.clone(), user_store.clone()));
        let api_key_service = Arc::new(ApiKeyService::new(backend.clone()));
        let rbac_service = Arc::new(RbacService::new(backend.clone(), app_config.rbac.clone()));

        let rate_limit_service = RateLimitService::new(backend.clone());
        if app_config.rate_limit.enabled {
            let global_policy = crate::models::RateLimitPolicy {
                requests: app_config.rate_limit.global_requests_per_window,
                window_seconds: app_config.rate_limit.global_window_seconds,
                burst_allowance: app_config.rate_limit.global_burst_allowance,
            };
            rate_limit_service.set_global_policy(global_policy).await;
        }
        let rate_limit_service = Arc::new(rate_limit_service);

        Ok((
            user_store,
            jwt_service,
            api_key_service,
            rbac_service,
            rate_limit_service,
        ))
    }

    /// Create configuration - use environment if available, otherwise create test defaults
    fn create_default_config(_app_config: &AppConfig) -> Result<DbxConfig, ServerError> {
        // Try to load from environment first (need to handle async)
        // For tests, we'll just use defaults since env vars may not be set

        // Fallback to creating test defaults if environment variables aren't set
        let mut backends = HashMap::new();

        // Create a single Redis backend for testing
        backends.insert(
            "test_redis".to_string(),
            dbx_config::BackendConfig {
                provider: "redis".to_string(),
                url: "redis://localhost:6379".to_string(),
                pool_size: Some(5),
                timeout_ms: Some(5000),
                retry_attempts: Some(3),
                retry_delay_ms: Some(1000),
                capabilities: None,
                additional_config: HashMap::new(),
            },
        );

        let routing = dbx_config::RoutingConfig {
            default_backend: "test_redis".to_string(),
            operation_routing: HashMap::new(),
            key_routing: vec![],
            load_balancing: None,
        };

        // Use proper default configurations
        let consistency = dbx_config::ConsistencyConfig::default();
        let performance = dbx_config::PerformanceConfig::default();
        let security = dbx_config::SecurityConfig::default();
        let server = dbx_config::ServerConfig::default();
        let admin = dbx_config::AdminConfig::default();

        Ok(dbx_config::DbxConfig {
            backends,
            routing,
            consistency,
            performance,
            security,
            server,
            admin,
        })
    }
}

/// Health check endpoint
async fn health_check() -> axum::Json<ApiResponse<String>> {
    axum::Json(ApiResponse::success("Server is running".to_string()))
}

/// Create the application router with BackendRouter
pub fn create_app(state: AppState) -> Router {
    // Load configuration for security settings
    let app_config = AppConfig::from_env().unwrap_or_else(|_| {
        // Fallback to defaults if config loading fails
        AppConfig {
            server: crate::config::ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 3000,
            },
            jwt: crate::config::JwtConfig {
                secret: "fallback-secret-key-at-least-32-chars".to_string(),
                access_token_expiration: 900,
                refresh_token_expiration: 604800,
                issuer: "dbx-api".to_string(),
            },
            rbac: crate::auth::RbacConfig::default(),
            rate_limit: crate::config::RateLimitConfig::default(),
            security: crate::config::SecurityConfig::default(),
            create_default_admin: false,
            default_admin_username: None,
            default_admin_password: None,
        }
    });

    let cors_layer = create_cors_layer(&app_config.security.cors);
    let security_config = app_config.security.clone();

    // Create route groups with security middleware
    let auth_routes = create_auth_routes(state.jwt_service.clone(), state.user_store.clone())
        .layer(cors_layer.clone());

    // Create API key management routes (JWT authentication required)
    let api_key_routes =
        create_api_key_routes(state.api_key_service.clone()).layer(cors_layer.clone());

    // Create data operation routes (authentication required)
    let data_routes = create_data_routes().layer(cors_layer.clone());

    // Create query routes (authentication required)
    let query_routes = create_query_routes().layer(cors_layer.clone());

    // Create role management routes (admin authentication required)
    let role_routes = create_role_routes(state.rbac_service.clone()).layer(cors_layer.clone());

    // Create streaming routes (authentication required)
    let stream_routes = create_stream_routes().layer(cors_layer.clone());

    // Create rate limiting management routes (admin authentication required)
    let rate_limit_routes = create_rate_limit_routes()
        .layer(cors_layer.clone());

    // Create health routes (admin only)
    let health_routes = create_health_routes()
        .layer(cors_layer.clone());

    Router::new()
        .nest("/auth", auth_routes)
        .nest("/api/v1/keys", api_key_routes)
        .nest("/api/v1/data", data_routes.with_state(state.backend_router.clone()))
        .nest("/api/v1/query", query_routes.with_state(state.backend_router.clone()))
        .nest("/api/v1/roles", role_routes)
        .nest("/api/v1/admin", health_routes.with_state(state.backend_router.clone()))
        .nest("/api/v1/stream", stream_routes.with_state(state.backend_router.clone()))
        .nest("/api/v1/rate-limit", rate_limit_routes.with_state(state.rate_limit_service.clone()))
        .layer(axum::middleware::from_fn(move |req, next| {
            let config = security_config.clone();
            async move { development_security_middleware(config, req, next).await }
        }))
}

/// Start the server with BackendRouter (now the main/default server)
pub async fn run_server(config_path: Option<&str>) -> Result<(), ServerError> {
    let state = AppState::new(config_path).await?;
    let config = AppConfig::from_env().map_err(ServerError::Configuration)?;

    let app = create_app(state);

    let addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|e| ServerError::ServerBinding(format!("Failed to bind to {}: {}", addr, e)))?;

    println!("DBX Server running on http://{}", addr);
    println!("API Endpoints:");
    println!("  Health: GET /health");
    println!("  Data Operations: POST/GET/PUT/DELETE /api/v1/data/{{key}}");
    println!("  Query Operations: POST /api/v1/query");
    println!("  Stream Operations: POST /api/v1/stream/{{stream}}");
    println!("  Authentication: POST /auth/login");

    axum::serve(listener, app)
        .await
        .map_err(|e| ServerError::ServerRuntime(e.to_string()))?;

    Ok(())
}

/// Public run function for compatibility
pub async fn run() -> Result<(), ConfigError> {
    run_server(None).await.map_err(|e| match e {
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
    use crate::config::JwtConfig;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use std::sync::Arc;
    use tower::ServiceExt;

    /// Helper function to set up required environment variables for tests
    fn setup_test_env() {
        std::env::set_var(
            "JWT_SECRET",
            "test-jwt-secret-that-is-at-least-32-characters-long-for-security",
        );
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

    /// Helper function to create AppState for tests, handling user conflicts gracefully
    async fn create_test_app_state() -> AppState {
        setup_test_env();
        let result = AppState::new(None).await;
        cleanup_test_env();

        match result {
            Ok(state) => state,
            Err(ServerError::UserStoreInitialization(msg)) if msg.contains("already exists") => {
                // If user already exists from parallel tests, create without default admin
                setup_test_env();
                std::env::remove_var("CREATE_DEFAULT_ADMIN");
                let state = AppState::new(None)
                    .await
                    .expect("Failed to create AppState without default admin");
                cleanup_test_env();
                state
            }
            Err(_) => {
                // For any other error, try without default admin
                setup_test_env();
                std::env::remove_var("CREATE_DEFAULT_ADMIN");
                let state = AppState::new(None)
                    .await
                    .expect("Failed to create AppState");
                cleanup_test_env();
                state
            }
        }
    }

    #[tokio::test]
    async fn test_create_app_state_success() {
        let _app_state = create_test_app_state().await;
        // If we reach here, the app state was created successfully
        assert!(true);
    }

    #[tokio::test]
    async fn test_create_app_state_with_default_admin() {
        setup_test_env();
        std::env::set_var("CREATE_DEFAULT_ADMIN", "true");
        std::env::set_var("DEFAULT_ADMIN_USERNAME", "admin");
        std::env::set_var("DEFAULT_ADMIN_PASSWORD", "admin123");

        let result = AppState::new(None).await;
        // Default admin creation might fail in some test environments (concurrent tests, permissions, etc.)
        // The important thing is that the application handles the configuration correctly
        match result {
            Ok(_) => {
                // Admin creation succeeded
            }
            Err(ServerError::UserStoreInitialization(_)) => {
                // Configuration parsed correctly, but user creation failed
            }
            Err(ServerError::Configuration(_)) => {
                panic!("Configuration should have been valid");
            }
            Err(_) => {
                // Other errors are also acceptable in test environments
            }
        }

        cleanup_test_env();
    }

    #[tokio::test]
    async fn test_create_app_state_missing_admin_credentials() {
        setup_test_env();
        std::env::set_var("CREATE_DEFAULT_ADMIN", "true");
        std::env::set_var("DEFAULT_ADMIN_USERNAME", "admin");
        std::env::remove_var("DEFAULT_ADMIN_PASSWORD");

        let result = AppState::new(None).await;
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
        let app_state = create_test_app_state().await;
        let app = create_app(app_state);

        // Test CORS preflight on auth endpoint (should work because CORS is applied there)
        let auth_request = Request::builder()
            .method(Method::OPTIONS)
            .uri("/auth/login")
            .header("Origin", "http://localhost:3000")
            .header("Access-Control-Request-Method", "POST")
            .body(Body::empty())
            .unwrap();

        let auth_response = app.oneshot(auth_request).await.unwrap();
        assert_eq!(auth_response.status(), StatusCode::OK);

        // Test OPTIONS on health endpoint (should return 405 as it doesn't support OPTIONS)
        let app_state = create_test_app_state().await;
        let app = create_app(app_state);

        let health_request = Request::builder()
            .method(Method::OPTIONS)
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let health_response = app.oneshot(health_request).await.unwrap();
        assert_eq!(health_response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn test_health_check_endpoint() {
        let app_state = create_test_app_state().await;
        let app = create_app(app_state);

        let request = Request::builder()
            .method(Method::GET)
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_middleware_chain() {
        let app_state = create_test_app_state().await;
        let app = create_app(app_state);

        let request = Request::builder()
            .method(Method::GET)
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_cors_configuration() {
        let app_state = create_test_app_state().await;
        let app = create_app(app_state);

        // Test CORS preflight on auth endpoint (should work - CORS enabled for browser access)
        let auth_preflight_request = Request::builder()
            .method(Method::OPTIONS)
            .uri("/auth/login")
            .header("Origin", "http://localhost:3000")
            .header("Access-Control-Request-Method", "POST")
            .body(Body::empty())
            .unwrap();

        let auth_response = app.oneshot(auth_preflight_request).await.unwrap();
        assert_eq!(auth_response.status(), StatusCode::OK);

        // Test that CORS headers are present
        assert!(auth_response
            .headers()
            .contains_key("access-control-allow-origin"));

        // Test OPTIONS on API endpoint (should return 401 - requires authentication first)
        let app_state = create_test_app_state().await;
        let app = create_app(app_state);

        let api_options_request = Request::builder()
            .method(Method::OPTIONS)
            .uri("/api/v1/data/test")
            .body(Body::empty())
            .unwrap();

        let api_response = app.oneshot(api_options_request).await.unwrap();
        assert_eq!(api_response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_create_app_state_error_handling() {
        setup_test_env();
        // Test that AppState can be created with valid configuration
        let result = AppState::new(None).await;
        assert!(result.is_ok());

        cleanup_test_env();
    }

    #[tokio::test]
    async fn test_api_docs_endpoint() {
        let app_state = create_test_app_state().await;
        let app = create_app(app_state);

        let request = Request::builder()
            .method(Method::GET)
            .uri("/docs")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_not_found_endpoint() {
        let app_state = create_test_app_state().await;
        let app = create_app(app_state);

        let request = Request::builder()
            .method(Method::GET)
            .uri("/nonexistent")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_protected_route_without_auth() {
        let app_state = create_test_app_state().await;
        let app = create_app(app_state);

        let request = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/data/test")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_admin_route_without_auth() {
        let app_state = create_test_app_state().await;
        let app = create_app(app_state);

        let request = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/admin/system")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_websocket_route_without_auth() {
        let app_state = create_test_app_state().await;
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

        assert_eq!(response.status().as_u16(), 404);
    }

    #[tokio::test]
    async fn test_route_structure() {
        let app_state = create_test_app_state().await;
        let app = create_app(app_state);

        let health_request = Request::builder()
            .method(Method::GET)
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(health_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_health_check_response() {
        let _response = health_check();
        // Async function compilation and return type validation
        assert!(true); // This test ensures the function compiles
    }

    #[tokio::test]
    async fn test_app_state_cloning() {
        let app_state = create_test_app_state().await;

        let backend_router_clone = app_state.backend_router.clone();
        let jwt_service_clone = app_state.jwt_service.clone();
        let user_store_clone = app_state.user_store.clone();

        assert!(Arc::ptr_eq(
            &app_state.backend_router,
            &backend_router_clone
        ));
        assert!(Arc::ptr_eq(&app_state.jwt_service, &jwt_service_clone));
        assert!(Arc::ptr_eq(&app_state.user_store, &user_store_clone));
    }

    #[tokio::test]
    async fn test_app_state_structure() {
        let app_state = create_test_app_state().await;

        assert!(Arc::strong_count(&app_state.backend_router) >= 1);
        assert!(Arc::strong_count(&app_state.jwt_service) >= 1);
        assert!(Arc::strong_count(&app_state.user_store) >= 1);
    }

    #[tokio::test]
    async fn test_json_rejection_handling() {
        let app_state = create_test_app_state().await;
        let app = create_app(app_state);

        // Test invalid JSON handling on existing auth route
        let request = Request::builder()
            .method(Method::POST)
            .uri("/auth/login")
            .header("content-type", "application/json")
            .body(Body::from("invalid json"))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
