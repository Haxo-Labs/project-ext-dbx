use crate::{
    auth::{ApiKeyService, RbacService},
    config::{AppConfig, ConfigError},
    middleware::{
        admin_info_permission_middleware, rate_limit_middleware, rbac_auth_middleware,
        security::{
            create_cors_layer, development_security_middleware, security_validation_middleware,
        },
        security_headers_middleware, JwtService, PolicyRateLimitService, UserStore,
    },
    models::ApiResponse,
    routes::{
        api_keys::create_api_key_routes, auth::create_auth_routes, data::create_data_routes,
        health::create_health_routes, query::create_query_routes,
        rate_limit::create_rate_limit_routes, roles::create_role_routes,
        stream::create_stream_routes,
    },
};
use axum::{response::IntoResponse, routing::get, Router};
use dbx_config::DbxConfig;
use std::sync::Arc;
use tracing::error;

/// Application state for the DBX API
#[derive(Clone)]
pub struct AppState {
    pub backend_router: Arc<dbx_router::BackendRouter>,
    pub jwt_service: Arc<JwtService>,
    pub user_store: Arc<UserStore>,
    pub api_key_service: Arc<ApiKeyService>,
    pub rbac_service: Arc<RbacService>,
    pub rate_limit_service: Arc<PolicyRateLimitService>,
}

impl AppState {
    /// Create new application state with backend router
    pub async fn new(config_path: Option<&str>) -> Result<Self, ServerError> {
        Self::new_with_optional_app_config(config_path, None).await
    }

    /// Create new application state with optional AppConfig override (for testing)
    pub async fn new_with_optional_app_config(
        config_path: Option<&str>,
        app_config_override: Option<AppConfig>,
    ) -> Result<Self, ServerError> {
        // If we have an AppConfig override, we need to create a minimal DbxConfig for backend routing
        // without calling the environment loader
        if let Some(app_config) = app_config_override {
            // Create a minimal DbxConfig for testing with mock backend
            let mut backends = std::collections::HashMap::new();
            backends.insert(
                "test_backend".to_string(),
                dbx_config::BackendConfig {
                    provider: "mock".to_string(),
                    url: "mock://localhost".to_string(),
                    pool_size: Some(10),
                    timeout_ms: Some(30000),
                    retry_attempts: Some(3),
                    retry_delay_ms: Some(1000),
                    capabilities: None,
                    additional_config: std::collections::HashMap::new(),
                },
            );

            let test_config = DbxConfig {
                backends,
                routing: dbx_config::RoutingConfig {
                    default_backend: "test_backend".to_string(),
                    operation_routing: std::collections::HashMap::new(),
                    key_routing: Vec::new(),
                    load_balancing: None,
                },
                consistency: dbx_config::ConsistencyConfig {
                    level: dbx_core::ConsistencyLevel::Eventual,
                    cross_backend: dbx_core::CrossBackendConsistency::BestEffort,
                    transaction_timeout_ms: 30000,
                    read_after_write: false,
                    staleness_tolerance_ms: Some(1000),
                },
                performance: dbx_config::PerformanceConfig {
                    query_timeout_ms: 5000,
                    connection_timeout_ms: 5000,
                    max_concurrent_operations: 1000,
                    cache_enabled: true,
                    cache_ttl_ms: 300000,
                    metrics_enabled: false,
                    tracing_enabled: false,
                    batch_size: 100,
                },
                security: dbx_config::SecurityConfig {
                    authentication_required: true,
                    authorization_enabled: true,
                    encryption_at_rest: false,
                    encryption_in_transit: false,
                    audit_logging: false,
                    rate_limiting: None,
                    jwt: Some(dbx_config::JwtConfig {
                        secret: app_config.jwt.secret.clone(),
                        expiration_seconds: app_config.jwt.access_token_expiration as u64,
                        issuer: app_config.jwt.issuer.clone(),
                        audience: Some("test".to_string()),
                    }),
                    tls: None,
                },
                server: dbx_config::ServerConfig {
                    host: app_config.server.host.clone(),
                    port: app_config.server.port,
                    workers: None,
                    websocket_enabled: false,
                    websocket_ping_interval: Some(30),
                    request_timeout_ms: 30000,
                    max_body_size: 1048576,
                    cors_enabled: true,
                    cors_origins: vec!["*".to_string()],
                },
                admin: dbx_config::AdminConfig {
                    create_default_admin: app_config.create_default_admin,
                    default_admin_username: app_config.default_admin_username.clone(),
                    default_admin_password: app_config.default_admin_password.clone(),
                    rbac: dbx_config::RbacConfig {
                        audit_enabled: app_config.rbac.audit_enabled,
                        audit_retention_days: app_config.rbac.audit_retention_days,
                        max_role_inheritance_depth: app_config.rbac.max_role_inheritance_depth,
                        performance_cache_ttl_seconds: app_config
                            .rbac
                            .performance_cache_ttl_seconds,
                        default_assignment_ttl_days: app_config.rbac.default_assignment_ttl_days,
                    },
                },
            };

            return Self::create_app_state_from_configs(app_config, test_config).await;
        }

        // Normal path: Load DbxConfig from environment
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

        Self::create_app_state_from_configs(app_config, config).await
    }

    /// Common method to create AppState from both configs
    async fn create_app_state_from_configs(
        app_config: AppConfig,
        dbx_config: DbxConfig,
    ) -> Result<Self, ServerError> {
        // Build backend registry
        let mut registry_builder = dbx_router::registry::BackendRegistryBuilder::new();

        // Register Redis backend factory
        let redis_factory = dbx_adapter::redis::factory::RedisBackendFactory::new();
        registry_builder = registry_builder.with_factory("redis", redis_factory);

        // Register PostgreSQL backend factory
        let postgres_factory = dbx_adapter::postgres::factory::PostgresBackendFactory::new();
        registry_builder = registry_builder.with_factory("postgresql", postgres_factory);

        // Build the registry
        let registry = registry_builder.build();

        // Initialize backends from configuration
        registry
            .initialize_backends(&dbx_config)
            .await
            .map_err(|e| {
                ServerError::DatabaseConnection(format!("Failed to initialize backends: {}", e))
            })?;

        // Create backend router
        let backend_router =
            dbx_router::BackendRouter::new(registry, &dbx_config).map_err(|e| {
                ServerError::DatabaseConnection(format!("Failed to create router: {}", e))
            })?;

        // Get default backend configuration for auth services
        let default_backend_name = &dbx_config.routing.default_backend;
        let _default_backend = dbx_config
            .backends
            .get(default_backend_name)
            .ok_or_else(|| {
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

    /// Create default admin user if it doesn't exist
    async fn create_default_admin_user(
        app_config: &AppConfig,
        user_store: &Arc<UserStore>,
        rbac_service: &Arc<RbacService>,
    ) -> Result<(), ServerError> {
        use crate::{
            middleware::auth::UserStoreOperations,
            models::{CreateUserRequest, UserRole},
        };

        let username = app_config
            .default_admin_username
            .as_ref()
            .ok_or_else(|| ServerError::Configuration(ConfigError::MissingDefaultAdminPassword))?;

        let password = app_config
            .default_admin_password
            .as_ref()
            .ok_or_else(|| ServerError::Configuration(ConfigError::MissingDefaultAdminPassword))?;

        // Check if admin user already exists
        match user_store.get_user_by_username(username).await {
            Ok(Some(_)) => {
                tracing::info!(
                    "Default admin user '{}' already exists, skipping creation",
                    username
                );
                return Ok(());
            }
            Ok(None) => {
                // User doesn't exist, create it
                tracing::info!("Creating default admin user '{}'", username);
            }
            Err(e) => {
                tracing::warn!("Failed to check for existing admin user: {}", e);
                // Continue with creation attempt
            }
        }

        // Create the admin user
        let create_request = CreateUserRequest {
            username: username.clone(),
            password: password.clone(),
            role: UserRole::Admin,
        };

        match user_store.create_user(create_request).await {
            Ok(user) => {
                tracing::info!("Successfully created default admin user '{}'", username);

                // Assign admin role using RBAC
                if let Err(e) = rbac_service
                    .assign_role(&user.id, username, "Admin", "system", None, None)
                    .await
                {
                    tracing::warn!("Failed to assign admin role to default user: {}", e);
                }
            }
            Err(e) => {
                tracing::error!("Failed to create default admin user '{}': {}", username, e);
                return Err(ServerError::UserStoreInitialization(format!(
                    "Failed to create default admin user: {}",
                    e
                )));
            }
        }

        Ok(())
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
            Arc<PolicyRateLimitService>,
        ),
        ServerError,
    > {
        // Create auth services using the configured backend
        let user_store = Arc::new(UserStore::new(backend.clone()));
        let jwt_service = Arc::new(JwtService::new(app_config.jwt.clone(), user_store.clone()));
        let api_key_service = Arc::new(ApiKeyService::new(backend.clone()));
        let rbac_service = Arc::new(RbacService::new(backend.clone(), app_config.rbac.clone()));

        let rate_limit_service = PolicyRateLimitService::new(backend.clone());
        if app_config.rate_limit.enabled {
            let global_policy = crate::models::RateLimitPolicy {
                requests: app_config.rate_limit.global_requests_per_window,
                window_seconds: app_config.rate_limit.global_window_seconds,
                burst_allowance: app_config.rate_limit.global_burst_allowance,
            };
            let _ = rate_limit_service.set_global_policy(global_policy).await;
        }
        let rate_limit_service = Arc::new(rate_limit_service);

        // Create default admin user if configured
        if app_config.create_default_admin {
            Self::create_default_admin_user(app_config, &user_store, &rbac_service).await?;
        }

        Ok((
            user_store,
            jwt_service,
            api_key_service,
            rbac_service,
            rate_limit_service,
        ))
    }
}

/// Health check endpoint
pub async fn health_check() -> axum::Json<ApiResponse<String>> {
    axum::Json(ApiResponse::success("Server is running".to_string()))
}

/// Middleware helper functions to eliminate duplication
mod middleware_helpers {
    use super::*;
    use axum::Router;

    /// Apply standard protected route middleware (rate limiting + RBAC auth)
    pub fn apply_protected_middleware<S>(router: Router<S>, state: &AppState) -> Router<S>
    where
        S: Clone + Send + Sync + 'static,
    {
        router
            .layer(axum::middleware::from_fn_with_state(
                state.rate_limit_service.clone(),
                rate_limit_middleware,
            ))
            .layer(axum::middleware::from_fn_with_state(
                (
                    state.jwt_service.clone(),
                    state.api_key_service.clone(),
                    state.rbac_service.clone(),
                ),
                rbac_auth_middleware,
            ))
    }

    /// Apply admin-only middleware (admin permissions + standard protected middleware)
    pub fn apply_admin_middleware<S>(router: Router<S>, state: &AppState) -> Router<S>
    where
        S: Clone + Send + Sync + 'static,
    {
        router
            .layer(axum::middleware::from_fn_with_state(
                state.rbac_service.clone(),
                admin_info_permission_middleware,
            ))
            .layer(axum::middleware::from_fn_with_state(
                (
                    state.jwt_service.clone(),
                    state.api_key_service.clone(),
                    state.rbac_service.clone(),
                ),
                rbac_auth_middleware,
            ))
    }

    /// Apply global security middleware stack
    pub fn apply_global_security_middleware(
        router: Router,
        security_config: crate::config::SecurityConfig,
        cors_layer: tower_http::cors::CorsLayer,
    ) -> Router {
        let security_config_validation = security_config.clone();
        let security_config_headers = security_config;

        router
            // Global CORS layer (applied first to handle preflight requests)
            .layer(cors_layer)
            // Global security validation middleware (applied after CORS)
            .layer(axum::middleware::from_fn(move |req, next| {
                let config = security_config_validation.clone();
                async move { security_validation_middleware(config, req, next).await }
            }))
            // Global security headers middleware
            .layer(axum::middleware::from_fn(move |req, next| {
                let config = security_config_headers.clone();
                async move {
                    if config.development_mode {
                        development_security_middleware(config, req, next).await
                    } else {
                        security_headers_middleware(config, req, next)
                            .await
                            .into_response()
                    }
                }
            }))
    }
}

/// Router builder pattern for organized route configuration
struct RouterBuilder {
    state: AppState,
    security_config: crate::config::SecurityConfig,
    cors_layer: tower_http::cors::CorsLayer,
}

impl RouterBuilder {
    /// Create a new router builder
    fn new(
        state: AppState,
        security_config: crate::config::SecurityConfig,
        cors_layer: tower_http::cors::CorsLayer,
    ) -> Self {
        Self {
            state,
            security_config,
            cors_layer,
        }
    }

    /// Build the complete application router
    fn build(self) -> Router {
        let router = Router::new()
            .route("/health", get(health_check))
            .merge(self.build_auth_routes())
            .merge(self.build_protected_routes())
            .merge(self.build_admin_routes());

        // Apply global security middleware
        middleware_helpers::apply_global_security_middleware(
            router,
            self.security_config,
            self.cors_layer,
        )
    }

    /// Build authentication routes (no middleware required)
    fn build_auth_routes(&self) -> Router {
        Router::new().nest(
            "/api/v1/auth",
            create_auth_routes(
                self.state.jwt_service.clone(),
                self.state.user_store.clone(),
            ),
        )
    }

    /// Build protected routes with standard middleware
    fn build_protected_routes(&self) -> Router {
        let api_key_routes = middleware_helpers::apply_protected_middleware(
            create_api_key_routes(self.state.api_key_service.clone()),
            &self.state,
        );

        let data_routes =
            middleware_helpers::apply_protected_middleware(create_data_routes(), &self.state);

        let query_routes =
            middleware_helpers::apply_protected_middleware(create_query_routes(), &self.state);

        let stream_routes =
            middleware_helpers::apply_protected_middleware(create_stream_routes(), &self.state);

        let role_routes = middleware_helpers::apply_protected_middleware(
            create_role_routes(self.state.rbac_service.clone()),
            &self.state,
        );

        let rate_limit_routes =
            middleware_helpers::apply_protected_middleware(create_rate_limit_routes(), &self.state);

        Router::new()
            .nest("/api/v1/api-keys", api_key_routes)
            .nest(
                "/api/v1/data",
                data_routes.with_state(self.state.backend_router.clone()),
            )
            .nest(
                "/api/v1/query",
                query_routes.with_state(self.state.backend_router.clone()),
            )
            .nest(
                "/api/v1/stream",
                stream_routes.with_state(self.state.backend_router.clone()),
            )
            .nest("/api/v1/roles", role_routes)
            .nest(
                "/api/v1/rate-limit",
                rate_limit_routes.with_state(self.state.rate_limit_service.clone()),
            )
    }

    /// Build admin routes with admin-only middleware
    fn build_admin_routes(&self) -> Router {
        let health_routes =
            middleware_helpers::apply_admin_middleware(create_health_routes(), &self.state);

        Router::new().nest(
            "/api/v1/admin",
            health_routes.with_state(self.state.backend_router.clone()),
        )
    }
}

/// Create the application router with BackendRouter
pub async fn create_app(state: AppState) -> Result<Router, ServerError> {
    #[cfg(test)]
    {
        // In test mode, use a test config to avoid blocking calls
        let test_config = create_test_app_config();
        Ok(create_app_with_config(state, test_config))
    }
    #[cfg(not(test))]
    {
        // In non-test mode, load config from environment
        let app_config = AppConfig::from_env()
            .await
            .map_err(ServerError::Configuration)?;
        Ok(create_app_with_config(state, app_config))
    }
}

/// Helper function to create test AppConfig without blocking calls (available in test mode)
#[cfg(test)]
pub fn create_test_app_config() -> AppConfig {
    AppConfig {
        server: crate::config::ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 3000,
        },
        jwt: crate::config::JwtConfig {
            secret: "test-jwt-secret-that-is-at-least-32-characters-long-for-security".to_string(),
            access_token_expiration: 3600,
            refresh_token_expiration: 25200,
            issuer: "dbx".to_string(),
        },
        rate_limit: crate::config::RateLimitConfig {
            enabled: false,
            global_requests_per_window: 100,
            global_window_seconds: 60,
            global_burst_allowance: Some(10),
            per_user_enabled: false,
            per_ip_enabled: false,
            endpoint_overrides: std::collections::HashMap::new(),
            key_prefix: "test".to_string(),
            graceful_degradation: true,
        },
        security: crate::config::SecurityConfig::default(),
        create_default_admin: false,
        default_admin_username: None,
        default_admin_password: None,
        rbac: crate::auth::rbac::RbacConfig {
            audit_enabled: false,
            audit_retention_days: 30,
            max_role_inheritance_depth: 5,
            performance_cache_ttl_seconds: 300,
            default_assignment_ttl_days: None,
        },
    }
}

/// Create the application router with BackendRouter and optional config
pub fn create_app_with_config(state: AppState, app_config: AppConfig) -> Router {
    let cors_layer = create_cors_layer(&app_config.security.cors);
    let security_config = app_config.security.clone();

    RouterBuilder::new(state, security_config, cors_layer).build()
}

/// Start the server with BackendRouter (now the main/default server)
pub async fn run_server(config_path: Option<&str>) -> Result<(), ServerError> {
    let state = AppState::new(config_path).await?;
    let config = AppConfig::from_env()
        .await
        .map_err(ServerError::Configuration)?;

    let app = create_app(state).await?;

    let addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| ServerError::ServerBinding(format!("Failed to bind to {}: {}", addr, e)))?;

    tracing::info!("DBX Server running on http://{}", addr);
    tracing::info!("API Endpoints:");
    tracing::info!("  Health: GET /health");
    tracing::info!("  Data Operations: POST/GET/PUT/DELETE /api/v1/data/{{key}}");
    tracing::info!("  Query Operations: POST /api/v1/query");
    tracing::info!("  Stream Operations: POST /api/v1/stream/{{stream}}");
    tracing::info!("  Authentication: POST /api/v1/auth/login");

    axum::serve(listener, app)
        .await
        .map_err(|e| ServerError::ServerRuntime(e.to_string()))?;

    Ok(())
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
