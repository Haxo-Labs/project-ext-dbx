use axum::http::StatusCode;
use axum::{response::Html, routing::get, Router, middleware};
use std::fs;
use std::sync::Arc;
use tracing::info;

use crate::{
    config::Config,
    constants::errors::ErrorMessages,
    middleware::{JwtService, UserStore, jwt_auth_middleware, require_admin_role, require_user_role},
};

use dbx_adapter::redis::{client::RedisPool, RedisPoolAdapter};

pub struct Server {
    config: Config,
    redis_pool: Option<Arc<RedisPool>>,
    jwt_service: Arc<JwtService>,
    user_store: Arc<UserStore>,
}

impl Server {
    pub async fn new(config: Config) -> anyhow::Result<Self> {
        info!("Connecting to Redis at {}", config.database_url);

        let pool = RedisPool::new(&config.database_url, config.pool_size)?;
        let pool_adapter = RedisPoolAdapter::new(pool.clone());
        let redis = pool_adapter.get_instance()?;
        let ping_result = redis.ping();

        let redis_pool = match ping_result {
            Ok(true) => {
                info!("Successfully connected to Redis with connection pool");
                Some(Arc::new(pool))
            }
            Ok(false) => {
                return Err(anyhow::anyhow!(ErrorMessages::REDIS_PING_FAILED));
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "{}{}",
                    ErrorMessages::REDIS_CONNECTION_FAILED,
                    e
                ));
            }
        };

        let jwt_service = Arc::new(JwtService::new(config.jwt.clone()));
        let user_store = Arc::new(UserStore::new());

        Ok(Self {
            config,
            redis_pool,
            jwt_service,
            user_store,
        })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Create the application router
    pub fn create_router(&self) -> Router {
        let mut router = Router::new()
            .route("/", get(serve_landing_page))
            .route("/redis_ws", get(serve_landing_page));

        // Add authentication routes (public)
        let auth_routes = crate::routes::auth::create_auth_routes(
            self.jwt_service.clone(),
            self.user_store.clone(),
        );
        router = router.nest("/auth", auth_routes);

        // Add Redis routes with authentication and role-based access control
        if let Some(pool) = &self.redis_pool {
            // Admin routes - require admin role
            let redis_admin_routes = crate::routes::redis::admin::create_redis_admin_routes(pool.clone())
                .layer(middleware::from_fn_with_state(
                    self.jwt_service.clone(),
                    jwt_auth_middleware,
                ))
                .layer(middleware::from_fn(require_admin_role));

            let redis_ws_admin_routes = crate::routes::redis_ws::admin::create_redis_ws_admin_routes(pool.clone())
                .layer(middleware::from_fn_with_state(
                    self.jwt_service.clone(),
                    jwt_auth_middleware,
                ))
                .layer(middleware::from_fn(require_admin_role));

            // Write operations - require user role or higher
            let redis_string_routes = crate::routes::redis::string::create_redis_string_routes(pool.clone())
                .layer(middleware::from_fn_with_state(
                    self.jwt_service.clone(),
                    jwt_auth_middleware,
                ))
                .layer(middleware::from_fn(require_user_role));

            let redis_hash_routes = crate::routes::redis::hash::create_redis_hash_routes(pool.clone())
                .layer(middleware::from_fn_with_state(
                    self.jwt_service.clone(),
                    jwt_auth_middleware,
                ))
                .layer(middleware::from_fn(require_user_role));

            let redis_set_routes = crate::routes::redis::set::create_redis_set_routes(pool.clone())
                .layer(middleware::from_fn_with_state(
                    self.jwt_service.clone(),
                    jwt_auth_middleware,
                ))
                .layer(middleware::from_fn(require_user_role));

            let redis_ws_string_routes = crate::routes::redis_ws::string::create_redis_ws_string_routes(pool.clone())
                .layer(middleware::from_fn_with_state(
                    self.jwt_service.clone(),
                    jwt_auth_middleware,
                ))
                .layer(middleware::from_fn(require_user_role));

            let redis_ws_hash_routes = crate::routes::redis_ws::hash::create_redis_ws_hash_routes(pool.clone())
                .layer(middleware::from_fn_with_state(
                    self.jwt_service.clone(),
                    jwt_auth_middleware,
                ))
                .layer(middleware::from_fn(require_user_role));

            let redis_ws_set_routes = crate::routes::redis_ws::set::create_redis_ws_set_routes(pool.clone())
                .layer(middleware::from_fn_with_state(
                    self.jwt_service.clone(),
                    jwt_auth_middleware,
                ))
                .layer(middleware::from_fn(require_user_role));

            router = router
                .nest("/redis", redis_string_routes)
                .nest("/redis", redis_hash_routes)
                .nest("/redis", redis_set_routes)
                .nest("/redis", redis_admin_routes)
                .nest("/redis_ws", redis_ws_string_routes)
                .nest("/redis_ws", redis_ws_hash_routes)
                .nest("/redis_ws", redis_ws_set_routes)
                .nest("/redis_ws", redis_ws_admin_routes);
        }

        router
    }

    /// Run the server
    pub async fn run(self, addr: std::net::SocketAddr) -> anyhow::Result<()> {
        let app = self.create_router();

        info!("Starting DBX Redis API server with JWT authentication on {}", addr);
        info!("=== API Endpoints ===");
        info!("Authentication API:");
        info!("  POST http://{}/auth/login - User login", addr);
        info!("  POST http://{}/auth/refresh - Refresh token", addr);
        info!("  POST http://{}/auth/logout - User logout", addr);
        info!("  GET  http://{}/auth/validate - Validate token (requires auth)", addr);
        info!("  GET  http://{}/auth/me - Get current user (requires auth)", addr);
        info!("");
        info!("Redis HTTP API (requires authentication):");
        info!("  Admin endpoints (Admin role required):");
        info!("    http://{}/redis/admin/* - Redis admin operations", addr);
        info!("  User endpoints (User role or higher required):");
        info!("    http://{}/redis/string/* - Redis string operations", addr);
        info!("    http://{}/redis/hash/* - Redis hash operations", addr);
        info!("    http://{}/redis/set/* - Redis set operations", addr);
        info!("");
        info!("Redis WebSocket API (requires authentication):");
        info!("  Admin endpoints (Admin role required):");
        info!("    ws://{}/redis_ws/admin/ws - Redis admin WebSocket", addr);
        info!("  User endpoints (User role or higher required):");
        info!("    ws://{}/redis_ws/string/ws - Redis string WebSocket", addr);
        info!("    ws://{}/redis_ws/hash/ws - Redis hash WebSocket", addr);
        info!("    ws://{}/redis_ws/set/ws - Redis set WebSocket", addr);
        info!("");
        info!("=== Authentication Instructions ===");
        info!("1. Login: POST /auth/login with {{\"username\": \"admin\", \"password\": \"admin123\"}}");
        info!("2. Use the returned access_token in Authorization header: 'Bearer <token>'");
        info!("3. Refresh token when needed: POST /auth/refresh with {{\"refresh_token\": \"<refresh_token>\"}}");

        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await?;

        Ok(())
    }
}

impl Clone for Server {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            redis_pool: self.redis_pool.clone(),
            jwt_service: self.jwt_service.clone(),
            user_store: self.user_store.clone(),
        }
    }
}

/// Serve the landing page HTML
async fn serve_landing_page() -> Result<Html<String>, StatusCode> {
    match fs::read_to_string("static/index.html") {
        Ok(content) => Ok(Html(content)),
        Err(_) => {
            // Fallback to a simple HTML if file not found
            let fallback_html = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DBX - Redis API Gateway</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50">
    <div class="min-h-screen flex items-center justify-center">
        <div class="text-center max-w-4xl">
            <h1 class="text-4xl font-bold text-blue-600 mb-4">DBX API Gateway</h1>
            <p class="text-xl text-gray-600 mb-8">Redis API Gateway with JWT Authentication</p>
            
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
                <div class="bg-white p-6 rounded-lg shadow">
                    <h2 class="text-xl font-semibold text-gray-900 mb-4">🔐 Authentication</h2>
                    <div class="text-left space-y-2 text-sm text-gray-600">
                        <p><strong>Login:</strong> POST /auth/login</p>
                        <p><strong>Refresh:</strong> POST /auth/refresh</p>
                        <p><strong>Validate:</strong> GET /auth/validate</p>
                        <p><strong>Current User:</strong> GET /auth/me</p>
                    </div>
                </div>
                
                <div class="bg-white p-6 rounded-lg shadow">
                    <h2 class="text-xl font-semibold text-gray-900 mb-4">🔧 Redis Operations</h2>
                    <div class="text-left space-y-2 text-sm text-gray-600">
                        <p><strong>Admin:</strong> /redis/admin/* (Admin role)</p>
                        <p><strong>Strings:</strong> /redis/string/* (User role)</p>
                        <p><strong>Hashes:</strong> /redis/hash/* (User role)</p>
                        <p><strong>Sets:</strong> /redis/set/* (User role)</p>
                    </div>
                </div>
            </div>
            
            <div class="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-6">
                <h3 class="font-semibold text-yellow-800 mb-2">Demo Users</h3>
                <div class="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                    <div class="text-yellow-700">
                        <strong>Admin:</strong><br/>
                        username: admin<br/>
                        password: admin123
                    </div>
                    <div class="text-yellow-700">
                        <strong>User:</strong><br/>
                        username: user<br/>
                        password: user123
                    </div>
                    <div class="text-yellow-700">
                        <strong>ReadOnly:</strong><br/>
                        username: readonly<br/>
                        password: readonly123
                    </div>
                </div>
            </div>
            
            <div class="bg-blue-50 border border-blue-200 rounded-lg p-4">
                <h3 class="font-semibold text-blue-800 mb-2">Usage Example</h3>
                <div class="text-left text-sm text-blue-700 space-y-1">
                    <p>1. Login: <code>curl -X POST /auth/login -d '{"username":"admin","password":"admin123"}'</code></p>
                    <p>2. Use token: <code>curl -H "Authorization: Bearer &lt;token&gt;" /redis/admin/ping</code></p>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
            "#;
            Ok(Html(fallback_html.to_string()))
        }
    }
}
