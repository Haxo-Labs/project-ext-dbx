use std::{env, sync::Once, time::Duration};

use reqwest::Client;
use serde_json::Value;
use thiserror::Error;
use tokio::{net::TcpListener, task::JoinHandle, time::sleep};
use uuid::Uuid;

use dbx_api::server::{create_app, AppState};

static INIT: Once = Once::new();

#[derive(Debug, Error)]
pub enum TestError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Authentication error: {0}")]
    Auth(String),
    #[error("Setup error: {0}")]
    Setup(String),
}

type TestResult<T> = std::result::Result<T, TestError>;

/// Test configuration and state management
pub struct TestServer {
    pub base_url: String,
    pub client: Client,
    pub admin_token: Option<String>,
    pub user_token: Option<String>,
    pub _server_handle: JoinHandle<()>,
}

impl TestServer {
    /// Create a new test server instance
    pub async fn new() -> TestResult<Self> {
        // Initialize logging once
        INIT.call_once(|| {
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::DEBUG)
                .with_test_writer()
                .init();
        });

        // Find available port
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let backend_url = "mock://localhost";

        Self::setup_test_env(&backend_url, port)?;

        // Create application state
        let app_state = Self::create_test_app_state(&backend_url).await?;
        let app = create_app(app_state)
            .await
            .map_err(|e| TestError::Setup(e.to_string()))?;

        // Start server using the existing listener
        let server_handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // Give server time to start
        sleep(Duration::from_millis(100)).await;

        let base_url = format!("http://127.0.0.1:{}", port);
        let client = Client::new();

        Ok(Self {
            base_url,
            client,
            admin_token: None,
            user_token: None,
            _server_handle: server_handle,
        })
    }

    /// Setup test environment variables
    fn setup_test_env(backend_url: &str, port: u16) -> TestResult<()> {
        env::set_var(
            "JWT_SECRET",
            "test-jwt-secret-that-is-at-least-32-characters-long",
        );
        env::set_var("HOST", "127.0.0.1");
        env::set_var("PORT", port.to_string());
        env::set_var("CREATE_DEFAULT_ADMIN", "true");
        env::set_var("DEFAULT_ADMIN_USERNAME", "testadmin");
        env::set_var("DEFAULT_ADMIN_PASSWORD", "password");

        // Backend configuration
        env::set_var("DBX_BACKEND_1_URL", backend_url);
        env::set_var("DBX_BACKEND_1_PROVIDER", "mock");
        env::set_var("DBX_BACKEND_1_NAME", "test_backend");
        env::set_var("DBX_BACKEND_1_POOL_SIZE", "10");
        env::set_var("DBX_DEFAULT_BACKEND", "test_backend");

        // Load balancer configuration (include the backend in load balancing)
        // env::set_var("DBX_LOAD_BALANCING_BACKENDS", "test_backend"); // Disabled for tests to avoid complexity

        // Development mode for testing
        env::set_var("DEVELOPMENT_MODE", "true");
        env::set_var("LOG_LEVEL", "debug");
        // Disable strict security validation for tests
        env::set_var("HOST_VALIDATION_ENABLED", "false");
        env::set_var("STRICT_PORT_VALIDATION", "false");

        // Enable RBAC audit logging and rate limiting for realistic testing
        env::set_var("RBAC_AUDIT_ENABLED", "true");
        env::set_var("RATE_LIMIT_ENABLED", "true");

        Ok(())
    }

    /// Create test application state with mock backend support
    async fn create_test_app_state(_backend_url: &str) -> TestResult<AppState> {
        // Load configurations
        let app_config = dbx_api::config::AppConfig::from_env()
            .await
            .map_err(|e| TestError::Setup(e.to_string()))?;
        let dbx_config = dbx_config::ConfigLoader::load_from_env()
            .await
            .map_err(|e| TestError::Setup(e.to_string()))?;

        // Create test-specific AppState that includes mock backend factory
        Self::create_app_state_with_mock_backend(app_config, dbx_config).await
    }

    /// Create AppState with mock backend factory registered (test-only)
    async fn create_app_state_with_mock_backend(
        app_config: dbx_api::config::AppConfig,
        dbx_config: dbx_config::DbxConfig,
    ) -> TestResult<AppState> {
        // Build backend registry with mock factory
        let mut registry_builder = dbx_router::registry::BackendRegistryBuilder::new();

        // Register Redis backend factory
        let redis_factory = dbx_adapter::redis::factory::RedisBackendFactory::new();
        registry_builder = registry_builder.with_factory("redis", redis_factory);

        // Register PostgreSQL backend factory
        let postgres_factory = dbx_adapter::postgres::factory::PostgresBackendFactory::new();
        registry_builder = registry_builder.with_factory("postgresql", postgres_factory);

        // Register mock backend factory for tests
        let mock_factory = crate::test_helpers::MockBackendFactory::new();
        registry_builder = registry_builder.with_factory("mock", mock_factory);

        // Build the registry
        let registry = registry_builder.build();

        // Initialize backends from configuration
        registry
            .initialize_backends(&dbx_config)
            .await
            .map_err(|e| TestError::Setup(format!("Failed to initialize backends: {}", e)))?;

        // Create backend router
        let backend_router = dbx_router::BackendRouter::new(registry, &dbx_config)
            .map_err(|e| TestError::Setup(format!("Failed to create router: {}", e)))?;

        // Get a backend instance for auth services (use the default backend)
        let default_backend_name = &dbx_config.routing.default_backend;

        let auth_backend = backend_router
            .get_backend(default_backend_name)
            .await
            .ok_or_else(|| {
                TestError::Setup(format!(
                    "Auth backend '{}' not available",
                    default_backend_name
                ))
            })?;

        // Create services using the standard configuration pattern
        let user_store =
            std::sync::Arc::new(dbx_api::middleware::UserStore::new(auth_backend.clone()));

        let jwt_service = std::sync::Arc::new(dbx_api::middleware::JwtService::new(
            app_config.jwt.clone(),
            user_store.clone(),
        ));

        let api_key_service =
            std::sync::Arc::new(dbx_api::auth::ApiKeyService::new(auth_backend.clone()));

        let rbac_service = std::sync::Arc::new(dbx_api::auth::RbacService::new(
            auth_backend.clone(),
            app_config.rbac.clone(),
        ));

        let rate_limit_service =
            dbx_api::middleware::PolicyRateLimitService::new(auth_backend.clone());

        // Initialize global rate limit policy if enabled
        if app_config.rate_limit.enabled {
            let global_policy = dbx_api::models::RateLimitPolicy {
                requests: app_config.rate_limit.global_requests_per_window,
                window_seconds: app_config.rate_limit.global_window_seconds,
                burst_allowance: app_config.rate_limit.global_burst_allowance,
            };
            let _ = rate_limit_service.set_global_policy(global_policy).await;
        }
        let rate_limit_service = std::sync::Arc::new(rate_limit_service);

        Ok(dbx_api::server::AppState {
            backend_router: std::sync::Arc::new(backend_router),
            jwt_service,
            user_store,
            api_key_service,
            rbac_service,
            rate_limit_service,
        })
    }

    /// Authenticate as admin and return JWT token
    pub async fn authenticate_admin(&mut self) -> TestResult<String> {
        let login_data = serde_json::json!({
            "username": "testadmin",
            "password": "password"
        });

        let response = self
            .client
            .post(&format!("{}/api/v1/auth/login", self.base_url))
            .json(&login_data)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(TestError::Auth(format!(
                "Admin authentication failed: {}",
                error_text
            )));
        }

        let auth_response: Value = response.json().await?;
        let token = auth_response["data"]["access_token"]
            .as_str()
            .ok_or_else(|| TestError::Auth("No access token in response".to_string()))?
            .to_string();

        self.admin_token = Some(token.clone());
        Ok(token)
    }

    /// Authenticate as regular user and return JWT token
    pub async fn authenticate_user(&mut self) -> TestResult<String> {
        // First create a user (this would require admin privileges)
        if self.admin_token.is_none() {
            self.authenticate_admin().await?;
        }

        let create_user_data = serde_json::json!({
            "username": "testuser",
            "password": "password",
            "role": "user"
        });

        let _create_response = self
            .post_admin("/api/v1/auth/users", &create_user_data)
            .await?;

        // Now authenticate as the user
        let login_data = serde_json::json!({
            "username": "testuser",
            "password": "password"
        });

        let response = self
            .client
            .post(&format!("{}/api/v1/auth/login", self.base_url))
            .json(&login_data)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(TestError::Auth(format!(
                "User authentication failed: {}",
                error_text
            )));
        }

        let auth_response: Value = response.json().await?;
        let token = auth_response["data"]["access_token"]
            .as_str()
            .ok_or_else(|| TestError::Auth("No access token in response".to_string()))?
            .to_string();

        self.user_token = Some(token.clone());
        Ok(token)
    }

    /// Get authorization header for admin requests
    pub fn get_admin_auth_header(&self) -> TestResult<reqwest::header::HeaderMap> {
        let token = self
            .admin_token
            .as_ref()
            .ok_or_else(|| TestError::Auth("Admin not authenticated".to_string()))?;

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token))
                .map_err(|e| TestError::Auth(e.to_string()))?,
        );
        Ok(headers)
    }

    /// Get authorization header for user requests
    pub fn get_user_auth_header(&self) -> TestResult<reqwest::header::HeaderMap> {
        let token = self
            .user_token
            .as_ref()
            .ok_or_else(|| TestError::Auth("User not authenticated".to_string()))?;

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token))
                .map_err(|e| TestError::Auth(e.to_string()))?,
        );
        Ok(headers)
    }

    /// Make GET request with admin authentication
    pub async fn get_admin(&self, path: &str) -> TestResult<reqwest::Response> {
        let headers = self.get_admin_auth_header()?;
        let response = self
            .client
            .get(&format!("{}{}", self.base_url, path))
            .headers(headers)
            .send()
            .await?;
        Ok(response)
    }

    /// Make POST request with admin authentication
    pub async fn post_admin(&self, path: &str, json: &Value) -> TestResult<reqwest::Response> {
        let headers = self.get_admin_auth_header()?;
        let response = self
            .client
            .post(&format!("{}{}", self.base_url, path))
            .headers(headers)
            .json(json)
            .send()
            .await?;
        Ok(response)
    }

    /// Make PUT request with admin authentication
    pub async fn put_admin(&self, path: &str, json: &Value) -> TestResult<reqwest::Response> {
        let headers = self.get_admin_auth_header()?;
        let response = self
            .client
            .put(&format!("{}{}", self.base_url, path))
            .headers(headers)
            .json(json)
            .send()
            .await?;
        Ok(response)
    }

    /// Make DELETE request with admin authentication
    pub async fn delete_admin(&self, path: &str) -> TestResult<reqwest::Response> {
        let headers = self.get_admin_auth_header()?;
        let response = self
            .client
            .delete(&format!("{}{}", self.base_url, path))
            .headers(headers)
            .send()
            .await?;
        Ok(response)
    }

    /// Make GET request with user authentication
    pub async fn get_user(&self, path: &str) -> TestResult<reqwest::Response> {
        let headers = self.get_user_auth_header()?;
        let response = self
            .client
            .get(&format!("{}{}", self.base_url, path))
            .headers(headers)
            .send()
            .await?;
        Ok(response)
    }

    /// Make GET request without authentication
    pub async fn get_unauthenticated(&self, path: &str) -> TestResult<reqwest::Response> {
        let response = self
            .client
            .get(&format!("{}{}", self.base_url, path))
            .send()
            .await?;
        Ok(response)
    }

    /// Generate unique test data
    pub fn unique_key(&self) -> String {
        format!("test_key_{}", Uuid::new_v4())
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        // Server cleanup handled by Drop implementation
    }
}

/// Macro to create tests with automatic server setup
#[macro_export]
macro_rules! test_with_server {
    ($test_name:ident, $test_body:block) => {
        #[tokio::test]
        #[serial_test::serial]
        async fn $test_name() {
            let mut server = crate::test_utils::TestServer::new()
                .await
                .expect("Failed to create test server");

            server
                .authenticate_admin()
                .await
                .expect("Failed to authenticate admin");

            $test_body
        }
    };
}

/// Macro to create tests that need both admin and user authentication
#[macro_export]
macro_rules! test_with_auth {
    ($test_name:ident, $test_body:block) => {
        #[tokio::test]
        #[serial_test::serial]
        async fn $test_name() {
            let mut server = crate::test_utils::TestServer::new()
                .await
                .expect("Failed to create test server");

            server
                .authenticate_admin()
                .await
                .expect("Failed to authenticate admin");

            server
                .authenticate_user()
                .await
                .expect("Failed to authenticate user");

            $test_body
        }
    };
}
