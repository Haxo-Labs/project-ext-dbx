use anyhow::Result;
use dbx_adapter::{redis::client::RedisPool, redis::factory::RedisBackendFactory};
use dbx_api::{
    config::{AppConfig, JwtConfig},
    middleware::{JwtService, UserStore},
    models::{CreateUserRequest, UserRole},
    server::{create_app, AppState},
};
use dbx_config::{BackendConfig, DbxConfig, LoadBalancingConfig, RoutingConfig};
use dbx_core::LoadBalancingStrategy;
use dbx_router::{BackendRegistryBuilder, BackendRouter};
use reqwest::{
    header::{HeaderMap, HeaderValue, AUTHORIZATION},
    Client,
};
use serde_json::Value;
use std::collections::HashMap;
use std::{
    env,
    sync::{Arc, Once},
    time::Duration,
};
use tokio::{net::TcpListener, task::JoinHandle, time::sleep};
use uuid::Uuid;

static INIT: Once = Once::new();

/// Test configuration and state management
pub struct TestServer {
    pub base_url: String,
    pub client: Client,
    pub admin_token: Option<String>,
    pub user_token: Option<String>,
    _server_handle: JoinHandle<()>,
    port: u16,
}

impl TestServer {
    /// Create a new test server instance
    pub async fn new() -> Result<Self> {
        // Initialize logging once
        INIT.call_once(|| {
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::DEBUG)
                .with_test_writer()
                .init();
        });

        // Find available port for test server
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();

        // Use a test-specific Redis database (Redis supports databases 0-15)
        let test_db = (port % 16) as usize; // Use port to determine database
        let redis_url = format!("redis://localhost:6379/{}", test_db);

        // Set up test environment
        Self::setup_test_env(&redis_url, port)?;

        // Create application state
        let app_state = Self::create_test_app_state(&redis_url).await?;
        let app = create_app(app_state);

        // Start server
        let server_handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // Wait for server to start
        sleep(Duration::from_millis(100)).await;

        let base_url = format!("http://127.0.0.1:{}", port);
        let client = Client::new();

        Ok(Self {
            base_url,
            client,
            admin_token: None,
            user_token: None,
            _server_handle: server_handle,
            port,
        })
    }

    /// Set up test environment variables
    fn setup_test_env(redis_url: &str, port: u16) -> Result<()> {
        env::set_var(
            "JWT_SECRET",
            "test-jwt-secret-that-is-at-least-32-characters-long-for-security",
        );
        env::set_var("REDIS_URL", redis_url);
        env::set_var("HOST", "127.0.0.1");
        env::set_var("PORT", port.to_string());
        env::set_var("CREATE_DEFAULT_ADMIN", "true");
        env::set_var("DEFAULT_ADMIN_USERNAME", "testadmin");
        env::set_var("DEFAULT_ADMIN_PASSWORD", "testpassword123");
        Ok(())
    }

    /// Create application state for testing
    async fn create_test_app_state(redis_url: &str) -> Result<AppState> {
        // Create backend configuration
        let mut backends = HashMap::new();
        backends.insert(
            "default".to_string(),
            BackendConfig {
                provider: "redis".to_string(),
                url: redis_url.to_string(),
                pool_size: Some(5),
                timeout_ms: Some(5000),
                retry_attempts: Some(3),
                retry_delay_ms: Some(1000),
                capabilities: None,
                additional_config: HashMap::new(),
            },
        );

        let routing = RoutingConfig {
            default_backend: "default".to_string(),
            key_routing: Vec::new(),
            operation_routing: HashMap::new(),
            load_balancing: Some(LoadBalancingConfig {
                strategy: LoadBalancingStrategy::RoundRobin,
                backends: vec!["default".to_string()],
                health_check_interval_ms: 30000,
                weights: Some({
                    let mut weights = HashMap::new();
                    weights.insert("default".to_string(), 1.0);
                    weights
                }),
            }),
        };

        let config = DbxConfig {
            backends,
            routing,
            consistency: Default::default(),
            performance: Default::default(),
            security: Default::default(),
            server: Default::default(),
        };

        // Build backend registry
        let mut registry_builder = BackendRegistryBuilder::new();
        let redis_factory = RedisBackendFactory::new();
        registry_builder = registry_builder.with_factory("redis", redis_factory);
        let registry = registry_builder.build();

        // Initialize backends from configuration
        registry
            .initialize_backends(&config)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to initialize backends: {}", e))?;

        // Create backend router
        let backend_router = BackendRouter::new(registry, &config)
            .map_err(|e| anyhow::anyhow!("Failed to create router: {}", e))?;

        // Create Redis pool for user store
        let redis_pool = Arc::new(RedisPool::new(redis_url, 5)?);

        // Create JWT service
        let jwt_config = JwtConfig {
            secret: "test-jwt-secret-that-is-at-least-32-characters-long-for-security".to_string(),
            access_token_expiration: 900,
            refresh_token_expiration: 604800,
            issuer: "dbx-test-api".to_string(),
        };
        let jwt_service = Arc::new(JwtService::new(jwt_config));

        // Create user store with test admin
        let user_store = Arc::new(
            UserStore::new_with_admin(redis_pool.clone(), "testadmin", "testpassword123").await?,
        );

        // Create additional test users
        let test_user_request = CreateUserRequest {
            username: "testuser".to_string(),
            password: "testpassword123".to_string(),
            role: UserRole::User,
        };

        let readonly_user_request = CreateUserRequest {
            username: "testreadonly".to_string(),
            password: "testpassword123".to_string(),
            role: UserRole::ReadOnly,
        };

        // Add test users to store
        if let UserStore::Redis(store) = user_store.as_ref() {
            let _ = store.create_user_from_request(test_user_request).await;
            let _ = store.create_user_from_request(readonly_user_request).await;
        }

        Ok(AppState {
            backend_router: Arc::new(backend_router),
            jwt_service,
            user_store,
        })
    }

    /// Authenticate as admin and store token
    pub async fn authenticate_admin(&mut self) -> Result<String> {
        let auth_payload = serde_json::json!({
            "username": "testadmin",
            "password": "testpassword123"
        });

        let response = self
            .client
            .post(&format!("{}/auth/login", self.base_url))
            .json(&auth_payload)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await?;
            anyhow::bail!("Admin authentication failed: {} - {}", status, body);
        }

        let auth_response: Value = response.json().await?;

        if !auth_response
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            anyhow::bail!(
                "Admin authentication failed: {}",
                auth_response
                    .get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown error")
            );
        }

        let access_token = auth_response["data"]["access_token"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("No access token in admin auth response"))?;

        self.admin_token = Some(access_token.to_string());
        Ok(access_token.to_string())
    }

    /// Authenticate as regular user and store token
    pub async fn authenticate_user(&mut self) -> Result<String> {
        let auth_payload = serde_json::json!({
            "username": "testuser",
            "password": "testpassword123"
        });

        let response = self
            .client
            .post(&format!("{}/auth/login", self.base_url))
            .json(&auth_payload)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await?;
            anyhow::bail!("User authentication failed: {} - {}", status, body);
        }

        let auth_response: Value = response.json().await?;

        if !auth_response
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            anyhow::bail!(
                "User authentication failed: {}",
                auth_response
                    .get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown error")
            );
        }

        let access_token = auth_response["data"]["access_token"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("No access token in user auth response"))?;

        self.user_token = Some(access_token.to_string());
        Ok(access_token.to_string())
    }

    /// Get authorization header for admin requests
    pub fn get_admin_auth_header(&self) -> Result<HeaderMap> {
        let token = self
            .admin_token
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Admin not authenticated"))?;

        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", token))?,
        );
        Ok(headers)
    }

    /// Get authorization header for user requests
    pub fn get_user_auth_header(&self) -> Result<HeaderMap> {
        let token = self
            .user_token
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("User not authenticated"))?;

        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", token))?,
        );
        Ok(headers)
    }

    /// Make authenticated GET request as admin
    pub async fn get_admin(&self, path: &str) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.base_url, path);
        Ok(self
            .client
            .get(&url)
            .headers(self.get_admin_auth_header()?)
            .send()
            .await?)
    }

    /// Make authenticated POST request as admin
    pub async fn post_admin(&self, path: &str, json: &Value) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.base_url, path);
        Ok(self
            .client
            .post(&url)
            .headers(self.get_admin_auth_header()?)
            .json(json)
            .send()
            .await?)
    }

    /// Make authenticated PUT request as admin
    pub async fn put_admin(&self, path: &str, json: &Value) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.base_url, path);
        Ok(self
            .client
            .put(&url)
            .headers(self.get_admin_auth_header()?)
            .json(json)
            .send()
            .await?)
    }

    /// Make authenticated DELETE request as admin
    pub async fn delete_admin(&self, path: &str) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.base_url, path);
        Ok(self
            .client
            .delete(&url)
            .headers(self.get_admin_auth_header()?)
            .send()
            .await?)
    }

    /// Make authenticated GET request as user
    pub async fn get_user(&self, path: &str) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.base_url, path);
        Ok(self
            .client
            .get(&url)
            .headers(self.get_user_auth_header()?)
            .send()
            .await?)
    }

    /// Make authenticated POST request as user
    pub async fn post_user(&self, path: &str, json: &Value) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.base_url, path);
        Ok(self
            .client
            .post(&url)
            .headers(self.get_user_auth_header()?)
            .json(json)
            .send()
            .await?)
    }

    /// Make unauthenticated request (should fail for protected endpoints)
    pub async fn get_unauthenticated(&self, path: &str) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.base_url, path);
        Ok(self.client.get(&url).send().await?)
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
