use anyhow::Result;
use dbx_adapter::{redis::client::RedisPool, redis::factory::RedisBackendFactory};
use dbx_api::{
    auth::{permissions::Permission, ApiKeyService, RbacConfig, RbacService},
    config::{AppConfig, JwtConfig},
    middleware::{JwtService, RateLimitService, UserStore, UserStoreOperations},
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

        // Use backend agnostic configuration - check for configured backend URL
        let test_db = (port % 16) as usize; // Use port to determine database
        let backend_url = std::env::var("DBX_BACKEND_1_URL")
            .unwrap_or_else(|_| format!("redis://localhost:6379/{}", test_db));

        // Set up test environment
        Self::setup_test_env(&backend_url, port)?;

        // Create application state
        let app_state = Self::create_test_app_state(&backend_url).await?;
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
    fn setup_test_env(backend_url: &str, port: u16) -> Result<()> {
        env::set_var(
            "JWT_SECRET",
            "test-jwt-secret-that-is-at-least-32-characters-long-for-security",
        );
        // Set backend agnostic configuration
        env::set_var("DBX_BACKEND_1_NAME", "test_backend");
        env::set_var("DBX_BACKEND_1_PROVIDER", "redis");
        env::set_var("DBX_BACKEND_1_URL", backend_url);
        env::set_var("DBX_DEFAULT_BACKEND", "test_backend");
        env::set_var("HOST", "127.0.0.1");
        env::set_var("PORT", port.to_string());
        env::set_var("CREATE_DEFAULT_ADMIN", "true");
        env::set_var("DEFAULT_ADMIN_USERNAME", "testadmin");
        env::set_var("DEFAULT_ADMIN_PASSWORD", "testpassword123");
        Ok(())
    }

    /// Create application state for testing
    async fn create_test_app_state(backend_url: &str) -> Result<AppState> {
        let app_state = AppState::new(None)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create app state: {}", e))?;

        Ok(app_state)
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
