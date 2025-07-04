pub mod common;
pub mod redis;
pub mod redis_ws;

use dbx_redis_api::{
    config::AppConfig,
    server::{create_app, AppState},
};
use std::net::SocketAddr;
use std::sync::Arc;

// Load environment variables from .env file for tests
#[ctor::ctor]
fn init() {
    dotenv::dotenv().ok();
    // Set a test JWT secret if not provided
    if std::env::var("JWT_SECRET").is_err() {
        std::env::set_var("JWT_SECRET", "test-secret-for-integration-tests-32-chars");
    }
}

pub struct TestServer {
    pub state: AppState,
    pub addr: SocketAddr,
}

impl TestServer {
    pub async fn new() -> anyhow::Result<Self> {
        // Ensure we have the minimum required environment variables for testing
        if std::env::var("JWT_SECRET").is_err() {
            std::env::set_var("JWT_SECRET", "test-secret-for-integration-tests-32-chars");
        }
        
        let state = AppState::new().await.map_err(|e| anyhow::anyhow!("Failed to create app state: {}", e))?;
        
        // Bind to port 0 to get a random available port
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        drop(listener); // Release the port so axum can bind to it
        
        Ok(Self { state, addr })
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        let app = create_app(self.state.clone());
        let listener = tokio::net::TcpListener::bind(self.addr).await?;
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                eprintln!("Server error: {}", e);
            }
        });
        tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
        Ok(())
    }
}

pub async fn get_test_server() -> Arc<TestServer> {
    let test_server = TestServer::new()
        .await
        .expect("Failed to create test server");
    test_server
        .start()
        .await
        .expect("Failed to start test server");
    Arc::new(test_server)
}

pub async fn get_test_base_url() -> String {
    let server = get_test_server().await;
    format!("http://{}", server.addr)
}

pub async fn get_test_ws_base_url() -> String {
    let server = get_test_server().await;
    format!("http://{}", server.addr)
}
