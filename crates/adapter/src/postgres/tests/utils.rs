//! Shared test utilities for PostgreSQL adapter tests

use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Once};

use tokio_postgres::{connect, NoTls};

use crate::postgres::{PostgresBackend, PostgresBackendFactory, PostgresConnectionPool};
use dbx_config::BackendConfig;
use dbx_core::{DataOperation, DataValue, UniversalBackend};
use dbx_router::registry::BackendFactory;

/// Ensures database setup is only done once across all tests
static INIT: Once = Once::new();

/// Macro to skip tests if PostgreSQL is not available
macro_rules! skip_if_no_postgres {
    () => {
        if !crate::postgres::tests::utils::is_postgres_available().await {
            eprintln!("Skipping test: PostgreSQL not available");
            return;
        }
    };
}

pub(crate) use skip_if_no_postgres;

/// Get PostgreSQL test connection URL from environment or use default
pub fn get_test_postgres_url() -> String {
    env::var("TEST_POSTGRES_URL")
        .unwrap_or_else(|_| "postgresql://postgres:password@localhost:5432/dbx_test".to_string())
}

/// Create a test backend configuration
pub fn create_test_config() -> BackendConfig {
    BackendConfig {
        provider: "postgresql".to_string(),
        url: get_test_postgres_url(),
        pool_size: Some(5),
        timeout_ms: Some(5000),
        retry_attempts: Some(3),
        retry_delay_ms: Some(1000),
        capabilities: None,
        additional_config: HashMap::new(),
    }
}

/// Create a test backend configuration with custom parameters
pub fn create_custom_config(
    pool_size: Option<u32>,
    timeout_ms: Option<u64>,
    url_override: Option<String>,
) -> BackendConfig {
    BackendConfig {
        provider: "postgresql".to_string(),
        url: url_override.unwrap_or_else(get_test_postgres_url),
        pool_size,
        timeout_ms,
        retry_attempts: Some(3),
        retry_delay_ms: Some(1000),
        capabilities: None,
        additional_config: HashMap::new(),
    }
}

/// Check if PostgreSQL is available for testing
pub async fn is_postgres_available() -> bool {
    let url = get_test_postgres_url();
    match connect(&url, NoTls).await {
        Ok((client, connection)) => {
            tokio::spawn(connection);
            client.simple_query("SELECT 1").await.is_ok()
        }
        Err(_) => false,
    }
}

/// Initialize test database (create tables, etc.)
pub async fn init_test_db() {
    INIT.call_once(|| {
        println!("Initializing test database schema");
    });
}

/// Generate test data for various scenarios
pub fn generate_test_data() -> Vec<(String, DataValue)> {
    vec![
        (
            "test:string".to_string(),
            DataValue::String("test_value".to_string()),
        ),
        ("test:int".to_string(), DataValue::Int(42)),
        ("test:float".to_string(), DataValue::Float(3.14)),
        ("test:bool".to_string(), DataValue::Bool(true)),
        ("test:null".to_string(), DataValue::Null),
        (
            "test:array".to_string(),
            DataValue::Array(vec![
                DataValue::String("item1".to_string()),
                DataValue::Int(1),
                DataValue::Bool(false),
            ]),
        ),
        (
            "test:object".to_string(),
            DataValue::Object({
                let mut map = HashMap::new();
                map.insert("name".to_string(), DataValue::String("John".to_string()));
                map.insert("age".to_string(), DataValue::Int(30));
                map.insert("active".to_string(), DataValue::Bool(true));
                map
            }),
        ),
    ]
}

/// Create a test backend instance (trait object)
pub async fn create_test_backend(
) -> Result<Arc<dyn UniversalBackend>, Box<dyn std::error::Error + Send + Sync>> {
    if !is_postgres_available().await {
        return Err("PostgreSQL not available for testing".into());
    }

    init_test_db().await;

    let config = create_test_config();
    let factory = PostgresBackendFactory::new();
    let backend = factory.create_backend("test_postgres", &config).await?;

    Ok(backend)
}

/// Create a concrete test backend instance for unit tests
pub async fn create_concrete_test_backend(
) -> Result<PostgresBackend, Box<dyn std::error::Error + Send + Sync>> {
    if !is_postgres_available().await {
        return Err("PostgreSQL not available for testing".into());
    }

    init_test_db().await;

    let config = create_test_config();
    let pool = PostgresConnectionPool::new(&config.url, config.pool_size.unwrap_or(5) as usize)?;
    let backend = PostgresBackend::new(Arc::new(pool), "test_postgres".to_string());

    Ok(backend)
}

/// Clean up test data with a given key prefix
pub async fn cleanup_test_data(backend: &dyn UniversalBackend, key_prefix: &str) {
    let test_keys = [
        format!("{}:string", key_prefix),
        format!("{}:int", key_prefix),
        format!("{}:float", key_prefix),
        format!("{}:bool", key_prefix),
        format!("{}:null", key_prefix),
        format!("{}:array", key_prefix),
        format!("{}:object", key_prefix),
    ];

    for key in &test_keys {
        let delete_op = DataOperation::Delete {
            key: key.clone(),
            fields: None,
        };
        let _ = backend.execute_data(delete_op).await;
    }
}
