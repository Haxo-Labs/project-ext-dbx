pub mod auth;
pub mod config;
pub mod constants;
pub mod middleware;
pub mod models;
pub mod routes;
pub mod server;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_helpers {
    use dbx_core::{
        BackendCapabilities, BackendHealth, BackendStats, ConnectionStats, DataOperation,
        DataOperationType, DataResult, DataValue, DbxError, HealthStatus, OperationStats,
        PerformanceStats, QueryCapabilities, QueryOperation, QueryResult, StorageStats,
        StreamCapabilities, StreamOperation, StreamResult, TransactionSupport, UniversalBackend,
    };
    use once_cell::sync::Lazy;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use uuid::Uuid;

    /// Shared data store for all mock backend instances
    static SHARED_MOCK_DATA: Lazy<Arc<RwLock<HashMap<String, String>>>> =
        Lazy::new(|| Arc::new(RwLock::new(HashMap::new())));

    /// Mock backend for testing
    #[derive(Clone)]
    pub struct MockBackend {
        name: String,
        data: Arc<RwLock<HashMap<String, String>>>,
    }

    impl MockBackend {
        pub fn new(name: String) -> Self {
            Self {
                name,
                data: SHARED_MOCK_DATA.clone(),
            }
        }

        pub async fn clear(&self) {
            self.data.write().await.clear();
        }

        /// Clear the shared data store (for test isolation)
        pub async fn clear_shared_data() {
            SHARED_MOCK_DATA.write().await.clear();
        }

        pub async fn insert_data(&self, key: String, value: String) {
            self.data.write().await.insert(key, value);
        }

        pub async fn populate_test_data(&self) {
            let mut data = self.data.write().await;

            // Test admin user data with bcrypt hash
            let admin_user = serde_json::json!({
                "id": "test-admin-uuid",
                "username": "testadmin",
                "password_hash": "$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi", // Known bcrypt hash for "password"
                "role": "Admin", // Keep UserRole::Admin for deserialization
                "created_at": chrono::Utc::now().to_rfc3339(),
                "updated_at": chrono::Utc::now().to_rfc3339(),
                "is_active": true
            });

            let test_user = serde_json::json!({
                "id": "test-user-uuid",
                "username": "testuser",
                "password_hash": "$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi", // Known bcrypt hash for "password"
                "role": "User", // Keep UserRole::User for deserialization
                "created_at": chrono::Utc::now().to_rfc3339(),
                "updated_at": chrono::Utc::now().to_rfc3339(),
                "is_active": true
            });

            // Store user data accessible by both username and ID
            data.insert(
                "user:username:testadmin".to_string(),
                serde_json::to_string(&admin_user).unwrap(),
            );
            data.insert(
                "user:id:test-admin-uuid".to_string(),
                serde_json::to_string(&admin_user).unwrap(),
            );
            data.insert(
                "user:username:testuser".to_string(),
                serde_json::to_string(&test_user).unwrap(),
            );
            data.insert(
                "user:id:test-user-uuid".to_string(),
                serde_json::to_string(&test_user).unwrap(),
            );

            // Create RBAC role assignments for test users
            let admin_assignment = serde_json::json!({
                "user_id": "test-admin-uuid",
                "username": "testadmin",
                "role_name": "admin",
                "assigned_by": "system",
                "assigned_at": chrono::Utc::now().to_rfc3339(),
                "expires_at": null,
                "is_active": true,
                "metadata": null
            });

            let user_assignment = serde_json::json!({
                "user_id": "test-user-uuid",
                "username": "testuser",
                "role_name": "user",
                "assigned_by": "system",
                "assigned_at": chrono::Utc::now().to_rfc3339(),
                "expires_at": null,
                "is_active": true,
                "metadata": null
            });

            // Store role assignment records
            data.insert(
                "rbac:assignment:test-admin-uuid:admin".to_string(),
                serde_json::to_string(&admin_assignment).unwrap(),
            );
            data.insert(
                "rbac:assignment:test-user-uuid:user".to_string(),
                serde_json::to_string(&user_assignment).unwrap(),
            );
        }

        /// Simple glob pattern matching for mock backend
        fn matches_pattern(&self, text: &str, pattern: &str) -> bool {
            // Simple pattern matching: * matches any characters, ? matches single char
            if pattern == "*" {
                return true;
            }

            // For now, just implement prefix matching for patterns ending with *
            if pattern.ends_with('*') {
                let prefix = &pattern[..pattern.len() - 1];
                return text.starts_with(prefix);
            }

            // Exact match if no wildcards
            text == pattern
        }
    }

    #[async_trait::async_trait]
    impl UniversalBackend for MockBackend {
        fn name(&self) -> &str {
            &self.name
        }

        fn capabilities(&self) -> BackendCapabilities {
            BackendCapabilities {
                data_operations: vec![
                    DataOperationType::Get,
                    DataOperationType::Set,
                    DataOperationType::Delete,
                    DataOperationType::Exists,
                    DataOperationType::Update,
                    DataOperationType::GetTtl,
                    DataOperationType::SetTtl,
                    DataOperationType::Batch,
                ],
                query_capabilities: QueryCapabilities {
                    key_patterns: true,
                    field_filters: false,
                    range_queries: false,
                    text_search: false,
                    logical_operations: false,
                    aggregations: false,
                    sorting: false,
                    pagination: false,
                },
                stream_capabilities: StreamCapabilities {
                    pub_sub: false,
                    streams: false,
                    persistent_streams: false,
                    stream_groups: false,
                },
                transaction_support: TransactionSupport::None,
                features: vec![],
            }
        }

        async fn execute_data(&self, operation: DataOperation) -> Result<DataResult, DbxError> {
            let operation_id = Uuid::new_v4();
            let mut data = self.data.write().await;

            match operation {
                DataOperation::Get { key, .. } => {
                    if let Some(value) = data.get(&key) {
                        // For user/role/rbac data, always return as string for deserialization
                        if key.starts_with("user:")
                            || key.starts_with("role:")
                            || key.starts_with("rbac:")
                        {
                            Ok(DataResult::success(
                                operation_id,
                                DataValue::String(value.clone()),
                            ))
                        } else {
                            // For rate limiting bit vector data, return as string for JSON deserialization
                            if key.contains("rate_limit_bv:") || key.contains("rate_limit:") {
                                Ok(DataResult::success(
                                    operation_id,
                                    DataValue::String(value.clone()),
                                ))
                            } else {
                                // For hash data, try to parse as JSON to return structured data
                                if let Ok(json_value) =
                                    serde_json::from_str::<serde_json::Value>(value)
                                {
                                    match json_value {
                                        serde_json::Value::Object(map) => {
                                            let mut result_map = HashMap::new();
                                            for (k, v) in map {
                                                let data_value = match v {
                                                    serde_json::Value::String(s) => {
                                                        DataValue::String(s)
                                                    }
                                                    serde_json::Value::Number(n) => {
                                                        if let Some(i) = n.as_i64() {
                                                            DataValue::Int(i)
                                                        } else if let Some(f) = n.as_f64() {
                                                            DataValue::Float(f)
                                                        } else {
                                                            DataValue::String(n.to_string())
                                                        }
                                                    }
                                                    serde_json::Value::Bool(b) => {
                                                        DataValue::Bool(b)
                                                    }
                                                    serde_json::Value::Null => DataValue::Null,
                                                    _ => DataValue::String(v.to_string()),
                                                };
                                                result_map.insert(k, data_value);
                                            }
                                            Ok(DataResult::success(
                                                operation_id,
                                                DataValue::Object(result_map),
                                            ))
                                        }
                                        _ => Ok(DataResult::success(
                                            operation_id,
                                            DataValue::String(value.clone()),
                                        )),
                                    }
                                } else {
                                    Ok(DataResult::success(
                                        operation_id,
                                        DataValue::String(value.clone()),
                                    ))
                                }
                            }
                        }
                    } else {
                        Ok(DataResult::empty_success(operation_id))
                    }
                }
                DataOperation::Set { key, value, ttl: _ } => match value {
                    DataValue::String(s) => {
                        data.insert(key, s);
                        Ok(DataResult::success(operation_id, DataValue::Bool(true)))
                    }
                    DataValue::Object(map) => {
                        let json_obj: serde_json::Map<String, serde_json::Value> = map
                            .into_iter()
                            .map(|(k, v)| {
                                let json_val = match v {
                                    DataValue::String(s) => serde_json::Value::String(s),
                                    DataValue::Int(i) => {
                                        serde_json::Value::Number(serde_json::Number::from(i))
                                    }
                                    DataValue::Float(f) => serde_json::Value::Number(
                                        serde_json::Number::from_f64(f)
                                            .unwrap_or_else(|| serde_json::Number::from(0)),
                                    ),
                                    DataValue::Bool(b) => serde_json::Value::Bool(b),
                                    DataValue::Null => serde_json::Value::Null,
                                    _ => serde_json::Value::String(format!("{:?}", v)),
                                };
                                (k, json_val)
                            })
                            .collect();
                        let json_string = serde_json::to_string(&json_obj).map_err(|e| {
                            DbxError::Serialization {
                                message: format!("Failed to serialize object: {}", e),
                            }
                        })?;
                        data.insert(key, json_string);
                        Ok(DataResult::success(operation_id, DataValue::Bool(true)))
                    }
                    DataValue::Array(arr) => {
                        let json_array: Vec<serde_json::Value> = arr
                            .into_iter()
                            .map(|v| match v {
                                DataValue::String(s) => serde_json::Value::String(s),
                                DataValue::Int(i) => {
                                    serde_json::Value::Number(serde_json::Number::from(i))
                                }
                                DataValue::Float(f) => serde_json::Value::Number(
                                    serde_json::Number::from_f64(f)
                                        .unwrap_or_else(|| serde_json::Number::from(0)),
                                ),
                                DataValue::Bool(b) => serde_json::Value::Bool(b),
                                DataValue::Null => serde_json::Value::Null,
                                _ => serde_json::Value::String(format!("{:?}", v)),
                            })
                            .collect();
                        let json_string = serde_json::to_string(&json_array).map_err(|e| {
                            DbxError::Serialization {
                                message: format!("Failed to serialize array: {}", e),
                            }
                        })?;
                        data.insert(key, json_string);
                        Ok(DataResult::success(operation_id, DataValue::Bool(true)))
                    }
                    DataValue::Int(i) => {
                        data.insert(key, i.to_string());
                        Ok(DataResult::success(operation_id, DataValue::Bool(true)))
                    }
                    _ => {
                        data.insert(key, format!("{:?}", value));
                        Ok(DataResult::success(operation_id, DataValue::Bool(true)))
                    }
                },
                DataOperation::Update { key, fields, .. } => {
                    // For hash operations, store fields as a JSON object
                    let json_obj: serde_json::Map<String, serde_json::Value> = fields
                        .into_iter()
                        .map(|(k, v)| {
                            let json_val = match v {
                                DataValue::String(s) => serde_json::Value::String(s),
                                DataValue::Int(i) => {
                                    serde_json::Value::Number(serde_json::Number::from(i))
                                }
                                DataValue::Float(f) => serde_json::Value::Number(
                                    serde_json::Number::from_f64(f)
                                        .unwrap_or_else(|| serde_json::Number::from(0)),
                                ),
                                DataValue::Bool(b) => serde_json::Value::Bool(b),
                                DataValue::Null => serde_json::Value::Null,
                                _ => serde_json::Value::String(format!("{:?}", v)),
                            };
                            (k, json_val)
                        })
                        .collect();

                    let json_string =
                        serde_json::to_string(&json_obj).map_err(|e| DbxError::Serialization {
                            message: format!("Failed to serialize fields: {}", e),
                        })?;
                    data.insert(key, json_string);
                    Ok(DataResult::success(operation_id, DataValue::Bool(true)))
                }
                DataOperation::Delete { key, .. } => {
                    let existed = data.remove(&key).is_some();
                    Ok(DataResult::success(operation_id, DataValue::Bool(existed)))
                }
                DataOperation::Exists { key, .. } => {
                    let exists = data.contains_key(&key);
                    Ok(DataResult::success(operation_id, DataValue::Bool(exists)))
                }
                DataOperation::GetTtl { .. } => {
                    Ok(DataResult::success(operation_id, DataValue::Int(-1)))
                }
                DataOperation::SetTtl { .. } => {
                    Ok(DataResult::success(operation_id, DataValue::Bool(true)))
                }
                DataOperation::Batch { operations } => {
                    // Execute batch operations directly on the data store without recursion

                    let mut results = Vec::new();

                    for op in operations {
                        let op_id = Uuid::new_v4();
                        let result = match op {
                            DataOperation::Get { key, .. } => {
                                let value = data.get(&key).cloned().unwrap_or_default();
                                DataResult::success(op_id, DataValue::String(value))
                            }
                            DataOperation::Set { key, value, .. } => {
                                let string_value = match value {
                                    DataValue::String(s) => s.clone(),
                                    DataValue::Int(i) => i.to_string(),
                                    DataValue::Float(f) => f.to_string(),
                                    DataValue::Bool(b) => b.to_string(),
                                    _ => "null".to_string(),
                                };
                                data.insert(key.clone(), string_value);
                                DataResult::success(op_id, DataValue::Bool(true))
                            }
                            DataOperation::Delete { key, .. } => {
                                let existed = data.remove(&key).is_some();
                                DataResult::success(op_id, DataValue::Bool(existed))
                            }
                            DataOperation::Update { key, fields, .. } => {
                                if let Some(existing_value) = data.get(&key) {
                                    let mut updated_value = existing_value.clone();
                                    for (field, value) in fields {
                                        let field_value = match value {
                                            DataValue::String(s) => s.clone(),
                                            DataValue::Int(i) => i.to_string(),
                                            DataValue::Float(f) => f.to_string(),
                                            DataValue::Bool(b) => b.to_string(),
                                            _ => "null".to_string(),
                                        };
                                        updated_value
                                            .push_str(&format!("{}:{}", field, field_value));
                                    }
                                    data.insert(key.clone(), updated_value);
                                    DataResult::success(op_id, DataValue::Bool(true))
                                } else {
                                    DataResult::success(op_id, DataValue::Bool(false))
                                }
                            }
                            DataOperation::Exists { key, .. } => {
                                let exists = data.contains_key(&key);
                                DataResult::success(op_id, DataValue::Bool(exists))
                            }
                            DataOperation::GetTtl { .. } => {
                                DataResult::success(op_id, DataValue::Int(-1))
                            }
                            DataOperation::SetTtl { .. } => {
                                DataResult::success(op_id, DataValue::Bool(true))
                            }
                            DataOperation::Batch { .. } => {
                                // Prevent infinite nesting
                                return Err(DbxError::validation(
                                    "Nested batch operations not supported".to_string(),
                                ));
                            }
                        };
                        results.push(result);
                    }

                    let result_values: Vec<DataValue> = results
                        .into_iter()
                        .map(|r| DataValue::String(format!("{:?}", r)))
                        .collect();
                    Ok(DataResult::success(
                        operation_id,
                        DataValue::Array(result_values),
                    ))
                }
            }
        }

        async fn execute_query(&self, operation: QueryOperation) -> Result<QueryResult, DbxError> {
            match operation.filter {
                dbx_core::QueryFilter::KeyPattern { pattern } => {
                    let data = self.data.read().await;
                    let mut results = Vec::new();

                    // Simple glob pattern matching
                    for key in data.keys() {
                        if self.matches_pattern(key, &pattern) {
                            if let Some(value) = data.get(key) {
                                results.push(dbx_core::QueryResultItem {
                                    key: key.clone(),
                                    data: DataValue::String(value.clone()),
                                    score: None,
                                });
                            }
                        }
                    }

                    Ok(QueryResult::success(operation.id, results))
                }
                _ => Ok(QueryResult::success(operation.id, vec![])),
            }
        }

        async fn execute_stream(
            &self,
            _operation: StreamOperation,
        ) -> Result<StreamResult, DbxError> {
            // Mock stream execution - return an error since this is just a mock
            Ok(StreamResult::Error {
                operation_id: Uuid::new_v4(),
                error: DbxError::unsupported_operation("stream", &self.name),
            })
        }

        async fn health_check(&self) -> Result<BackendHealth, DbxError> {
            Ok(BackendHealth {
                status: HealthStatus::Healthy,
                response_time_ms: Some(1),
                details: None,
                last_check: chrono::Utc::now(),
            })
        }

        async fn get_stats(&self) -> Result<BackendStats, DbxError> {
            let data_count = self.data.read().await.len() as u64;
            Ok(BackendStats {
                connections: ConnectionStats {
                    active: 1,
                    idle: 0,
                    total: 1,
                    max_pool_size: 10,
                },
                operations: OperationStats {
                    total_operations: 0,
                    successful_operations: 0,
                    failed_operations: 0,
                    operations_per_second: 0.0,
                },
                performance: PerformanceStats {
                    avg_response_time_ms: 1.0,
                    p95_response_time_ms: 2.0,
                    p99_response_time_ms: 3.0,
                },
                storage: Some(StorageStats {
                    used_memory_bytes: data_count * 64,
                    total_memory_bytes: Some(1024 * 1024),
                    key_count: data_count,
                    database_size_bytes: Some(data_count * 64),
                }),
            })
        }

        async fn test_connection(&self) -> Result<(), DbxError> {
            Ok(())
        }
    }

    /// Create a mock backend for unit tests
    pub fn create_mock_backend() -> Arc<dyn UniversalBackend> {
        Arc::new(MockBackend::new("test_mock".to_string()))
    }

    /// Create a mock backend with pre-populated test data
    pub async fn create_mock_backend_with_data() -> Arc<dyn UniversalBackend> {
        let backend = MockBackend::new("test_mock".to_string());
        backend.populate_test_data().await;
        Arc::new(backend)
    }

    /// Mock backend factory for testing
    pub struct MockBackendFactory {
        auto_populate_data: bool,
    }

    impl MockBackendFactory {
        pub fn new() -> Self {
            Self {
                auto_populate_data: true,
            }
        }

        pub fn new_empty() -> Self {
            Self {
                auto_populate_data: false,
            }
        }
    }

    #[async_trait::async_trait]
    impl dbx_router::registry::BackendFactory for MockBackendFactory {
        async fn create_backend(
            &self,
            name: &str,
            config: &dbx_config::BackendConfig,
        ) -> Result<Arc<dyn UniversalBackend>, dbx_router::RouterError> {
            // Validate configuration
            if config.provider != "mock" {
                return Err(dbx_router::RouterError::backend_initialization(
                    name.to_string(),
                    format!(
                        "MockBackendFactory only supports 'mock' provider, got '{}'",
                        config.provider
                    ),
                ));
            }

            // Validate URL format (should be mock://...)
            if !config.url.starts_with("mock://") {
                return Err(dbx_router::RouterError::backend_initialization(
                    name.to_string(),
                    format!(
                        "Invalid mock URL format: '{}'. Expected format: 'mock://host'",
                        config.url
                    ),
                ));
            }

            // Clear shared data first for test isolation
            MockBackend::clear_shared_data().await;

            // Create mock backend
            let backend = MockBackend::new(name.to_string());

            // Populate test data if configured
            if self.auto_populate_data {
                backend.populate_test_data().await;
            }

            Ok(Arc::new(backend))
        }

        fn provider_name(&self) -> &str {
            "mock"
        }

        fn validate_config(
            &self,
            config: &dbx_config::BackendConfig,
        ) -> Result<(), dbx_router::RouterError> {
            if config.provider != "mock" {
                return Err(dbx_router::RouterError::routing_configuration(format!(
                    "Invalid provider '{}' for MockBackendFactory. Expected 'mock'",
                    config.provider
                )));
            }

            if !config.url.starts_with("mock://") {
                return Err(dbx_router::RouterError::routing_configuration(format!(
                    "Invalid mock URL format: '{}'. Expected format: 'mock://host'",
                    config.url
                )));
            }

            // Validate pool size if specified
            if let Some(pool_size) = config.pool_size {
                if pool_size == 0 {
                    return Err(dbx_router::RouterError::routing_configuration(
                        "Pool size must be greater than 0".to_string(),
                    ));
                }
            }

            Ok(())
        }
    }

    /// Test configuration factory
    pub struct TestConfig;

    impl TestConfig {
        /// Create AppConfig for testing
        pub fn create_app_config() -> crate::config::AppConfig {
            crate::config::AppConfig {
                server: crate::config::ServerConfig {
                    host: "127.0.0.1".to_string(),
                    port: 3000,
                },
                jwt: crate::config::JwtConfig {
                    secret: "test-secret-key-that-is-at-least-32-characters-long".to_string(),
                    access_token_expiration: 3600,
                    refresh_token_expiration: 86400,
                    issuer: "test-issuer".to_string(),
                },
                rbac: crate::auth::rbac::RbacConfig {
                    audit_enabled: true,
                    audit_retention_days: 90,
                    max_role_inheritance_depth: 5,
                    performance_cache_ttl_seconds: 300,
                    default_assignment_ttl_days: None,
                },
                rate_limit: crate::config::RateLimitConfig {
                    enabled: true,
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
            }
        }

        /// Create a DbxConfig for testing with mock backend
        pub fn create_dbx_config() -> dbx_config::DbxConfig {
            // Use the default configuration and override what we need
            let mut config = dbx_config::DbxConfig::default();

            // Set up mock backend
            let mut backends = std::collections::HashMap::new();
            backends.insert(
                "test_backend".to_string(),
                dbx_config::BackendConfig {
                    provider: "mock".to_string(),
                    url: "mock://localhost:6379".to_string(),
                    pool_size: Some(10),
                    timeout_ms: Some(30000),
                    retry_attempts: Some(3),
                    retry_delay_ms: Some(1000),
                    capabilities: None,
                    additional_config: std::collections::HashMap::new(),
                },
            );

            config.backends = backends;
            config.routing.default_backend = "test_backend".to_string();
            config
        }

        /// Create rate limit policy for testing
        pub fn create_rate_limit_policy() -> crate::models::RateLimitPolicy {
            crate::models::RateLimitPolicy {
                requests: 100,
                window_seconds: 60,
                burst_allowance: Some(10),
            }
        }
    }

    /// AppState builder for testing
    pub struct TestAppStateBuilder {
        populate_data: bool,
    }

    impl TestAppStateBuilder {
        pub fn new() -> Self {
            Self {
                populate_data: true,
            }
        }

        pub fn without_data_population(mut self) -> Self {
            self.populate_data = false;
            self
        }

        /// Build AppState with mock backend registration
        pub async fn build(self) -> Result<crate::server::AppState, crate::server::ServerError> {
            let app_config = TestConfig::create_app_config();
            let dbx_config = TestConfig::create_dbx_config();

            // Build backend registry with mock factory registered
            let mut registry_builder = dbx_router::registry::BackendRegistryBuilder::new();

            // Register Redis backend factory for completeness
            let redis_factory = dbx_adapter::redis::factory::RedisBackendFactory::new();
            registry_builder = registry_builder.with_factory("redis", redis_factory);

            // Register mock backend factory with data population control
            let mock_factory = if self.populate_data {
                MockBackendFactory::new()
            } else {
                MockBackendFactory::new_empty()
            };
            registry_builder = registry_builder.with_factory("mock", mock_factory);

            // Build the registry
            let registry = registry_builder.build();

            // Initialize backends from configuration
            registry
                .initialize_backends(&dbx_config)
                .await
                .map_err(|e| {
                    crate::server::ServerError::DatabaseConnection(format!(
                        "Failed to initialize backends: {}",
                        e
                    ))
                })?;

            // Create backend router
            let backend_router =
                dbx_router::BackendRouter::new(registry, &dbx_config).map_err(|e| {
                    crate::server::ServerError::DatabaseConnection(format!(
                        "Failed to create backend router: {}",
                        e
                    ))
                })?;

            // Get auth backend for service creation
            let auth_backend = backend_router
                .get_backend(&dbx_config.routing.default_backend)
                .await
                .ok_or_else(|| {
                    crate::server::ServerError::DatabaseConnection(format!(
                        "Failed to get default backend: {}",
                        dbx_config.routing.default_backend
                    ))
                })?;

            // Create all services with dependencies
            let user_store = std::sync::Arc::new(crate::middleware::auth::UserStore::new(
                auth_backend.clone(),
            ));
            let jwt_service = std::sync::Arc::new(crate::middleware::auth::JwtService::new(
                app_config.jwt.clone(),
                user_store.clone(),
            ));
            let api_key_service =
                std::sync::Arc::new(crate::auth::ApiKeyService::new(auth_backend.clone()));
            let rbac_service = std::sync::Arc::new(crate::auth::rbac::RbacService::new(
                auth_backend.clone(),
                app_config.rbac.clone(),
            ));

            // Register capitalized roles to match UserRole enum variants
            if self.populate_data {
                // Remove custom role registration - using existing default roles instead
            }

            // Create rate limit service
            let rate_limit_service = std::sync::Arc::new(
                crate::middleware::rate_limit::PolicyRateLimitService::new(auth_backend),
            );

            Ok(crate::server::AppState {
                backend_router: std::sync::Arc::new(backend_router),
                jwt_service,
                user_store,
                api_key_service,
                rbac_service,
                rate_limit_service,
            })
        }
    }

    /// Convenience function to create a standard test AppState
    pub async fn create_test_app_state(
    ) -> Result<crate::server::AppState, crate::server::ServerError> {
        TestAppStateBuilder::new().build().await
    }

    /// Convenience function to create a test AppState without pre-populated data
    pub async fn create_empty_test_app_state(
    ) -> Result<crate::server::AppState, crate::server::ServerError> {
        TestAppStateBuilder::new()
            .without_data_population()
            .build()
            .await
    }
}
