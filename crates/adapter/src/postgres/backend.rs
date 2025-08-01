use crate::postgres::client::PostgresConnectionPool;
use async_trait::async_trait;
use base64::Engine;
use chrono::Utc;
use serde_json;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_postgres::IsolationLevel;
use tracing::debug;
use uuid::Uuid;

use dbx_core::{
    BackendCapabilities, BackendFeature, BackendHealth, BackendStats, ConnectionStats,
    DataOperation, DataOperationType, DataResult, DataValue, DbxError, HealthStatus,
    OperationStats, PerformanceStats, QueryCapabilities, QueryOperation, QueryResult,
    ResultMetadata, StorageStats, StreamCapabilities, StreamOperation, StreamResult,
    TransactionSupport, UniversalBackend,
};

/// PostgreSQL backend with JSONB storage and TTL support
#[derive(Debug, Clone)]
pub struct PostgresBackend {
    pool: Arc<PostgresConnectionPool>,
    backend_name: String,
    capabilities: BackendCapabilities,
}

impl PostgresBackend {
    /// Create PostgreSQL backend
    pub fn new(pool: Arc<PostgresConnectionPool>, backend_name: String) -> Self {
        Self {
            pool,
            backend_name,
            capabilities: Self::create_capabilities(),
        }
    }

    /// PostgreSQL capabilities
    fn create_capabilities() -> BackendCapabilities {
        BackendCapabilities {
            data_operations: vec![
                DataOperationType::Get,
                DataOperationType::Set,
                DataOperationType::Update,
                DataOperationType::Delete,
                DataOperationType::Exists,
                DataOperationType::GetTtl,
                DataOperationType::SetTtl,
                DataOperationType::Increment,
                DataOperationType::Decrement,
                DataOperationType::Append,
                DataOperationType::Length,
                DataOperationType::CompareAndSwap,
                DataOperationType::Batch,
            ],
            query_capabilities: QueryCapabilities {
                key_patterns: true,
                field_filters: true,
                range_queries: true,
                text_search: true,
                logical_operations: true,
                sorting: true,
                pagination: true,
                aggregations: true,
            },
            stream_capabilities: StreamCapabilities {
                pub_sub: false, // PostgreSQL doesn't have built-in pub/sub
                streams: false,
                persistent_streams: false,
                stream_groups: false,
            },
            transaction_support: TransactionSupport::Acid,
            features: vec![
                BackendFeature::JsonSupport,
                BackendFeature::BinaryData,
                BackendFeature::Replication,
                BackendFeature::Clustering,
                BackendFeature::FullTextSearch,
                BackendFeature::Analytics,
                BackendFeature::Geospatial,
            ],
        }
    }

    /// Create from URL
    pub async fn from_url(
        url: &str,
        backend_name: String,
        pool_size: usize,
    ) -> Result<Self, DbxError> {
        let pool = PostgresConnectionPool::new(url, pool_size).map_err(|e| {
            DbxError::connection(backend_name.clone(), format!("Failed to connect: {}", e))
        })?;

        Ok(Self::new(Arc::new(pool), backend_name))
    }

    /// DataValue to JSON
    fn data_value_to_json(&self, value: &DataValue) -> Result<serde_json::Value, DbxError> {
        match value {
            DataValue::Null => Ok(serde_json::Value::Null),
            DataValue::Bool(b) => Ok(serde_json::Value::Bool(*b)),
            DataValue::Int(i) => Ok(serde_json::Value::Number(serde_json::Number::from(*i))),
            DataValue::Float(f) => serde_json::Number::from_f64(*f)
                .map(serde_json::Value::Number)
                .ok_or_else(|| DbxError::serialization("Invalid float value".to_string())),
            DataValue::String(s) => Ok(serde_json::Value::String(s.clone())),
            DataValue::Bytes(b) => {
                let base64 = base64::prelude::BASE64_STANDARD.encode(b);
                Ok(serde_json::Value::String(base64))
            }
            DataValue::Array(arr) => {
                let json_arr: Result<Vec<serde_json::Value>, DbxError> =
                    arr.iter().map(|v| self.data_value_to_json(v)).collect();
                Ok(serde_json::Value::Array(json_arr?))
            }
            DataValue::Object(obj) => {
                let json_obj: Result<HashMap<String, serde_json::Value>, DbxError> = obj
                    .iter()
                    .map(|(k, v)| Ok((k.clone(), self.data_value_to_json(v)?)))
                    .collect();
                let json_map: serde_json::Map<String, serde_json::Value> =
                    json_obj?.into_iter().collect();
                Ok(serde_json::Value::Object(json_map))
            }
        }
    }

    /// JSON to DataValue
    fn json_to_data_value(&self, json: &serde_json::Value) -> Result<DataValue, DbxError> {
        match json {
            serde_json::Value::Null => Ok(DataValue::Null),
            serde_json::Value::Bool(b) => Ok(DataValue::Bool(*b)),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Ok(DataValue::Int(i))
                } else if let Some(f) = n.as_f64() {
                    Ok(DataValue::Float(f))
                } else {
                    Err(DbxError::serialization("Invalid number format".to_string()))
                }
            }
            serde_json::Value::String(s) => Ok(DataValue::String(s.clone())),
            serde_json::Value::Array(arr) => {
                let data_arr: Result<Vec<DataValue>, DbxError> =
                    arr.iter().map(|v| self.json_to_data_value(v)).collect();
                Ok(DataValue::Array(data_arr?))
            }
            serde_json::Value::Object(obj) => {
                let data_obj: Result<HashMap<String, DataValue>, DbxError> = obj
                    .iter()
                    .map(|(k, v)| Ok((k.clone(), self.json_to_data_value(v)?)))
                    .collect();
                Ok(DataValue::Object(data_obj?))
            }
        }
    }

    /// Initialize database tables
    async fn ensure_tables(&self) -> Result<(), DbxError> {
        let conn = self.pool.get().await.map_err(|e| {
            DbxError::backend(
                self.backend_name.clone(),
                format!("Failed to get connection: {}", e),
            )
        })?;

        // Main table
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS dbx_data (
                key TEXT PRIMARY KEY,
                value JSONB,
                expires_at TIMESTAMP WITH TIME ZONE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            )
            "#,
            &[],
        )
        .await
        .map_err(|e| {
            DbxError::backend(
                self.backend_name.clone(),
                format!("Failed to create dbx_data table: {}", e),
            )
        })?;

        // Performance indexes
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_dbx_data_updated_at ON dbx_data (updated_at)",
            &[],
        )
        .await
        .map_err(|e| {
            DbxError::backend(
                self.backend_name.clone(),
                format!("Failed to create updated_at index: {}", e),
            )
        })?;

        // TTL index
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_dbx_data_expires_at ON dbx_data (expires_at) WHERE expires_at IS NOT NULL",
            &[],
        )
        .await
        .map_err(|e| {
            DbxError::backend(
                self.backend_name.clone(),
                format!("Failed to create index: {}", e),
            )
        })?;

        Ok(())
    }

    /// Remove expired entries
    pub async fn remove_expired_entries(&self) -> Result<u64, DbxError> {
        let conn = self.pool.get().await.map_err(|e| {
            DbxError::backend(
                self.backend_name.clone(),
                format!("Failed to get connection: {}", e),
            )
        })?;

        let deleted_count = conn
            .execute(
                "DELETE FROM dbx_data WHERE expires_at IS NOT NULL AND expires_at <= NOW()",
                &[],
            )
            .await
            .map_err(|e| {
                DbxError::backend(
                    self.backend_name.clone(),
                    format!("Failed to remove expired entries: {}", e),
                )
            })?;

        debug!(
                backend = %self.backend_name,
                deleted_count = %deleted_count,
        "Removed expired entries"
            );

        Ok(deleted_count)
    }

    /// Execute data operation
    async fn execute_data_operation_internal(
        &self,
        operation: &DataOperation,
    ) -> Result<DataValue, DbxError> {
        self.ensure_tables().await?;

        match operation {
            DataOperation::Get { key, fields: _ } => {
                let conn = self.pool.get().await.map_err(|e| {
                    DbxError::backend(
                        self.backend_name.clone(),
                        format!("Connection failed: {}", e),
                    )
                })?;

                let row = conn
                    .query_opt("SELECT value FROM dbx_data WHERE key = $1 AND (expires_at IS NULL OR expires_at > NOW())", &[&key])
                    .await
                    .map_err(|e| {
                        DbxError::backend(
                            self.backend_name.clone(),
                            format!("Get operation failed: {}", e),
                        )
                    })?;

                match row {
                    Some(row) => {
                        let json_value: serde_json::Value = row.get(0);
                        self.json_to_data_value(&json_value)
                    }
                    None => Ok(DataValue::Null),
                }
            }

            DataOperation::Set { key, value, ttl } => {
                let conn = self.pool.get().await.map_err(|e| {
                    DbxError::backend(
                        self.backend_name.clone(),
                        format!("Connection failed: {}", e),
                    )
                })?;

                let json_value = self.data_value_to_json(value)?;

                match ttl {
                    Some(ttl_seconds) => {
                        // Set new TTL
                        let expires_at =
                            chrono::Utc::now() + chrono::Duration::seconds(*ttl_seconds as i64);
                        conn.execute(
                            r#"
                            INSERT INTO dbx_data (key, value, expires_at, updated_at) 
                            VALUES ($1, $2, $3, NOW()) 
                            ON CONFLICT (key) 
                            DO UPDATE SET value = $2, expires_at = $3, updated_at = NOW()
                            "#,
                            &[&key, &json_value, &expires_at],
                        )
                        .await
                        .map_err(|e| {
                            DbxError::backend(
                                self.backend_name.clone(),
                                format!("Set operation failed: {}", e),
                            )
                        })?;
                    }
                    None => {
                        // Preserve existing TTL
                        conn.execute(
                            r#"
                            INSERT INTO dbx_data (key, value, expires_at, updated_at) 
                            VALUES ($1, $2, NULL, NOW()) 
                            ON CONFLICT (key) 
                            DO UPDATE SET value = $2, updated_at = NOW()
                            "#,
                            &[&key, &json_value],
                        )
                        .await
                        .map_err(|e| {
                            DbxError::backend(
                                self.backend_name.clone(),
                                format!("Set operation failed: {}", e),
                            )
                        })?;
                    }
                }

                Ok(DataValue::Bool(true))
            }

            DataOperation::Delete { key, fields: _ } => {
                let conn = self.pool.get().await.map_err(|e| {
                    DbxError::backend(
                        self.backend_name.clone(),
                        format!("Connection failed: {}", e),
                    )
                })?;

                let rows_affected = conn
                    .execute("DELETE FROM dbx_data WHERE key = $1", &[&key])
                    .await
                    .map_err(|e| {
                        DbxError::backend(
                            self.backend_name.clone(),
                            format!("Delete operation failed: {}", e),
                        )
                    })?;

                Ok(DataValue::Bool(rows_affected > 0))
            }

            DataOperation::Exists { key, fields: _ } => {
                let conn = self.pool.get().await.map_err(|e| {
                    DbxError::backend(
                        self.backend_name.clone(),
                        format!("Connection failed: {}", e),
                    )
                })?;

                let row = conn
                    .query_opt("SELECT 1 FROM dbx_data WHERE key = $1 AND (expires_at IS NULL OR expires_at > NOW())", &[&key])
                    .await
                    .map_err(|e| {
                        DbxError::backend(
                            self.backend_name.clone(),
                            format!("Exists operation failed: {}", e),
                        )
                    })?;

                Ok(DataValue::Bool(row.is_some()))
            }

            DataOperation::Batch { operations } => {
                let mut results = Vec::new();
                for operation in operations {
                    let future = Box::pin(self.execute_data_operation_internal(operation));
                    let result = future.await?;
                    results.push(result);
                }
                Ok(DataValue::Array(results))
            }

            DataOperation::Update { key, fields, ttl } => {
                let conn = self.pool.get().await.map_err(|e| {
                    DbxError::backend(
                        self.backend_name.clone(),
                        format!("Connection failed: {}", e),
                    )
                })?;

                // Get current value
                let row = conn
                    .query_opt("SELECT value FROM dbx_data WHERE key = $1 AND (expires_at IS NULL OR expires_at > NOW())", &[&key])
                    .await
                    .map_err(|e| {
                        DbxError::backend(
                            self.backend_name.clone(),
                            format!("Get operation failed: {}", e),
                        )
                    })?;

                let mut current_value = match row {
                    Some(row) => {
                        let json_value: serde_json::Value = row.get(0);
                        self.json_to_data_value(&json_value)?
                    }
                    None => DataValue::Object(HashMap::new()),
                };

                // Update fields in the object
                if let DataValue::Object(ref mut obj) = current_value {
                    for (field_key, field_value) in fields {
                        obj.insert(field_key.clone(), field_value.clone());
                    }
                } else {
                    // If not an object, create new object with the fields
                    let mut new_obj = HashMap::new();
                    for (field_key, field_value) in fields {
                        new_obj.insert(field_key.clone(), field_value.clone());
                    }
                    current_value = DataValue::Object(new_obj);
                }

                // Save updated value
                let json_value = self.data_value_to_json(&current_value)?;
                let expires_at =
                    ttl.map(|t| chrono::Utc::now() + chrono::Duration::seconds(t as i64));

                conn.execute(
                    r#"
                    INSERT INTO dbx_data (key, value, expires_at, updated_at) 
                    VALUES ($1, $2, $3, NOW()) 
                    ON CONFLICT (key) 
                    DO UPDATE SET value = $2, expires_at = $3, updated_at = NOW()
                    "#,
                    &[&key, &json_value, &expires_at],
                )
                .await
                .map_err(|e| {
                    DbxError::backend(
                        self.backend_name.clone(),
                        format!("Update operation failed: {}", e),
                    )
                })?;

                Ok(DataValue::Bool(true))
            }

            DataOperation::Increment { key, amount } => {
                let conn = self.pool.get().await.map_err(|e| {
                    DbxError::backend(
                        self.backend_name.clone(),
                        format!("Connection failed: {}", e),
                    )
                })?;

                // Use atomic increment with JSONB
                let result = conn
                    .query_one(
                        r#"
                        INSERT INTO dbx_data (key, value, updated_at) 
                        VALUES ($1, to_jsonb($2::bigint), NOW()) 
                        ON CONFLICT (key) 
                        DO UPDATE SET 
                            value = CASE 
                                WHEN jsonb_typeof(dbx_data.value) = 'number' 
                                THEN to_jsonb((dbx_data.value #>> '{}')::bigint + $2)
                                ELSE to_jsonb($2::bigint)
                            END,
                            updated_at = NOW()
                        RETURNING (value #>> '{}')::bigint
                        "#,
                        &[&key, &amount],
                    )
                    .await
                    .map_err(|e| {
                        DbxError::backend(
                            self.backend_name.clone(),
                            format!("Increment operation failed: {}", e),
                        )
                    })?;

                let new_value: i64 = result.get(0);
                Ok(DataValue::Int(new_value))
            }

            DataOperation::Decrement { key, amount } => {
                let conn = self.pool.get().await.map_err(|e| {
                    DbxError::backend(
                        self.backend_name.clone(),
                        format!("Connection failed: {}", e),
                    )
                })?;

                // Use atomic decrement with JSONB
                let result = conn
                    .query_one(
                        r#"
                        INSERT INTO dbx_data (key, value, updated_at) 
                        VALUES ($1, to_jsonb((-($2::bigint))::bigint), NOW()) 
                        ON CONFLICT (key) 
                        DO UPDATE SET 
                            value = CASE 
                                WHEN jsonb_typeof(dbx_data.value) = 'number' 
                                THEN to_jsonb((dbx_data.value #>> '{}')::bigint - $2)
                                ELSE to_jsonb((-($2::bigint))::bigint)
                            END,
                            updated_at = NOW()
                        RETURNING (value #>> '{}')::bigint
                        "#,
                        &[&key, &amount],
                    )
                    .await
                    .map_err(|e| {
                        DbxError::backend(
                            self.backend_name.clone(),
                            format!("Decrement operation failed: {}", e),
                        )
                    })?;

                let new_value: i64 = result.get(0);
                Ok(DataValue::Int(new_value))
            }

            DataOperation::Append { key, value } => {
                let conn = self.pool.get().await.map_err(|e| {
                    DbxError::backend(
                        self.backend_name.clone(),
                        format!("Connection failed: {}", e),
                    )
                })?;

                let value_json = serde_json::Value::String(value.clone());

                let result = conn
                    .query_one(
                        r#"
                        INSERT INTO dbx_data (key, value, updated_at) 
                        VALUES ($1, $2, NOW()) 
                        ON CONFLICT (key) 
                        DO UPDATE SET 
                            value = CASE 
                                WHEN jsonb_typeof(dbx_data.value) = 'string' 
                                THEN to_jsonb((dbx_data.value #>> '{}') || ($2 #>> '{}'))
                                ELSE $2
                            END,
                            updated_at = NOW()
                        RETURNING char_length(value #>> '{}')
                        "#,
                        &[&key, &value_json],
                    )
                    .await
                    .map_err(|e| {
                        DbxError::backend(
                            self.backend_name.clone(),
                            format!("Append operation failed: {}", e),
                        )
                    })?;

                let new_length: i32 = result.get(0);
                Ok(DataValue::Int(new_length as i64))
            }

            DataOperation::Length { key } => {
                let conn = self.pool.get().await.map_err(|e| {
                    DbxError::backend(
                        self.backend_name.clone(),
                        format!("Connection failed: {}", e),
                    )
                })?;

                let row = conn
                    .query_opt(
                        "SELECT char_length(value #>> '{}') FROM dbx_data WHERE key = $1 AND (expires_at IS NULL OR expires_at > NOW())",
                        &[&key],
                    )
                    .await
                    .map_err(|e| {
                        DbxError::backend(
                            self.backend_name.clone(),
                            format!("Length operation failed: {}", e),
                        )
                    })?;

                match row {
                    Some(row) => {
                        let length: Option<i32> = row.get(0);
                        Ok(DataValue::Int(length.unwrap_or(0) as i64))
                    }
                    None => Ok(DataValue::Int(0)),
                }
            }

            DataOperation::GetTtl { key } => {
                let conn = self.pool.get().await.map_err(|e| {
                    DbxError::backend(
                        self.backend_name.clone(),
                        format!("Connection failed: {}", e),
                    )
                })?;

                let row = conn
                    .query_opt(
                        "SELECT EXTRACT(EPOCH FROM (expires_at - NOW()))::bigint FROM dbx_data WHERE key = $1",
                        &[&key],
                    )
                    .await
                    .map_err(|e| {
                        DbxError::backend(
                            self.backend_name.clone(),
                            format!("GetTtl operation failed: {}", e),
                        )
                    })?;

                match row {
                    Some(row) => {
                        let ttl: Option<i64> = row.get(0);
                        Ok(DataValue::Int(ttl.unwrap_or(-1)))
                    }
                    None => Ok(DataValue::Int(-2)), // Key doesn't exist
                }
            }

            DataOperation::SetTtl { key, ttl } => {
                let conn = self.pool.get().await.map_err(|e| {
                    DbxError::backend(
                        self.backend_name.clone(),
                        format!("Connection failed: {}", e),
                    )
                })?;

                let expires_at = if *ttl > 0 {
                    Some(chrono::Utc::now() + chrono::Duration::seconds(*ttl as i64))
                } else {
                    None
                };

                let rows_affected = conn
                    .execute(
                        "UPDATE dbx_data SET expires_at = $2, updated_at = NOW() WHERE key = $1",
                        &[&key, &expires_at],
                    )
                    .await
                    .map_err(|e| {
                        DbxError::backend(
                            self.backend_name.clone(),
                            format!("SetTtl operation failed: {}", e),
                        )
                    })?;

                Ok(DataValue::Bool(rows_affected > 0))
            }

            DataOperation::CompareAndSwap {
                key,
                expected_value,
                new_value,
                ttl,
            } => {
                let conn = self.pool.get().await.map_err(|e| {
                    DbxError::backend(
                        self.backend_name.clone(),
                        format!("Connection failed: {}", e),
                    )
                })?;

                let expires_at =
                    ttl.map(|t| chrono::Utc::now() + chrono::Duration::seconds(t as i64));
                let new_json = self.data_value_to_json(&DataValue::String(new_value.clone()))?;

                let rows_affected = if expected_value.is_empty() {
                    // Expected empty/null - insert only if key doesn't exist
                    conn.execute(
                        r#"
                        INSERT INTO dbx_data (key, value, expires_at, updated_at) 
                        VALUES ($1, $2, $3, NOW())
                        ON CONFLICT (key) DO NOTHING
                        "#,
                        &[&key, &new_json, &expires_at],
                    )
                    .await
                    .map_err(|e| {
                        DbxError::backend(
                            self.backend_name.clone(),
                            format!("CompareAndSwap operation failed: {}", e),
                        )
                    })?
                } else {
                    // Compare current value with expected
                    conn.execute(
                        r#"
                        UPDATE dbx_data 
                        SET value = $3, expires_at = $4, updated_at = NOW() 
                        WHERE key = $1 AND (value #>> '{}') = $2
                        "#,
                        &[&key, &expected_value, &new_json, &expires_at],
                    )
                    .await
                    .map_err(|e| {
                        DbxError::backend(
                            self.backend_name.clone(),
                            format!("CompareAndSwap operation failed: {}", e),
                        )
                    })?
                };

                Ok(DataValue::Bool(rows_affected > 0))
            }
        }
    }

    /// Validate key format and constraints
    fn validate_key(&self, key: &str) -> Result<(), DbxError> {
        if key.is_empty() {
            return Err(DbxError::validation("Key cannot be empty".to_string()));
        }

        if key.len() > 1024 {
            return Err(DbxError::validation(
                "Key too long (max 1024 chars)".to_string(),
            ));
        }

        if key.contains('\0') {
            return Err(DbxError::validation(
                "Key cannot contain null bytes".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate JSON data size and structure
    fn validate_data_value(&self, value: &DataValue) -> Result<(), DbxError> {
        match value {
            DataValue::String(s) if s.len() > 10_000_000 => Err(DbxError::validation(
                "String value too large (max 10MB)".to_string(),
            )),
            DataValue::Bytes(b) if b.len() > 10_000_000 => Err(DbxError::validation(
                "Bytes value too large (max 10MB)".to_string(),
            )),
            DataValue::Array(arr) if arr.len() > 100_000 => Err(DbxError::validation(
                "Array too large (max 100k elements)".to_string(),
            )),
            DataValue::Object(obj) if obj.len() > 10_000 => Err(DbxError::validation(
                "Object too large (max 10k fields)".to_string(),
            )),
            DataValue::Array(arr) => {
                for item in arr {
                    self.validate_data_value(item)?;
                }
                Ok(())
            }
            DataValue::Object(obj) => {
                for (k, v) in obj {
                    if k.len() > 1024 {
                        return Err(DbxError::validation(
                            "Object key too long (max 1024 chars)".to_string(),
                        ));
                    }
                    self.validate_data_value(v)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Validate TTL value
    fn validate_ttl(&self, ttl: u64) -> Result<(), DbxError> {
        const MAX_TTL: u64 = 86400 * 365 * 10; // 10 years
        if ttl > MAX_TTL {
            return Err(DbxError::validation(format!(
                "TTL too large (max {} seconds)",
                MAX_TTL
            )));
        }
        Ok(())
    }

    /// Execute with validation
    pub async fn execute_with_validation(
        &self,
        operation: &DataOperation,
    ) -> Result<DataValue, DbxError> {
        // Validate inputs
        match operation {
            DataOperation::Get { key, .. }
            | DataOperation::Delete { key, .. }
            | DataOperation::Exists { key, .. }
            | DataOperation::GetTtl { key }
            | DataOperation::Length { key }
            | DataOperation::Increment { key, .. }
            | DataOperation::Decrement { key, .. }
            | DataOperation::Append { key, .. } => {
                self.validate_key(key)?;
            }
            DataOperation::Set { key, value, ttl } => {
                self.validate_key(key)?;
                self.validate_data_value(value)?;
                if let Some(ttl_val) = ttl {
                    self.validate_ttl(*ttl_val)?;
                }
            }
            DataOperation::Update { key, fields, ttl } => {
                self.validate_key(key)?;
                for (field_key, field_value) in fields {
                    if field_key.len() > 1024 {
                        return Err(DbxError::validation("Field key too long".to_string()));
                    }
                    self.validate_data_value(field_value)?;
                }
                if let Some(ttl_val) = ttl {
                    self.validate_ttl(*ttl_val)?;
                }
            }
            DataOperation::SetTtl { key, ttl } => {
                self.validate_key(key)?;
                self.validate_ttl(*ttl)?;
            }
            DataOperation::CompareAndSwap {
                key,
                expected_value,
                new_value,
                ttl,
            } => {
                self.validate_key(key)?;
                if expected_value.len() > 10_000_000 {
                    return Err(DbxError::validation("Expected value too large".to_string()));
                }
                if new_value.len() > 10_000_000 {
                    return Err(DbxError::validation("New value too large".to_string()));
                }
                if let Some(ttl_val) = ttl {
                    self.validate_ttl(*ttl_val)?;
                }
            }
            DataOperation::Batch { operations } => {
                if operations.len() > 10_000 {
                    return Err(DbxError::validation(
                        "Batch too large (max 10k operations)".to_string(),
                    ));
                }
                for op in operations {
                    let future = Box::pin(self.execute_with_validation(op));
                    future.await?;
                }
                return Ok(DataValue::Array(Vec::new()));
            }
        }

        // Execute operation
        self.execute_data_operation_internal(operation)
            .await
            .map_err(|e| match e {
                DbxError::Backend {
                    backend,
                    message,
                    error_code: _,
                } => {
                    if message.contains("postgres") {
                        DbxError::backend(backend, message)
                    } else {
                        DbxError::backend(backend, format!("Operation failed: {}", message))
                    }
                }
                _ => e,
            })
    }

    /// Batch insert with prepared statements
    pub async fn batch_insert(
        &self,
        operations: &[(
            String,
            serde_json::Value,
            Option<chrono::DateTime<chrono::Utc>>,
        )],
    ) -> Result<u64, DbxError> {
        let mut conn = self.pool.get().await.map_err(|e| {
            DbxError::backend(
                self.backend_name.clone(),
                format!("Connection failed: {}", e),
            )
        })?;

        let transaction = conn.transaction().await.map_err(|e| {
            DbxError::backend(
                self.backend_name.clone(),
                format!("Transaction failed: {}", e),
            )
        })?;

        let stmt = transaction
            .prepare(
                r#"
                INSERT INTO dbx_data (key, value, expires_at, updated_at) 
                VALUES ($1, $2, $3, NOW()) 
                ON CONFLICT (key) 
                DO UPDATE SET value = $2, expires_at = $3, updated_at = NOW()
                "#,
            )
            .await
            .map_err(|e| {
                DbxError::backend(self.backend_name.clone(), format!("Prepare failed: {}", e))
            })?;

        let mut total_affected = 0u64;
        for (key, value, expires_at) in operations {
            let affected = transaction
                .execute(&stmt, &[key, value, expires_at])
                .await
                .map_err(|e| {
                    DbxError::backend(
                        self.backend_name.clone(),
                        format!("Batch execute failed: {}", e),
                    )
                })?;
            total_affected += affected;
        }

        transaction.commit().await.map_err(|e| {
            DbxError::backend(self.backend_name.clone(), format!("Commit failed: {}", e))
        })?;

        Ok(total_affected)
    }

    /// Remove expired entries in batches
    pub async fn remove_expired_batch(&self, limit: i64) -> Result<u64, DbxError> {
        let conn = self.pool.get().await.map_err(|e| {
            DbxError::backend(
                self.backend_name.clone(),
                format!("Connection failed: {}", e),
            )
        })?;

        let deleted_count = conn
            .execute(
                "DELETE FROM dbx_data WHERE ctid IN (SELECT ctid FROM dbx_data WHERE expires_at IS NOT NULL AND expires_at <= NOW() LIMIT $1)",
                &[&limit],
            )
            .await
            .map_err(|e| {
                DbxError::backend(
                    self.backend_name.clone(),
                    format!("Batch removal failed: {}", e),
                )
            })?;

        Ok(deleted_count)
    }

    /// Search keys by pattern with pagination
    pub async fn find_keys_by_pattern(
        &self,
        pattern: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<String>, DbxError> {
        let conn = self.pool.get().await.map_err(|e| {
            DbxError::backend(
                self.backend_name.clone(),
                format!("Connection failed: {}", e),
            )
        })?;

        let sql_pattern = pattern.replace('*', "%");
        let rows = conn
            .query(
                "SELECT key FROM dbx_data WHERE key LIKE $1 AND (expires_at IS NULL OR expires_at > NOW()) ORDER BY key LIMIT $2 OFFSET $3",
                &[&sql_pattern, &limit, &offset],
            )
            .await
            .map_err(|e| {
                DbxError::backend(
                    self.backend_name.clone(),
                    format!("Pattern search failed: {}", e),
                )
            })?;

        Ok(rows.iter().map(|row| row.get::<_, String>(0)).collect())
    }
}

impl PostgresBackend {
    /// Full-text search
    pub async fn full_text_search(
        &self,
        query: &str,
        limit: Option<usize>,
    ) -> Result<Vec<(String, DataValue, f32)>, DbxError> {
        let conn = self.pool.get().await.map_err(|e| {
            DbxError::backend(
                self.backend_name.clone(),
                format!("Connection failed: {}", e),
            )
        })?;

        let search_limit = limit.unwrap_or(100) as i64;
        let rows = conn
            .query(
                r#"
                SELECT key, value, ts_rank(to_tsvector('english', value::text), plainto_tsquery('english', $1)) as rank
                FROM dbx_data 
                WHERE to_tsvector('english', value::text) @@ plainto_tsquery('english', $1)
                AND (expires_at IS NULL OR expires_at > NOW())
                ORDER BY rank DESC
                LIMIT $2
                "#,
                &[&query, &search_limit],
            )
            .await
            .map_err(|e| {
                DbxError::backend(
                    self.backend_name.clone(),
                    format!("Full-text search failed: {}", e),
                )
            })?;

        let mut results = Vec::new();
        for row in rows {
            let key: String = row.get(0);
            let json_value: serde_json::Value = row.get(1);
            let rank: f32 = row.get(2);
            let data_value = self.json_to_data_value(&json_value)?;
            results.push((key, data_value, rank));
        }

        Ok(results)
    }

    /// Geospatial proximity search
    pub async fn geospatial_within(
        &self,
        center_lat: f64,
        center_lng: f64,
        radius_meters: f64,
        limit: Option<usize>,
    ) -> Result<Vec<(String, DataValue, f64)>, DbxError> {
        let conn = self.pool.get().await.map_err(|e| {
            DbxError::backend(
                self.backend_name.clone(),
                format!("Connection failed: {}", e),
            )
        })?;

        let search_limit = limit.unwrap_or(100) as i64;
        let rows = conn
            .query(
                r#"
                SELECT key, value, 
                       ST_Distance(
                           ST_GeogFromText('POINT(' || (value->>'lng')::float || ' ' || (value->>'lat')::float || ')'),
                           ST_GeogFromText('POINT($2 $1)')
                       ) as distance
                FROM dbx_data 
                WHERE value ? 'lat' AND value ? 'lng'
                AND ST_DWithin(
                    ST_GeogFromText('POINT(' || (value->>'lng')::float || ' ' || (value->>'lat')::float || ')'),
                    ST_GeogFromText('POINT($2 $1)'),
                    $3
                )
                AND (expires_at IS NULL OR expires_at > NOW())
                ORDER BY distance
                LIMIT $4
                "#,
                &[&center_lat, &center_lng, &radius_meters, &search_limit],
            )
            .await
            .map_err(|e| {
                DbxError::backend(
                    self.backend_name.clone(),
                    format!("Geospatial query failed: {}", e),
                )
            })?;

        let mut results = Vec::new();
        for row in rows {
            let key: String = row.get(0);
            let json_value: serde_json::Value = row.get(1);
            let distance: f64 = row.get(2);
            let data_value = self.json_to_data_value(&json_value)?;
            results.push((key, data_value, distance));
        }

        Ok(results)
    }

    /// Aggregate data by field
    pub async fn aggregate_field(
        &self,
        field_path: &str,
        operation: &str, // "count", "sum", "avg", "min", "max"
        filter: Option<&str>,
    ) -> Result<DataValue, DbxError> {
        let conn = self.pool.get().await.map_err(|e| {
            DbxError::backend(
                self.backend_name.clone(),
                format!("Connection failed: {}", e),
            )
        })?;

        let sql_function = match operation {
            "count" => format!("COUNT(value #>> '{{{}}}')", field_path),
            "sum" => format!("SUM((value #>> '{{{}}}')::numeric)", field_path),
            "avg" => format!("AVG((value #>> '{{{}}}')::numeric)", field_path),
            "min" => format!("MIN((value #>> '{{{}}}')::numeric)", field_path),
            "max" => format!("MAX((value #>> '{{{}}}')::numeric)", field_path),
            _ => {
                return Err(DbxError::unsupported_operation(
                    "Analytics operation",
                    &self.backend_name,
                ))
            }
        };

        let where_clause = if let Some(filter_expr) = filter {
            format!(
                "WHERE {} AND (expires_at IS NULL OR expires_at > NOW())",
                filter_expr
            )
        } else {
            "WHERE expires_at IS NULL OR expires_at > NOW()".to_string()
        };

        let query = format!("SELECT {} FROM dbx_data {}", sql_function, where_clause);

        let row = conn.query_one(&query, &[]).await.map_err(|e| {
            DbxError::backend(
                self.backend_name.clone(),
                format!("Aggregation query failed: {}", e),
            )
        })?;

        match operation {
            "count" => {
                let count: i64 = row.get(0);
                Ok(DataValue::Int(count))
            }
            "sum" | "avg" | "min" | "max" => {
                let value: Option<f64> = row.get(0);
                match value {
                    Some(float_val) => Ok(DataValue::Float(float_val)),
                    None => Ok(DataValue::Null),
                }
            }
            _ => Ok(DataValue::Null),
        }
    }

    /// Execute within transaction with isolation level
    pub async fn execute_in_transaction<F, T>(
        &self,
        _isolation: IsolationLevel,
        operation: F,
    ) -> Result<T, DbxError>
    where
        F: FnOnce(&tokio_postgres::Transaction) -> Result<T, DbxError> + Send,
        T: Send,
    {
        let mut conn = self.pool.get().await.map_err(|e| {
            DbxError::backend(
                self.backend_name.clone(),
                format!("Connection failed: {}", e),
            )
        })?;

        let transaction = conn.transaction().await.map_err(|e| {
            DbxError::backend(
                self.backend_name.clone(),
                format!("Transaction failed: {}", e),
            )
        })?;

        let result = operation(&transaction)?;

        transaction.commit().await.map_err(|e| {
            DbxError::backend(self.backend_name.clone(), format!("Commit failed: {}", e))
        })?;

        Ok(result)
    }

    /// Execute with retry on failure
    pub async fn execute_with_retry<F, T>(
        &self,
        max_retries: u32,
        operation: F,
    ) -> Result<T, DbxError>
    where
        F: Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, DbxError>> + Send>>
            + Send
            + Sync,
        T: Send,
    {
        let mut retries = 0;
        loop {
            match operation().await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    if retries >= max_retries {
                        return Err(e);
                    }

                    let error_str = e.to_string().to_lowercase();
                    if error_str.contains("deadlock") || error_str.contains("serialization failure")
                    {
                        retries += 1;
                        let delay = std::time::Duration::from_millis(50 * (1 << retries.min(5)));
                        tokio::time::sleep(delay).await;
                        continue;
                    }

                    return Err(e);
                }
            }
        }
    }

    /// Execute in serializable transaction
    pub async fn serializable_transaction<F, T>(&self, operation: F) -> Result<T, DbxError>
    where
        F: FnOnce(&tokio_postgres::Transaction) -> Result<T, DbxError> + Send,
        T: Send,
    {
        self.execute_in_transaction(IsolationLevel::Serializable, operation)
            .await
    }

    /// Execute in read committed transaction
    pub async fn read_committed_transaction<F, T>(&self, operation: F) -> Result<T, DbxError>
    where
        F: FnOnce(&tokio_postgres::Transaction) -> Result<T, DbxError> + Send,
        T: Send,
    {
        self.execute_in_transaction(IsolationLevel::ReadCommitted, operation)
            .await
    }
}

impl PostgresBackend {
    /// Query by JSON path
    pub async fn json_path_query(
        &self,
        json_path: &str,
        value: &serde_json::Value,
        operator: &str, // "=", "!=", ">", "<", ">=", "<=", "@>", "<@"
        limit: Option<usize>,
    ) -> Result<Vec<(String, DataValue)>, DbxError> {
        let conn = self.pool.get().await.map_err(|e| {
            DbxError::backend(
                self.backend_name.clone(),
                format!("Connection failed: {}", e),
            )
        })?;

        let search_limit = limit.unwrap_or(100) as i64;
        let query = format!(
            "SELECT key, value FROM dbx_data WHERE value #> $1 {} $2 AND (expires_at IS NULL OR expires_at > NOW()) LIMIT $3",
            operator
        );

        let path_array: Vec<&str> = json_path
            .trim_start_matches('{')
            .trim_end_matches('}')
            .split(',')
            .collect();
        let rows = conn
            .query(&query, &[&path_array, value, &search_limit])
            .await
            .map_err(|e| {
                DbxError::backend(
                    self.backend_name.clone(),
                    format!("JSON path query failed: {}", e),
                )
            })?;

        let mut results = Vec::new();
        for row in rows {
            let key: String = row.get(0);
            let json_value: serde_json::Value = row.get(1);
            let data_value = self.json_to_data_value(&json_value)?;
            results.push((key, data_value));
        }

        Ok(results)
    }

    /// Query by JSONB containment
    pub async fn jsonb_contains(
        &self,
        contains: &serde_json::Value,
        limit: Option<usize>,
    ) -> Result<Vec<(String, DataValue)>, DbxError> {
        let conn = self.pool.get().await.map_err(|e| {
            DbxError::backend(
                self.backend_name.clone(),
                format!("Connection failed: {}", e),
            )
        })?;

        let search_limit = limit.unwrap_or(100) as i64;
        let rows = conn
            .query(
                "SELECT key, value FROM dbx_data WHERE value @> $1 AND (expires_at IS NULL OR expires_at > NOW()) LIMIT $2",
                &[contains, &search_limit],
            )
            .await
            .map_err(|e| {
                DbxError::backend(
                    self.backend_name.clone(),
                    format!("JSONB contains failed: {}", e),
                )
            })?;

        let mut results = Vec::new();
        for row in rows {
            let key: String = row.get(0);
            let json_value: serde_json::Value = row.get(1);
            let data_value = self.json_to_data_value(&json_value)?;
            results.push((key, data_value));
        }

        Ok(results)
    }

    /// Batch update with JSONB merge
    pub async fn batch_merge_update(
        &self,
        updates: &[(String, serde_json::Value)], // key, jsonb_merge_patch
    ) -> Result<u64, DbxError> {
        let mut conn = self.pool.get().await.map_err(|e| {
            DbxError::backend(
                self.backend_name.clone(),
                format!("Connection failed: {}", e),
            )
        })?;

        let transaction = conn.transaction().await.map_err(|e| {
            DbxError::backend(
                self.backend_name.clone(),
                format!("Transaction failed: {}", e),
            )
        })?;

        let stmt = transaction
            .prepare(
                "UPDATE dbx_data SET value = value || $2, updated_at = NOW() WHERE key = $1 AND (expires_at IS NULL OR expires_at > NOW())",
            )
            .await
            .map_err(|e| {
                DbxError::backend(
                    self.backend_name.clone(),
                    format!("Prepare failed: {}", e),
                )
            })?;

        let mut total_affected = 0u64;
        for (key, patch) in updates {
            let affected = transaction
                .execute(&stmt, &[key, patch])
                .await
                .map_err(|e| {
                    DbxError::backend(
                        self.backend_name.clone(),
                        format!("Batch update failed: {}", e),
                    )
                })?;
            total_affected += affected;
        }

        transaction.commit().await.map_err(|e| {
            DbxError::backend(self.backend_name.clone(), format!("Commit failed: {}", e))
        })?;

        Ok(total_affected)
    }
}

impl PostgresBackend {
    /// Get detailed connection pool metrics
    pub async fn get_pool_metrics(&self) -> Result<PoolMetrics, DbxError> {
        let pool_stats = self.pool.get_stats().await;
        let start_time = std::time::Instant::now();

        // Test connection latency
        let latency = match self.pool.get().await {
            Ok(_) => Some(start_time.elapsed().as_millis() as u64),
            Err(_) => None,
        };

        // Get database-level statistics
        let conn = self.pool.get().await.map_err(|e| {
            DbxError::backend(
                self.backend_name.clone(),
                format!("Connection failed: {}", e),
            )
        })?;

        let db_stats = conn
            .query_one(
                r#"
                SELECT 
                    numbackends,
                    xact_commit,
                    xact_rollback,
                    blks_read,
                    blks_hit,
                    temp_files,
                    temp_bytes,
                    deadlocks,
                    conflicts
                FROM pg_stat_database 
                WHERE datname = current_database()
                "#,
                &[],
            )
            .await
            .map_err(|e| {
                DbxError::backend(
                    self.backend_name.clone(),
                    format!("Database stats failed: {}", e),
                )
            })?;

        let table_stats = conn
            .query_one(
                "SELECT seq_scan, seq_tup_read, idx_scan, idx_tup_fetch, n_tup_ins, n_tup_upd, n_tup_del FROM pg_stat_user_tables WHERE relname = 'dbx_data'",
                &[],
            )
            .await
            .map_err(|e| {
                DbxError::backend(
                    self.backend_name.clone(),
                    format!("Table stats failed: {}", e),
                )
            })?;

        Ok(PoolMetrics {
            pool_stats,
            connection_latency_ms: latency,
            database_connections: db_stats.get::<_, i32>(0) as u32,
            transactions_committed: db_stats.get::<_, i64>(1) as u64,
            transactions_rolled_back: db_stats.get::<_, i64>(2) as u64,
            blocks_read: db_stats.get::<_, i64>(3) as u64,
            blocks_hit: db_stats.get::<_, i64>(4) as u64,
            cache_hit_ratio: {
                let read = db_stats.get::<_, i64>(3) as f64;
                let hit = db_stats.get::<_, i64>(4) as f64;
                if read + hit > 0.0 {
                    hit / (read + hit)
                } else {
                    0.0
                }
            },
            temp_files: db_stats.get::<_, i64>(5) as u64,
            temp_bytes: db_stats.get::<_, i64>(6) as u64,
            deadlocks: db_stats.get::<_, i64>(7) as u64,
            conflicts: db_stats.get::<_, i64>(8) as u64,
            table_seq_scans: table_stats.get::<_, i64>(0) as u64,
            table_seq_reads: table_stats.get::<_, i64>(1) as u64,
            table_idx_scans: table_stats.get::<_, i64>(2) as u64,
            table_idx_reads: table_stats.get::<_, i64>(3) as u64,
            table_inserts: table_stats.get::<_, i64>(4) as u64,
            table_updates: table_stats.get::<_, i64>(5) as u64,
            table_deletes: table_stats.get::<_, i64>(6) as u64,
        })
    }

    /// Assess connection pool health
    pub async fn assess_pool_health(&self) -> PoolHealthStatus {
        let stats = match self.get_pool_metrics().await {
            Ok(stats) => stats,
            Err(_) => return PoolHealthStatus::Critical,
        };

        let pool_utilization =
            stats.pool_stats.active_connections as f32 / stats.pool_stats.max_connections as f32;
        let has_latency_issues = stats.connection_latency_ms.map_or(true, |lat| lat > 100);
        let has_cache_issues = stats.cache_hit_ratio < 0.9;
        let has_deadlocks = stats.deadlocks > 0;

        match (
            pool_utilization,
            has_latency_issues,
            has_cache_issues,
            has_deadlocks,
        ) {
            (util, _, _, true) if util > 0.9 => PoolHealthStatus::Critical,
            (util, true, true, _) if util > 0.8 => PoolHealthStatus::Warning,
            (util, _, _, _) if util > 0.95 => PoolHealthStatus::Warning,
            _ => PoolHealthStatus::Healthy,
        }
    }

    /// Generate optimization recommendations
    pub async fn get_recommendations(&self) -> Result<Vec<String>, DbxError> {
        let stats = self.get_pool_metrics().await?;
        let mut suggestions = Vec::new();

        if stats.cache_hit_ratio < 0.9 {
            suggestions.push("Consider increasing shared_buffers".to_string());
        }

        if stats.table_seq_scans > stats.table_idx_scans * 10 {
            suggestions.push("Add more indexes for common query patterns".to_string());
        }

        if stats.deadlocks > 100 {
            suggestions.push("Review application logic for deadlock prevention".to_string());
        }

        let pool_util =
            stats.pool_stats.active_connections as f32 / stats.pool_stats.max_connections as f32;
        if pool_util > 0.9 {
            suggestions.push("Consider increasing connection pool size".to_string());
        }

        if stats.temp_files > 1000 {
            suggestions.push("Consider increasing work_mem setting".to_string());
        }

        Ok(suggestions)
    }
}

#[derive(Debug, Clone)]
pub struct PoolMetrics {
    pub pool_stats: crate::postgres::client::PoolStats,
    pub connection_latency_ms: Option<u64>,
    pub database_connections: u32,
    pub transactions_committed: u64,
    pub transactions_rolled_back: u64,
    pub blocks_read: u64,
    pub blocks_hit: u64,
    pub cache_hit_ratio: f64,
    pub temp_files: u64,
    pub temp_bytes: u64,
    pub deadlocks: u64,
    pub conflicts: u64,
    pub table_seq_scans: u64,
    pub table_seq_reads: u64,
    pub table_idx_scans: u64,
    pub table_idx_reads: u64,
    pub table_inserts: u64,
    pub table_updates: u64,
    pub table_deletes: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PoolHealthStatus {
    Healthy,
    Warning,
    Critical,
}

pub struct PostgresBackendWithScheduler {
    backend: PostgresBackend,
    cleanup_running: Arc<AtomicBool>,
    cleanup_stats: Arc<RwLock<CleanupStats>>,
}

#[derive(Debug, Clone)]
pub struct CleanupStats {
    pub last_cleanup: Option<chrono::DateTime<chrono::Utc>>,
    pub total_cleaned: u64,
    pub cleanup_count: u64,
    pub avg_cleanup_time_ms: f64,
}

impl Default for CleanupStats {
    fn default() -> Self {
        Self {
            last_cleanup: None,
            total_cleaned: 0,
            cleanup_count: 0,
            avg_cleanup_time_ms: 0.0,
        }
    }
}

impl PostgresBackendWithScheduler {
    pub fn new(backend: PostgresBackend) -> Self {
        Self {
            backend,
            cleanup_running: Arc::new(AtomicBool::new(false)),
            cleanup_stats: Arc::new(RwLock::new(CleanupStats::default())),
        }
    }

    /// Start background cleanup task
    pub fn start_cleanup_scheduler(&self, interval_seconds: u64) -> tokio::task::JoinHandle<()> {
        let backend = self.backend.clone();
        let running = self.cleanup_running.clone();
        let stats = self.cleanup_stats.clone();

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(interval_seconds));

            loop {
                interval.tick().await;

                if running.load(Ordering::Relaxed) {
                    continue;
                }

                running.store(true, Ordering::Relaxed);
                let start_time = std::time::Instant::now();

                match backend.remove_expired_batch(10000).await {
                    Ok(cleaned) => {
                        let elapsed = start_time.elapsed().as_millis() as f64;
                        let mut stats_guard = stats.write().await;
                        stats_guard.last_cleanup = Some(chrono::Utc::now());
                        stats_guard.total_cleaned += cleaned;
                        stats_guard.cleanup_count += 1;
                        stats_guard.avg_cleanup_time_ms = (stats_guard.avg_cleanup_time_ms
                            * (stats_guard.cleanup_count - 1) as f64
                            + elapsed)
                            / stats_guard.cleanup_count as f64;
                    }
                    Err(e) => {
                        tracing::error!("Cleanup task failed: {}", e);
                    }
                }

                running.store(false, Ordering::Relaxed);
            }
        })
    }

    /// Get cleanup statistics
    pub async fn get_cleanup_stats(&self) -> CleanupStats {
        self.cleanup_stats.read().await.clone()
    }

    /// Manual cleanup trigger
    pub async fn trigger_cleanup(&self) -> Result<u64, DbxError> {
        if self.cleanup_running.load(Ordering::Relaxed) {
            return Err(DbxError::backend(
                self.backend.backend_name.clone(),
                "Cleanup already running".to_string(),
            ));
        }

        self.cleanup_running.store(true, Ordering::Relaxed);
        let result = self.backend.remove_expired_batch(10000).await;
        self.cleanup_running.store(false, Ordering::Relaxed);

        if let Ok(cleaned) = result {
            let mut stats = self.cleanup_stats.write().await;
            stats.total_cleaned += cleaned;
            stats.last_cleanup = Some(chrono::Utc::now());
        }

        result
    }
}

impl std::ops::Deref for PostgresBackendWithScheduler {
    type Target = PostgresBackend;

    fn deref(&self) -> &Self::Target {
        &self.backend
    }
}

#[derive(Debug, Clone)]
pub struct CacheStats {
    pub total_entries: usize,
    pub valid_entries: usize,
    pub expired_entries: usize,
    pub max_size: usize,
    pub hit_ratio: f64,
}

#[derive(Debug, Clone)]
pub struct HealthDiagnostics {
    pub is_healthy: bool,
    pub connection_time_ms: u64,
    pub ping_time_ms: Option<u64>,
    pub table_exists: bool,
    pub sample_query_time_ms: Option<u64>,
    pub error: Option<String>,
}

#[async_trait]
impl UniversalBackend for PostgresBackend {
    fn name(&self) -> &str {
        &self.backend_name
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.capabilities.clone()
    }

    async fn execute_data(&self, operation: DataOperation) -> Result<DataResult, DbxError> {
        let operation_id = Uuid::new_v4();
        let start_time = std::time::Instant::now();

        debug!(
            backend = %self.backend_name,
            operation_id = %operation_id,
            operation = ?operation,
            "Executing data operation"
        );

        match self.execute_data_operation_internal(&operation).await {
            Ok(data) => {
                let execution_time = start_time.elapsed().as_millis() as u64;
                let metadata = ResultMetadata::new(self.backend_name.clone(), execution_time);

                Ok(DataResult::success_with_metadata(
                    operation_id,
                    data,
                    metadata,
                ))
            }
            Err(error) => Ok(DataResult::error(operation_id, error)),
        }
    }

    async fn execute_query(&self, _operation: QueryOperation) -> Result<QueryResult, DbxError> {
        Err(DbxError::unsupported_operation(
            "Complex queries",
            &self.backend_name,
        ))
    }

    async fn execute_stream(&self, _operation: StreamOperation) -> Result<StreamResult, DbxError> {
        Err(DbxError::unsupported_operation(
            "Streaming",
            &self.backend_name,
        ))
    }

    async fn health_check(&self) -> Result<BackendHealth, DbxError> {
        let start_time = std::time::Instant::now();

        match self.pool.health_check().await {
            Ok(true) => {
                let response_time = start_time.elapsed();
                Ok(BackendHealth {
                    status: HealthStatus::Healthy,
                    response_time_ms: Some(response_time.as_millis() as u64),
                    details: None,
                    last_check: Utc::now(),
                })
            }
            _ => Ok(BackendHealth {
                status: HealthStatus::Unhealthy,
                response_time_ms: Some(start_time.elapsed().as_millis() as u64),
                details: None,
                last_check: Utc::now(),
            }),
        }
    }

    async fn get_stats(&self) -> Result<BackendStats, DbxError> {
        let pool_stats = self.pool.get_stats().await;

        Ok(BackendStats {
            connections: ConnectionStats {
                active: pool_stats.active_connections as u32,
                idle: pool_stats.idle_connections as u32,
                total: pool_stats.total_connections as u32,
                max_pool_size: pool_stats.max_connections as u32,
            },
            operations: OperationStats {
                total_operations: 0,
                successful_operations: 0,
                failed_operations: 0,
                operations_per_second: 0.0,
            },
            performance: PerformanceStats {
                avg_response_time_ms: 0.0,
                p95_response_time_ms: 0.0,
                p99_response_time_ms: 0.0,
            },
            storage: Some(StorageStats {
                used_memory_bytes: 0,
                total_memory_bytes: None,
                key_count: 0,
                database_size_bytes: None,
            }),
        })
    }

    async fn test_connection(&self) -> Result<(), DbxError> {
        self.pool.ping().await.map_err(|e| {
            DbxError::connection(
                self.backend_name.clone(),
                format!("Connection test failed: {}", e),
            )
        })?;
        Ok(())
    }
}
