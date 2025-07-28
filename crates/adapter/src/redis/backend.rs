use crate::redis::client::RedisConnectionPool;
use async_trait::async_trait;
use base64::Engine;
use chrono::Utc;
use futures::TryFutureExt;
use serde_json;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, warn};
use uuid::Uuid;

use dbx_core::{
    BackendCapabilities, BackendFeature, BackendHealth, BackendStats, ConnectionStats,
    DataOperation, DataOperationType, DataResult, DataValue, DbxError, HealthStatus,
    OperationStats, PerformanceStats, QueryCapabilities, QueryOperation, QueryResult,
    QueryResultItem, ResultMetadata, StorageStats, StreamCapabilities, StreamEntry,
    StreamOperation, StreamResult, TransactionSupport, UniversalBackend,
};

/// Redis backend implementation for DBX using async connection pool
pub struct RedisBackend {
    pool: Arc<RedisConnectionPool>,
    backend_name: String,
    capabilities: BackendCapabilities,
}

impl RedisBackend {
    /// Create a new Redis backend instance
    pub fn new(pool: Arc<RedisConnectionPool>, backend_name: String) -> Self {
        Self {
            pool,
            backend_name,
            capabilities: Self::create_capabilities(),
        }
    }

    /// Define the capabilities of this Redis backend
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
                DataOperationType::Batch,
            ],
            query_capabilities: QueryCapabilities {
                key_patterns: true,
                field_filters: false,
                range_queries: false,
                text_search: false,
                logical_operations: false,
                sorting: false,
                pagination: true,
                aggregations: false,
            },
            stream_capabilities: StreamCapabilities {
                pub_sub: true,
                streams: true,
                persistent_streams: true,
                stream_groups: false,
            },
            transaction_support: TransactionSupport::MultiOperation,
            features: vec![
                BackendFeature::JsonSupport,
                BackendFeature::BinaryData,
                BackendFeature::Replication,
                BackendFeature::Clustering,
            ],
        }
    }

    /// Create Redis backend from URL
    pub async fn from_url(
        url: &str,
        backend_name: String,
        pool_size: usize,
    ) -> Result<Self, DbxError> {
        let pool = RedisConnectionPool::new(url, pool_size).map_err(|e| {
            DbxError::connection(backend_name.clone(), format!("Failed to connect: {}", e))
        })?;

        Ok(Self::new(Arc::new(pool), backend_name))
    }

    /// Convert DataValue to Redis value
    fn data_value_to_redis_value(&self, value: &DataValue) -> Result<String, DbxError> {
        match value {
            DataValue::Null => Ok("".to_string()),
            DataValue::Bool(b) => Ok(if *b { "1".to_string() } else { "0".to_string() }),
            DataValue::Int(i) => Ok(i.to_string()),
            DataValue::Float(f) => Ok(f.to_string()),
            DataValue::String(s) => Ok(s.clone()),
            DataValue::Bytes(b) => Ok(base64::prelude::BASE64_STANDARD.encode(b)),
            DataValue::Array(arr) => {
                let json_value = serde_json::Value::Array(
                    arr.iter()
                        .map(|v| self.data_value_to_json(v))
                        .collect::<Result<Vec<_>, _>>()?,
                );
                serde_json::to_string(&json_value).map_err(|e| {
                    DbxError::serialization(format!("Failed to serialize array: {}", e))
                })
            }
            DataValue::Object(obj) => {
                let json_obj: HashMap<String, serde_json::Value> = obj
                    .iter()
                    .map(|(k, v)| Ok((k.clone(), self.data_value_to_json(v)?)))
                    .collect::<Result<HashMap<String, serde_json::Value>, DbxError>>()?;
                let json_map: serde_json::Map<String, serde_json::Value> =
                    json_obj.into_iter().collect();
                serde_json::to_string(&serde_json::Value::Object(json_map)).map_err(|e| {
                    DbxError::serialization(format!("Failed to serialize object: {}", e))
                })
            }
        }
    }

    /// Convert DataValue to JSON for serialization
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

    /// Convert Redis string value to DataValue
    fn redis_value_to_data_value(&self, value: Option<String>) -> Result<DataValue, DbxError> {
        match value {
            None => Ok(DataValue::Null),
            Some(s) => {
                // Empty strings should be preserved as empty strings, not converted to null
                if s.is_empty() {
                    return Ok(DataValue::String(s));
                }

                // Try JSON first (for complex types)
                if s.starts_with('{') || s.starts_with('[') {
                    if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(&s) {
                        return self.json_to_data_value(&json_value);
                    }
                }

                // Try parsing as number
                if let Ok(int_val) = s.parse::<i64>() {
                    return Ok(DataValue::Int(int_val));
                }

                if let Ok(float_val) = s.parse::<f64>() {
                    return Ok(DataValue::Float(float_val));
                }

                // Try parsing as boolean
                match s.as_str() {
                    "true" | "1" => Ok(DataValue::Bool(true)),
                    "false" | "0" => Ok(DataValue::Bool(false)),
                    _ => Ok(DataValue::String(s)),
                }
            }
        }
    }

    /// Get the Redis data type of a key
    async fn get_redis_type(&self, key: &str) -> Result<String, DbxError> {
        let mut conn = self.pool.acquire_connection().await.map_err(|e| {
            DbxError::backend(
                self.backend_name.clone(),
                format!("Failed to acquire lock: {}", e),
            )
        })?;
        let key_type: String = redis::cmd("TYPE")
            .arg(key)
            .query_async(&mut *conn)
            .await
            .map_err(|e| {
                DbxError::backend(
                    self.backend_name.clone(),
                    format!("Failed to get key type: {}", e),
                )
            })?;
        Ok(key_type)
    }

    /// Convert JSON to DataValue
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
            serde_json::Value::String(s) => {
                // Check if it's base64 encoded bytes
                if let Ok(bytes) = base64::prelude::BASE64_STANDARD.decode(s) {
                    if String::from_utf8(bytes.clone()).is_err() {
                        return Ok(DataValue::Bytes(bytes));
                    }
                }
                Ok(DataValue::String(s.clone()))
            }
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

    /// Execute a data operation on Redis
    fn execute_data_operation<'a>(
        &'a self,
        operation: &'a DataOperation,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<DataValue, DbxError>> + Send + 'a>>
    {
        Box::pin(async move {
            match operation {
                DataOperation::Get { key, fields } => {
                    if let Some(fields) = fields {
                        if fields.is_empty() {
                            // Key-value get operation
                            let mut conn = self.pool.get().await.map_err(|e| {
                                DbxError::backend(
                                    self.backend_name.clone(),
                                    format!("Failed to get connection: {}", e),
                                )
                            })?;
                            let value: Option<String> = redis::cmd("GET")
                                .arg(key)
                                .query_async(&mut *conn)
                                .await
                                .map_err(|e| {
                                    DbxError::backend(
                                        self.backend_name.clone(),
                                        format!("Get failed: {}", e),
                                    )
                                })?;
                            self.redis_value_to_data_value(value)
                        } else {
                            // Hash field get
                            let mut conn = self.pool.acquire_connection().await.map_err(|e| {
                                DbxError::backend(
                                    self.backend_name.clone(),
                                    format!("Failed to acquire lock: {}", e),
                                )
                            })?;
                            let mut result = HashMap::new();
                            for field in fields {
                                let value = redis::cmd("HGET")
                                    .arg(key)
                                    .arg(field)
                                    .query_async(&mut *conn)
                                    .await
                                    .map_err(|e| {
                                        DbxError::backend(
                                            self.backend_name.clone(),
                                            format!("Hash get failed: {}", e),
                                        )
                                    })?;
                                result
                                    .insert(field.clone(), self.redis_value_to_data_value(value)?);
                            }
                            Ok(DataValue::Object(result))
                        }
                    } else {
                        // No fields specified - detect data type and handle accordingly
                        let data_type = self.get_redis_type(key).await?;
                        match data_type.as_str() {
                            "hash" => {
                                // Get all hash fields
                                let mut conn =
                                    self.pool.acquire_connection().await.map_err(|e| {
                                        DbxError::backend(
                                            self.backend_name.clone(),
                                            format!("Failed to acquire lock: {}", e),
                                        )
                                    })?;
                                let hash_data: HashMap<String, String> = redis::cmd("HGETALL")
                                    .arg(key)
                                    .query_async(&mut *conn)
                                    .await
                                    .map_err(|e| {
                                        DbxError::backend(
                                            self.backend_name.clone(),
                                            format!("Hash get all failed: {}", e),
                                        )
                                    })?;

                                let mut result = HashMap::new();
                                for (field, value) in hash_data {
                                    result.insert(
                                        field,
                                        self.redis_value_to_data_value(Some(value))?,
                                    );
                                }
                                Ok(DataValue::Object(result))
                            }
                            "string" => {
                                // Get string value
                                let mut conn = self.pool.get().await.map_err(|e| {
                                    DbxError::backend(
                                        self.backend_name.clone(),
                                        format!("Failed to get connection: {}", e),
                                    )
                                })?;
                                let value: Option<String> = redis::cmd("GET")
                                    .arg(key)
                                    .query_async(&mut *conn)
                                    .await
                                    .map_err(|e| {
                                        DbxError::backend(
                                            self.backend_name.clone(),
                                            format!("Get failed: {}", e),
                                        )
                                    })?;
                                self.redis_value_to_data_value(value)
                            }
                            "list" => {
                                // Get list values
                                let mut conn =
                                    self.pool.acquire_connection().await.map_err(|e| {
                                        DbxError::backend(
                                            self.backend_name.clone(),
                                            format!("Failed to acquire lock: {}", e),
                                        )
                                    })?;
                                let list_data: Vec<String> = redis::cmd("LRANGE")
                                    .arg(key)
                                    .arg(0)
                                    .arg(-1)
                                    .query_async(&mut *conn)
                                    .await
                                    .map_err(|e| {
                                        DbxError::backend(
                                            self.backend_name.clone(),
                                            format!("List get failed: {}", e),
                                        )
                                    })?;

                                let result: Result<Vec<DataValue>, DbxError> = list_data
                                    .into_iter()
                                    .map(|v| self.redis_value_to_data_value(Some(v)))
                                    .collect();
                                Ok(DataValue::Array(result?))
                            }
                            "set" => {
                                // Get set members
                                let mut conn =
                                    self.pool.acquire_connection().await.map_err(|e| {
                                        DbxError::backend(
                                            self.backend_name.clone(),
                                            format!("Failed to acquire lock: {}", e),
                                        )
                                    })?;
                                let set_data: Vec<String> = redis::cmd("SMEMBERS")
                                    .arg(key)
                                    .query_async(&mut *conn)
                                    .await
                                    .map_err(|e| {
                                        DbxError::backend(
                                            self.backend_name.clone(),
                                            format!("Set get failed: {}", e),
                                        )
                                    })?;

                                let result: Result<Vec<DataValue>, DbxError> = set_data
                                    .into_iter()
                                    .map(|v| self.redis_value_to_data_value(Some(v)))
                                    .collect();
                                Ok(DataValue::Array(result?))
                            }
                            "none" => {
                                // Key doesn't exist
                                Ok(DataValue::Null)
                            }
                            _ => {
                                // Unsupported type, try string as fallback
                                let mut conn = self.pool.get().await.map_err(|e| {
                                    DbxError::backend(
                                        self.backend_name.clone(),
                                        format!("Failed to get connection: {}", e),
                                    )
                                })?;
                                let value: Option<String> = redis::cmd("GET")
                                    .arg(key)
                                    .query_async(&mut *conn)
                                    .await
                                    .map_err(|e| {
                                        DbxError::backend(
                                            self.backend_name.clone(),
                                            format!("Get failed: {}", e),
                                        )
                                    })?;
                                self.redis_value_to_data_value(value)
                            }
                        }
                    }
                }

                DataOperation::Set { key, value, ttl } => {
                    let redis_value = self.data_value_to_redis_value(value)?;
                    let mut conn = self.pool.acquire_connection().await.map_err(|e| {
                        DbxError::backend(
                            self.backend_name.clone(),
                            format!("Failed to acquire lock: {}", e),
                        )
                    })?;

                    if let Some(ttl_secs) = ttl {
                        redis::cmd("SETEX")
                            .arg(key)
                            .arg(ttl_secs.to_string())
                            .arg(redis_value)
                            .query_async::<_, ()>(&mut *conn)
                            .await
                            .map_err(|e| {
                                DbxError::backend(
                                    self.backend_name.clone(),
                                    format!("Set with TTL failed: {}", e),
                                )
                            })?;
                    } else {
                        redis::cmd("SET")
                            .arg(key)
                            .arg(redis_value)
                            .query_async::<_, ()>(&mut *conn)
                            .await
                            .map_err(|e| {
                                DbxError::backend(
                                    self.backend_name.clone(),
                                    format!("Set failed: {}", e),
                                )
                            })?;
                    }

                    Ok(DataValue::Bool(true))
                }

                DataOperation::Update { key, fields, ttl } => {
                    let mut conn = self.pool.acquire_connection().await.map_err(|e| {
                        DbxError::backend(
                            self.backend_name.clone(),
                            format!("Failed to acquire lock: {}", e),
                        )
                    })?;

                    for (field, value) in fields {
                        let redis_value = self.data_value_to_redis_value(value)?;
                        redis::cmd("HSET")
                            .arg(key)
                            .arg(field)
                            .arg(redis_value)
                            .query_async::<_, ()>(&mut *conn)
                            .await
                            .map_err(|e| {
                                DbxError::backend(
                                    self.backend_name.clone(),
                                    format!("Hash set failed: {}", e),
                                )
                            })?;
                    }

                    if let Some(ttl_secs) = ttl {
                        redis::cmd("EXPIRE")
                            .arg(key)
                            .arg(ttl_secs.to_string())
                            .query_async::<_, ()>(&mut *conn)
                            .await
                            .map_err(|e| {
                                DbxError::backend(
                                    self.backend_name.clone(),
                                    format!("Set TTL failed: {}", e),
                                )
                            })?;
                    }

                    Ok(DataValue::Bool(true))
                }

                DataOperation::Delete { key, fields } => {
                    let mut conn = self
                        .pool
                        .acquire_connection()
                        .map_err(|e| {
                            DbxError::backend(
                                self.backend_name.clone(),
                                format!("Failed to acquire lock: {}", e),
                            )
                        })
                        .await?;

                    if let Some(fields) = fields {
                        if fields.is_empty() {
                            // Delete entire key
                            redis::cmd("DEL")
                                .arg(key)
                                .query_async::<_, ()>(&mut *conn)
                                .await
                                .map_err(|e| {
                                    DbxError::backend(
                                        self.backend_name.clone(),
                                        format!("Delete failed: {}", e),
                                    )
                                })?;
                        } else {
                            // Delete hash fields
                            let field_refs: Vec<&str> = fields.iter().map(|s| s.as_str()).collect();
                            redis::cmd("HDEL")
                                .arg(key)
                                .arg(&field_refs)
                                .query_async::<_, ()>(&mut *conn)
                                .await
                                .map_err(|e| {
                                    DbxError::backend(
                                        self.backend_name.clone(),
                                        format!("Hash delete failed: {}", e),
                                    )
                                })?;
                        }
                    } else {
                        // Delete entire key (no fields specified)
                        redis::cmd("DEL")
                            .arg(key)
                            .query_async::<_, ()>(&mut *conn)
                            .await
                            .map_err(|e| {
                                DbxError::backend(
                                    self.backend_name.clone(),
                                    format!("Delete failed: {}", e),
                                )
                            })?;
                    }
                    Ok(DataValue::Bool(true))
                }

                DataOperation::Exists { key, fields } => {
                    let mut conn = self.pool.acquire_connection().await.map_err(|e| {
                        DbxError::backend(
                            self.backend_name.clone(),
                            format!("Failed to acquire lock: {}", e),
                        )
                    })?;

                    if let Some(fields) = fields {
                        if fields.is_empty() {
                            // Check if key exists
                            let exists: i32 = redis::cmd("EXISTS")
                                .arg(key)
                                .query_async(&mut *conn)
                                .await
                                .map_err(|e| {
                                    DbxError::backend(
                                        self.backend_name.clone(),
                                        format!("Exists check failed: {}", e),
                                    )
                                })?;
                            Ok(DataValue::Bool(exists > 0))
                        } else {
                            // Check if hash fields exist
                            let mut result = HashMap::new();
                            for field in fields {
                                let exists: i32 = redis::cmd("HEXISTS")
                                    .arg(key)
                                    .arg(field)
                                    .query_async(&mut *conn)
                                    .await
                                    .map_err(|e| {
                                        DbxError::backend(
                                            self.backend_name.clone(),
                                            format!("Hash exists check failed: {}", e),
                                        )
                                    })?;
                                result.insert(field.clone(), DataValue::Bool(exists > 0));
                            }
                            Ok(DataValue::Object(result))
                        }
                    } else {
                        // Check if key exists (no fields specified)
                        let exists: i32 = redis::cmd("EXISTS")
                            .arg(key)
                            .query_async(&mut *conn)
                            .await
                            .map_err(|e| {
                                DbxError::backend(
                                    self.backend_name.clone(),
                                    format!("Exists check failed: {}", e),
                                )
                            })?;
                        Ok(DataValue::Bool(exists > 0))
                    }
                }

                DataOperation::SetTtl { key, ttl } => {
                    let mut conn = self.pool.acquire_connection().await.map_err(|e| {
                        DbxError::backend(
                            self.backend_name.clone(),
                            format!("Failed to acquire lock: {}", e),
                        )
                    })?;
                    let success: i32 = redis::cmd("EXPIRE")
                        .arg(key)
                        .arg(ttl.to_string())
                        .query_async(&mut *conn)
                        .await
                        .map_err(|e| {
                            DbxError::backend(
                                self.backend_name.clone(),
                                format!("Set TTL failed: {}", e),
                            )
                        })?;
                    Ok(DataValue::Bool(success > 0))
                }

                DataOperation::GetTtl { key } => {
                    let mut conn = self.pool.acquire_connection().await.map_err(|e| {
                        DbxError::backend(
                            self.backend_name.clone(),
                            format!("Failed to acquire lock: {}", e),
                        )
                    })?;
                    let ttl = redis::cmd("TTL")
                        .arg(key)
                        .query_async(&mut *conn)
                        .await
                        .map_err(|e| {
                            DbxError::backend(
                                self.backend_name.clone(),
                                format!("Get TTL failed: {}", e),
                            )
                        })?;
                    Ok(DataValue::Int(ttl))
                }

                DataOperation::Batch { operations } => {
                    // Execute operations in sequence (Redis transaction limitations)
                    let mut results = Vec::new();
                    for op in operations {
                        let result = self.execute_data_operation(op).await?;
                        results.push(result);
                    }
                    Ok(DataValue::Array(results))
                }
            }
        })
    }
}

#[async_trait]
impl UniversalBackend for RedisBackend {
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

        match self.execute_data_operation(&operation).await {
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

    async fn execute_query(&self, operation: QueryOperation) -> Result<QueryResult, DbxError> {
        debug!(
            backend = %self.backend_name,
            query_id = %operation.id,
            "Executing query operation"
        );

        // Redis supports pattern matching queries
        let start_time = std::time::Instant::now();

        match &operation.filter {
            dbx_core::QueryFilter::KeyPattern { pattern } => {
                let keys = self.pool.keys(pattern).await.map_err(|e| {
                    DbxError::backend(
                        self.backend_name.clone(),
                        format!("Key pattern scan failed: {}", e),
                    )
                })?;

                let limited_keys = if let Some(limit) = operation.limit {
                    keys.into_iter().take(limit).collect()
                } else {
                    keys
                };

                let mut results = Vec::new();
                for key in limited_keys {
                    // Get the value for each key
                    let mut conn = self.pool.get().await.map_err(|e| {
                        DbxError::backend(
                            self.backend_name.clone(),
                            format!("Failed to get connection: {}", e),
                        )
                    })?;
                    let value: Option<String> = redis::cmd("GET")
                        .arg(&key)
                        .query_async(&mut *conn)
                        .await
                        .map_err(|e| {
                            DbxError::backend(
                                self.backend_name.clone(),
                                format!("Get key value failed: {}", e),
                            )
                        })?;

                    let data_value = self.redis_value_to_data_value(value)?;
                    results.push(QueryResultItem {
                        key,
                        data: data_value,
                        score: None,
                    });
                }

                let execution_time = start_time.elapsed().as_millis() as u64;
                let metadata = ResultMetadata::new(self.backend_name.clone(), execution_time);

                let result_count = results.len();
                let mut query_result =
                    QueryResult::success_with_count(operation.id, results, result_count);
                query_result.metadata = Some(metadata);
                Ok(query_result)
            }
            _ => {
                warn!(backend = %self.backend_name, "Complex query operation not supported by Redis backend");
                Err(DbxError::unsupported_operation(
                    "Complex queries",
                    &self.backend_name,
                ))
            }
        }
    }

    async fn execute_stream(&self, operation: StreamOperation) -> Result<StreamResult, DbxError> {
        debug!(
            backend = %self.backend_name,
            operation = ?operation,
            "Executing stream operation"
        );

        match operation {
            StreamOperation::Publish { channel, message } => {
                let mut conn = self.pool.acquire_connection().await.map_err(|e| {
                    DbxError::backend(
                        self.backend_name.clone(),
                        format!("Connection failed: {}", e),
                    )
                })?;

                let serialized_message = self.data_value_to_redis_value(&message)?;
                let _subscribers: i64 = redis::cmd("PUBLISH")
                    .arg(&channel)
                    .arg(serialized_message)
                    .query_async(&mut *conn)
                    .await
                    .map_err(|e| {
                        DbxError::backend(
                            self.backend_name.clone(),
                            format!("Publish failed: {}", e),
                        )
                    })?;

                Ok(StreamResult::Published {
                    channel: channel.clone(),
                    message_id: Uuid::new_v4().to_string(),
                })
            }

            StreamOperation::Subscribe { channel } => Ok(StreamResult::Subscribed {
                channel: channel.clone(),
                subscriber_id: Uuid::new_v4(),
            }),

            StreamOperation::Unsubscribe { channel } => Ok(StreamResult::Unsubscribed {
                channel: channel.clone(),
                subscriber_id: Uuid::new_v4(),
            }),

            StreamOperation::CreateStream { name, config: _ } => {
                let mut conn = self.pool.acquire_connection().await.map_err(|e| {
                    DbxError::backend(
                        self.backend_name.clone(),
                        format!("Connection failed: {}", e),
                    )
                })?;

                let stream_id: String = redis::cmd("XADD")
                    .arg(&name)
                    .arg("*")
                    .arg("__init__")
                    .arg("true")
                    .query_async(&mut *conn)
                    .await
                    .map_err(|e| {
                        DbxError::backend(
                            self.backend_name.clone(),
                            format!("Stream creation failed: {}", e),
                        )
                    })?;

                Ok(StreamResult::StreamCreated {
                    stream: name.clone(),
                    stream_id,
                })
            }

            StreamOperation::StreamAdd { stream, fields } => {
                let mut conn = self.pool.acquire_connection().await.map_err(|e| {
                    DbxError::backend(
                        self.backend_name.clone(),
                        format!("Connection failed: {}", e),
                    )
                })?;

                let mut cmd = redis::cmd("XADD");
                cmd.arg(&stream).arg("*");

                for (field, value) in fields {
                    let serialized_value = self.data_value_to_redis_value(&value)?;
                    cmd.arg(field).arg(serialized_value);
                }

                let entry_id: String = cmd.query_async(&mut *conn).await.map_err(|e| {
                    DbxError::backend(
                        self.backend_name.clone(),
                        format!("Stream add failed: {}", e),
                    )
                })?;

                Ok(StreamResult::StreamEntryAdded {
                    stream: stream.clone(),
                    entry_id,
                })
            }

            StreamOperation::StreamRead { stream, count, .. } => {
                let mut conn = self.pool.acquire_connection().await.map_err(|e| {
                    DbxError::backend(
                        self.backend_name.clone(),
                        format!("Connection failed: {}", e),
                    )
                })?;

                let limit = count.unwrap_or(10);

                // Read from stream
                let results: Vec<(String, Vec<(String, String)>)> = redis::cmd("XREAD")
                    .arg("COUNT")
                    .arg(limit)
                    .arg("STREAMS")
                    .arg(&stream)
                    .arg("0")
                    .query_async(&mut *conn)
                    .await
                    .map_err(|e| {
                        DbxError::backend(
                            self.backend_name.clone(),
                            format!("Stream read failed: {}", e),
                        )
                    })?;

                let mut entries = Vec::new();
                for (entry_id, field_pairs) in results {
                    let mut fields = HashMap::new();
                    for i in (0..field_pairs.len()).step_by(2) {
                        if i + 1 < field_pairs.len() {
                            let field_name = &field_pairs[i].0;
                            let field_value = Some(field_pairs[i + 1].1.clone());
                            let data_value = self.redis_value_to_data_value(field_value)?;
                            fields.insert(field_name.clone(), data_value);
                        }
                    }

                    entries.push(StreamEntry {
                        id: entry_id,
                        fields,
                        timestamp: Utc::now(),
                    });
                }

                Ok(StreamResult::StreamRead {
                    stream: stream.clone(),
                    entries,
                })
            }
        }
    }

    async fn health_check(&self) -> Result<BackendHealth, DbxError> {
        let start_time = std::time::Instant::now();

        match self.pool.ping().await {
            Ok(true) => {
                let response_time = start_time.elapsed();
                Ok(BackendHealth {
                    status: HealthStatus::Healthy,
                    response_time_ms: Some(response_time.as_millis() as u64),
                    details: None,
                    last_check: Utc::now(),
                })
            }
            Ok(false) => Ok(BackendHealth {
                status: HealthStatus::Unhealthy,
                response_time_ms: Some(start_time.elapsed().as_millis() as u64),
                details: Some({
                    let mut details = HashMap::new();
                    details.insert(
                        "error".to_string(),
                        serde_json::Value::String("Ping returned false".to_string()),
                    );
                    details
                }),
                last_check: Utc::now(),
            }),
            Err(e) => Ok(BackendHealth {
                status: HealthStatus::Unhealthy,
                response_time_ms: Some(start_time.elapsed().as_millis() as u64),
                details: Some({
                    let mut details = HashMap::new();
                    details.insert(
                        "error".to_string(),
                        serde_json::Value::String(format!("Ping failed: {}", e)),
                    );
                    details
                }),
                last_check: Utc::now(),
            }),
        }
    }

    async fn get_stats(&self) -> Result<BackendStats, DbxError> {
        let mut conn = self.pool.acquire_connection().await.map_err(|e| {
            DbxError::backend(
                self.backend_name.clone(),
                format!("Connection failed: {}", e),
            )
        })?;

        // Get Redis INFO
        let info: String = redis::cmd("INFO")
            .arg("stats")
            .query_async(&mut *conn)
            .await
            .map_err(|e| {
                DbxError::backend(
                    self.backend_name.clone(),
                    format!("INFO command failed: {}", e),
                )
            })?;

        // Parse stats from INFO output
        let mut total_commands = 0;
        let mut rejected_connections = 0;
        let mut used_memory = 0;

        for line in info.lines() {
            if line.starts_with("total_commands_processed:") {
                if let Some(value) = line.split(':').nth(1) {
                    total_commands = value.parse().unwrap_or(0);
                }
            } else if line.starts_with("rejected_connections:") {
                if let Some(value) = line.split(':').nth(1) {
                    rejected_connections = value.parse().unwrap_or(0);
                }
            } else if line.starts_with("used_memory:") {
                if let Some(value) = line.split(':').nth(1) {
                    used_memory = value.parse().unwrap_or(0);
                }
            }
        }

        Ok(BackendStats {
            connections: ConnectionStats {
                active: 1,
                idle: 0,
                total: 1,
                max_pool_size: 1,
            },
            operations: OperationStats {
                total_operations: total_commands,
                successful_operations: total_commands - rejected_connections,
                failed_operations: rejected_connections,
                operations_per_second: 0.0, // Would need tracking over time
            },
            performance: PerformanceStats {
                avg_response_time_ms: 0.0, // Redis doesn't provide this directly
                p95_response_time_ms: 0.0,
                p99_response_time_ms: 0.0,
            },
            storage: Some(StorageStats {
                used_memory_bytes: used_memory,
                total_memory_bytes: None,
                key_count: 0, // Would need DBSIZE command
                database_size_bytes: Some(used_memory),
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
