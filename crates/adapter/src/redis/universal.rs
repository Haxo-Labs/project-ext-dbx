use std::collections::HashMap;
use async_trait::async_trait;
use serde_json::{Map, Value as JsonValue};
use tracing::{debug, warn};
use uuid::Uuid;
use chrono::Utc;
use base64::Engine;

use dbx_core::{
    BackendCapabilities, DataOperation, DataOperationType, DataResult, DataValue, DbxError,
    QueryCapabilities, QueryOperation, QueryResult, QueryResultItem, StreamCapabilities,
    StreamOperation, StreamResult, TransactionSupport, UniversalBackend, BackendFeature,
    BackendHealth, BackendStats, HealthStatus, ConnectionStats, OperationStats, 
    PerformanceStats, StorageStats, ResultMetadata, StreamEntry
};

use super::client::RedisClient;

/// Universal Redis backend implementation
pub struct UniversalRedisBackend {
    client: RedisClient,
    backend_name: String,
}

impl UniversalRedisBackend {
    /// Create a new Universal Redis backend
    pub fn new(client: RedisClient, backend_name: String) -> Self {
        Self {
            client,
            backend_name,
        }
    }

    /// Create from URL
    pub fn from_url(url: &str, backend_name: String) -> Result<Self, DbxError> {
        let client = RedisClient::from_url(url)
            .map_err(|e| DbxError::connection(backend_name.clone(), format!("Failed to connect: {}", e)))?;
        
        Ok(Self::new(client, backend_name))
    }

    /// Convert DataValue to Redis value
    fn data_value_to_redis_value(&self, value: &DataValue) -> Result<String, DbxError> {
        match value {
            DataValue::Null => Ok("".to_string()),
            DataValue::Bool(b) => Ok(if *b { "1".to_string() } else { "0".to_string() }),
            DataValue::Int(i) => Ok(i.to_string()),
            DataValue::Float(f) => Ok(f.to_string()),
            DataValue::String(s) => Ok(s.clone()),
            DataValue::Bytes(b) => Ok(String::from_utf8_lossy(b).to_string()),
            DataValue::Array(arr) => {
                let json_value = JsonValue::Array(
                    arr.iter().map(|v| self.data_value_to_json(v)).collect::<Result<Vec<_>, _>>()?
                );
                serde_json::to_string(&json_value)
                    .map_err(|e| DbxError::serialization(format!("Failed to serialize array: {}", e)))
            }
            DataValue::Object(obj) => {
                let json_obj: Map<String, JsonValue> = obj.iter()
                    .map(|(k, v)| Ok((k.clone(), self.data_value_to_json(v)?)))
                    .collect::<Result<Map<String, JsonValue>, DbxError>>()?;
                serde_json::to_string(&JsonValue::Object(json_obj))
                    .map_err(|e| DbxError::serialization(format!("Failed to serialize object: {}", e)))
            }
        }
    }

    /// Convert DataValue to JSON for serialization
    fn data_value_to_json(&self, value: &DataValue) -> Result<JsonValue, DbxError> {
        match value {
            DataValue::Null => Ok(JsonValue::Null),
            DataValue::Bool(b) => Ok(JsonValue::Bool(*b)),
            DataValue::Int(i) => Ok(JsonValue::Number(serde_json::Number::from(*i))),
            DataValue::Float(f) => {
                serde_json::Number::from_f64(*f)
                    .map(JsonValue::Number)
                    .ok_or_else(|| DbxError::serialization("Invalid float value".to_string()))
            }
            DataValue::String(s) => Ok(JsonValue::String(s.clone())),
            DataValue::Bytes(b) => {
                let base64 = base64::prelude::BASE64_STANDARD.encode(b);
                Ok(JsonValue::String(base64))
            }
            DataValue::Array(arr) => {
                let json_arr: Result<Vec<JsonValue>, DbxError> = arr.iter()
                    .map(|v| self.data_value_to_json(v))
                    .collect();
                Ok(JsonValue::Array(json_arr?))
            }
            DataValue::Object(obj) => {
                let json_obj: Result<Map<String, JsonValue>, DbxError> = obj.iter()
                    .map(|(k, v)| Ok((k.clone(), self.data_value_to_json(v)?)))
                    .collect();
                Ok(JsonValue::Object(json_obj?))
            }
        }
    }

    /// Convert Redis string value to DataValue
    fn redis_value_to_data_value(&self, value: Option<String>) -> Result<DataValue, DbxError> {
        match value {
            None => Ok(DataValue::Null),
            Some(s) => {
                // Try to parse as different types
                if s.is_empty() {
                    return Ok(DataValue::Null);
                }

                // Try JSON first (for complex types)
                if s.starts_with('{') || s.starts_with('[') {
                    if let Ok(json_value) = serde_json::from_str::<JsonValue>(&s) {
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
                    _ => Ok(DataValue::String(s))
                }
            }
        }
    }

    /// Convert JSON to DataValue
    fn json_to_data_value(&self, json: &JsonValue) -> Result<DataValue, DbxError> {
        match json {
            JsonValue::Null => Ok(DataValue::Null),
            JsonValue::Bool(b) => Ok(DataValue::Bool(*b)),
            JsonValue::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Ok(DataValue::Int(i))
                } else if let Some(f) = n.as_f64() {
                    Ok(DataValue::Float(f))
                } else {
                    Err(DbxError::serialization("Invalid number format".to_string()))
                }
            }
            JsonValue::String(s) => {
                // Check if it's base64 encoded bytes
                if let Ok(bytes) = base64::prelude::BASE64_STANDARD.decode(s) {
                    if String::from_utf8(bytes.clone()).is_err() {
                        return Ok(DataValue::Bytes(bytes));
                    }
                }
                Ok(DataValue::String(s.clone()))
            }
            JsonValue::Array(arr) => {
                let data_arr: Result<Vec<DataValue>, DbxError> = arr.iter()
                    .map(|v| self.json_to_data_value(v))
                    .collect();
                Ok(DataValue::Array(data_arr?))
            }
            JsonValue::Object(obj) => {
                let data_obj: Result<HashMap<String, DataValue>, DbxError> = obj.iter()
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
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<DataValue, DbxError>> + Send + 'a>> {
        Box::pin(async move {
            match operation {
                DataOperation::Get { key, fields } => {
                    if let Some(fields) = fields {
                        if fields.is_empty() {
                            // Simple key-value get
                            let redis_string = self.client.string();
                            let value = redis_string.get(key)
                                .map_err(|e| DbxError::backend(self.backend_name.clone(), format!("Get failed: {}", e)))?;
                            self.redis_value_to_data_value(value)
                        } else {
                            // Hash field get
                            let redis_hash = self.client.hash();
                            if fields.len() == 1 {
                                let value = redis_hash.hget(key, &fields[0])
                                    .map_err(|e| DbxError::backend(self.backend_name.clone(), format!("Hash get failed: {}", e)))?;
                                self.redis_value_to_data_value(value)
                            } else {
                                // Multiple fields
                                let mut result = HashMap::new();
                                for field in fields {
                                    let value = redis_hash.hget(key, field)
                                        .map_err(|e| DbxError::backend(self.backend_name.clone(), format!("Hash get failed: {}", e)))?;
                                    result.insert(field.clone(), self.redis_value_to_data_value(value)?);
                                }
                                Ok(DataValue::Object(result))
                            }
                        }
                    } else {
                        // Simple key-value get (no fields specified)
                        let redis_string = self.client.string();
                        let value = redis_string.get(key)
                            .map_err(|e| DbxError::backend(self.backend_name.clone(), format!("Get failed: {}", e)))?;
                        self.redis_value_to_data_value(value)
                    }
                }

                DataOperation::Set { key, value, ttl } => {
                    let redis_value = self.data_value_to_redis_value(value)?;
                    let redis_string = self.client.string();
                    
                    if let Some(ttl_secs) = ttl {
                        redis_string.set_with_expiry(key, &redis_value, *ttl_secs as usize)
                            .map_err(|e| DbxError::backend(self.backend_name.clone(), format!("Set with TTL failed: {}", e)))?;
                    } else {
                        redis_string.set(key, &redis_value)
                            .map_err(|e| DbxError::backend(self.backend_name.clone(), format!("Set failed: {}", e)))?;
                    }

                    Ok(DataValue::Bool(true))
                }

                DataOperation::Update { key, fields, ttl } => {
                    let redis_hash = self.client.hash();
                    
                    for (field, value) in fields {
                        let redis_value = self.data_value_to_redis_value(value)?;
                        redis_hash.hset(key, field, &redis_value)
                            .map_err(|e| DbxError::backend(self.backend_name.clone(), format!("Hash set failed: {}", e)))?;
                    }

                    if let Some(ttl_secs) = ttl {
                        redis_hash.expire(key, *ttl_secs)
                            .map_err(|e| DbxError::backend(self.backend_name.clone(), format!("Set TTL failed: {}", e)))?;
                    }

                    Ok(DataValue::Bool(true))
                }

                DataOperation::Delete { key, fields } => {
                    if let Some(fields) = fields {
                        if fields.is_empty() {
                            // Delete entire key
                            let redis_string = self.client.string();
                            redis_string.del(key)
                                .map_err(|e| DbxError::backend(self.backend_name.clone(), format!("Delete failed: {}", e)))?;
                        } else {
                            // Delete hash fields
                            let redis_hash = self.client.hash();
                            let field_refs: Vec<&str> = fields.iter().map(|s| s.as_str()).collect();
                            redis_hash.hdel(key, &field_refs)
                                .map_err(|e| DbxError::backend(self.backend_name.clone(), format!("Hash delete failed: {}", e)))?;
                        }
                    } else {
                        // Delete entire key (no fields specified)
                        let redis_string = self.client.string();
                        redis_string.del(key)
                            .map_err(|e| DbxError::backend(self.backend_name.clone(), format!("Delete failed: {}", e)))?;
                    }
                    Ok(DataValue::Bool(true))
                }

                DataOperation::Exists { key, fields } => {
                    if let Some(fields) = fields {
                        if fields.is_empty() {
                            // Check if key exists
                            let redis_string = self.client.string();
                            let exists = redis_string.exists(key)
                                .map_err(|e| DbxError::backend(self.backend_name.clone(), format!("Exists check failed: {}", e)))?;
                            Ok(DataValue::Bool(exists))
                        } else {
                            // Check if hash fields exist
                            let redis_hash = self.client.hash();
                            let mut result = HashMap::new();
                            for field in fields {
                                let exists = redis_hash.hexists(key, field)
                                    .map_err(|e| DbxError::backend(self.backend_name.clone(), format!("Hash exists check failed: {}", e)))?;
                                result.insert(field.clone(), DataValue::Bool(exists));
                            }
                            Ok(DataValue::Object(result))
                        }
                    } else {
                        // Check if key exists (no fields specified)
                        let redis_string = self.client.string();
                        let exists = redis_string.exists(key)
                            .map_err(|e| DbxError::backend(self.backend_name.clone(), format!("Exists check failed: {}", e)))?;
                        Ok(DataValue::Bool(exists))
                    }
                }

                DataOperation::SetTtl { key, ttl } => {
                    let redis_string = self.client.string();
                    let success = redis_string.expire(key, *ttl)
                        .map_err(|e| DbxError::backend(self.backend_name.clone(), format!("Set TTL failed: {}", e)))?;
                    Ok(DataValue::Bool(success))
                }

                DataOperation::GetTtl { key } => {
                    let redis_string = self.client.string();
                    let ttl = redis_string.ttl(key)
                        .map_err(|e| DbxError::backend(self.backend_name.clone(), format!("Get TTL failed: {}", e)))?;
                    Ok(DataValue::Int(ttl))
                }

                DataOperation::Batch { operations } => {
                    // Execute all operations in sequence (Redis doesn't have multi-statement transactions easily accessible)
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
impl UniversalBackend for UniversalRedisBackend {
    fn name(&self) -> &str {
        &self.backend_name
    }

    fn capabilities(&self) -> BackendCapabilities {
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
                pagination: true, // Limited support
                aggregations: false,
            },
            stream_capabilities: StreamCapabilities {
                pub_sub: true,
                streams: true,
                persistent_streams: true,
                stream_groups: false, // Could be added later
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
                
                Ok(DataResult::success_with_metadata(operation_id, data, metadata))
            }
            Err(error) => {
                Ok(DataResult::error(operation_id, error))
            }
        }
    }

    async fn execute_query(&self, operation: QueryOperation) -> Result<QueryResult, DbxError> {
        debug!(
            backend = %self.backend_name,
            query_id = %operation.id,
            "Executing query operation"
        );

        // Redis doesn't support complex queries, but we can implement basic pattern matching
        let start_time = std::time::Instant::now();

        match &operation.filter {
            dbx_core::QueryFilter::KeyPattern { pattern } => {
                let redis_string = self.client.string();
                let keys = redis_string.keys(pattern)
                    .map_err(|e| DbxError::backend(self.backend_name.clone(), format!("Key pattern scan failed: {}", e)))?;

                let limited_keys = if let Some(limit) = operation.limit {
                    keys.into_iter().take(limit).collect()
                } else {
                    keys
                };

                let mut results = Vec::new();
                for key in limited_keys {
                    // Get the value for each key
                    let value = redis_string.get(&key)
                        .map_err(|e| DbxError::backend(self.backend_name.clone(), format!("Get key value failed: {}", e)))?;
                    
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
                let mut query_result = QueryResult::success_with_count(operation.id, results, result_count);
                query_result.metadata = Some(metadata);
                Ok(query_result)
            }
            _ => {
                warn!(backend = %self.backend_name, "Complex query operation not supported by Redis backend");
                Err(DbxError::unsupported_operation("Complex queries", &self.backend_name))
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
                let mut conn = self.client.get_new_connection()
                    .map_err(|e| DbxError::backend(self.backend_name.clone(), format!("Connection failed: {}", e)))?;
                
                let serialized_message = self.data_value_to_redis_value(&message)?;
                let _subscribers: i64 = redis::cmd("PUBLISH")
                    .arg(channel)
                    .arg(serialized_message)
                    .query(&mut conn)
                    .map_err(|e| DbxError::backend(self.backend_name.clone(), format!("Publish failed: {}", e)))?;
                
                Ok(StreamResult::Published {
                    channel: channel.clone(),
                    message_id: Uuid::new_v4().to_string(),
                })
            }

            StreamOperation::Subscribe { channel } => {
                Ok(StreamResult::Subscribed {
                    channel: channel.clone(),
                    subscriber_id: Uuid::new_v4(),
                })
            }

            StreamOperation::Unsubscribe { channel } => {
                Ok(StreamResult::Unsubscribed {
                    channel: channel.clone(),
                    subscriber_id: Uuid::new_v4(),
                })
            }

            StreamOperation::CreateStream { name, config: _ } => {
                let mut conn = self.client.get_new_connection()
                    .map_err(|e| DbxError::backend(self.backend_name.clone(), format!("Connection failed: {}", e)))?;
                
                let stream_id: String = redis::cmd("XADD")
                    .arg(name)
                    .arg("*")
                    .arg("__init__")
                    .arg("true")
                    .query(&mut conn)
                    .map_err(|e| DbxError::backend(self.backend_name.clone(), format!("Stream creation failed: {}", e)))?;
                
                Ok(StreamResult::StreamCreated {
                    stream: name.clone(),
                    stream_id,
                })
            }

            StreamOperation::StreamAdd { stream, fields } => {
                let mut conn = self.client.get_new_connection()
                    .map_err(|e| DbxError::backend(self.backend_name.clone(), format!("Connection failed: {}", e)))?;
                
                let mut cmd = redis::cmd("XADD");
                cmd.arg(stream).arg("*");
                
                for (field, value) in fields {
                    let serialized_value = self.data_value_to_redis_value(value)?;
                    cmd.arg(field).arg(serialized_value);
                }
                
                let entry_id: String = cmd.query(&mut conn)
                    .map_err(|e| DbxError::backend(self.backend_name.clone(), format!("Stream add failed: {}", e)))?;
                
                Ok(StreamResult::StreamEntryAdded {
                    stream: stream.clone(),
                    entry_id,
                })
            }

            StreamOperation::StreamRead { stream, count, .. } => {
                let mut conn = self.client.get_new_connection()
                    .map_err(|e| DbxError::backend(self.backend_name.clone(), format!("Connection failed: {}", e)))?;
                
                let limit = count.unwrap_or(10);
                
                // Read from stream
                let results: Vec<(String, Vec<(String, String)>)> = redis::cmd("XREAD")
                    .arg("COUNT")
                    .arg(limit)
                    .arg("STREAMS")
                    .arg(stream)
                    .arg("0")
                    .query(&mut conn)
                    .map_err(|e| DbxError::backend(self.backend_name.clone(), format!("Stream read failed: {}", e)))?;
                
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
        
        match self.client.ping() {
            Ok(true) => {
                let response_time = start_time.elapsed();
                Ok(BackendHealth {
                    status: HealthStatus::Healthy,
                    response_time_ms: Some(response_time.as_millis() as u64),
                    details: None,
                    last_check: Utc::now(),
                })
            }
            Ok(false) => {
                Ok(BackendHealth {
                    status: HealthStatus::Unhealthy,
                    response_time_ms: Some(start_time.elapsed().as_millis() as u64),
                    details: Some({
                        let mut details = HashMap::new();
                        details.insert("error".to_string(), serde_json::Value::String("Ping returned false".to_string()));
                        details
                    }),
                    last_check: Utc::now(),
                })
            }
            Err(e) => {
                Ok(BackendHealth {
                    status: HealthStatus::Unhealthy,
                    response_time_ms: Some(start_time.elapsed().as_millis() as u64),
                    details: Some({
                        let mut details = HashMap::new();
                        details.insert("error".to_string(), serde_json::Value::String(format!("Ping failed: {}", e)));
                        details
                    }),
                    last_check: Utc::now(),
                })
            }
        }
    }

    async fn get_stats(&self) -> Result<BackendStats, DbxError> {
        let mut conn = self.client.get_new_connection()
            .map_err(|e| DbxError::backend(self.backend_name.clone(), format!("Connection failed: {}", e)))?;

        // Get Redis INFO
        let info: String = redis::cmd("INFO")
            .arg("stats")
            .query(&mut conn)
            .map_err(|e| DbxError::backend(self.backend_name.clone(), format!("INFO command failed: {}", e)))?;

        // Parse basic stats from INFO output
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
        self.client.ping()
            .map_err(|e| DbxError::connection(self.backend_name.clone(), format!("Connection test failed: {}", e)))?;
        Ok(())
    }
}
