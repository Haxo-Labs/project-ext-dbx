use crate::auth::AuthManager;
use crate::error::DbxError;
use crate::types::{
    ApiResponse, BatchOperation, BatchOperationRequest, DataResponseData, DbxBatchOperation,
    DbxResponse,
};
use crate::utils::{HttpUtils, JsonUtils, UrlUtils};
use reqwest::Client;
use serde::Deserialize;

/// Batch operations manager
pub struct BatchManager {
    client: Client,
    base_url: String,
    max_retries: u32,
    retry_delay_ms: u32,
    enable_logging: bool,
}

impl BatchManager {
    /// Create new batch manager
    pub fn new(
        client: Client,
        base_url: String,
        max_retries: u32,
        retry_delay_ms: u32,
        enable_logging: bool,
    ) -> Self {
        Self {
            client,
            base_url,
            max_retries,
            retry_delay_ms,
            enable_logging,
        }
    }

    /// Execute HTTP request with appropriate retry and logging
    async fn execute_request<T: for<'de> Deserialize<'de>>(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<T, DbxError> {
        if self.enable_logging {
            HttpUtils::execute_with_retry_and_logging(
                request,
                self.max_retries,
                self.retry_delay_ms,
                true,
            )
            .await
        } else {
            HttpUtils::execute_with_retry(request, self.max_retries, self.retry_delay_ms).await
        }
    }

    /// Execute batch operations
    pub async fn execute_batch(
        &self,
        auth_manager: &AuthManager,
        operations: Vec<DbxBatchOperation>,
    ) -> Result<DbxResponse, DbxError> {
        if operations.is_empty() {
            return Ok(DbxResponse {
                success: true,
                data: Some("[]".to_string()),
                error: None,
                operation_id: None,
                execution_time_ms: Some(0),
                backend: None,
                metadata: None,
            });
        }

        let auth_header = auth_manager.get_auth_header().await?;

        let batch_ops: Result<Vec<BatchOperation>, DbxError> = operations
            .into_iter()
            .map(|op| self.convert_batch_operation(op))
            .collect();

        let batch_ops = batch_ops?;

        let request_data = BatchOperationRequest {
            operations: batch_ops,
        };

        let request = self
            .client
            .post(&UrlUtils::batch_endpoint(&self.base_url))
            .header("Authorization", auth_header)
            .json(&request_data);

        let api_response: ApiResponse<serde_json::Value> = self.execute_request(request).await?;

        // Handle batch-specific response format
        if api_response.success {
            if let Some(data) = api_response.data {
                // Extract the batch results from the nested structure
                let batch_data = if let Some(arr) = data.as_array() {
                    if let Some(first) = arr.first() {
                        if let Some(inner_data) = first.get("data") {
                            if let Some(inner_arr) = inner_data.as_array() {
                                serde_json::to_string(inner_arr).unwrap_or_default()
                            } else {
                                serde_json::to_string(inner_data).unwrap_or_default()
                            }
                        } else {
                            serde_json::to_string(&data).unwrap_or_default()
                        }
                    } else {
                        "[]".to_string()
                    }
                } else {
                    serde_json::to_string(&data).unwrap_or_default()
                };

                Ok(DbxResponse {
                    success: true,
                    data: Some(batch_data),
                    error: None,
                    operation_id: None,
                    execution_time_ms: Some(0),
                    backend: None,
                    metadata: None,
                })
            } else {
                Ok(DbxResponse {
                    success: true,
                    data: Some("[]".to_string()),
                    error: None,
                    operation_id: None,
                    execution_time_ms: Some(0),
                    backend: None,
                    metadata: None,
                })
            }
        } else {
            Ok(DbxResponse {
                success: false,
                data: None,
                error: api_response.error,
                operation_id: None,
                execution_time_ms: Some(0),
                backend: None,
                metadata: None,
            })
        }
    }

    /// Execute multiple get operations
    pub async fn batch_get(
        &self,
        auth_manager: &AuthManager,
        keys: Vec<String>,
    ) -> Result<DbxResponse, DbxError> {
        let operations = keys
            .into_iter()
            .map(|key| DbxBatchOperation {
                operation_type: "get".to_string(),
                key,
                value: None,
                fields: None,
                ttl: None,
            })
            .collect();

        self.execute_batch(auth_manager, operations).await
    }

    /// Execute multiple set operations
    pub async fn batch_set(
        &self,
        auth_manager: &AuthManager,
        items: Vec<(String, String, Option<u32>)>,
    ) -> Result<DbxResponse, DbxError> {
        let operations = items
            .into_iter()
            .map(|(key, value, ttl)| DbxBatchOperation {
                operation_type: "set".to_string(),
                key,
                value: Some(value),
                fields: None,
                ttl,
            })
            .collect();

        self.execute_batch(auth_manager, operations).await
    }

    /// Execute multiple delete operations
    pub async fn batch_delete(
        &self,
        auth_manager: &AuthManager,
        keys: Vec<String>,
    ) -> Result<DbxResponse, DbxError> {
        let operations = keys
            .into_iter()
            .map(|key| DbxBatchOperation {
                operation_type: "delete".to_string(),
                key,
                value: None,
                fields: None,
                ttl: None,
            })
            .collect();

        self.execute_batch(auth_manager, operations).await
    }

    /// Execute multiple exists operations
    pub async fn batch_exists(
        &self,
        auth_manager: &AuthManager,
        keys: Vec<String>,
    ) -> Result<DbxResponse, DbxError> {
        let operations = keys
            .into_iter()
            .map(|key| DbxBatchOperation {
                operation_type: "exists".to_string(),
                key,
                value: None,
                fields: None,
                ttl: None,
            })
            .collect();

        self.execute_batch(auth_manager, operations).await
    }

    /// Execute multiple update operations
    pub async fn batch_update(
        &self,
        auth_manager: &AuthManager,
        items: Vec<(String, String, Option<u32>)>,
    ) -> Result<DbxResponse, DbxError> {
        let operations = items
            .into_iter()
            .map(|(key, fields_json, ttl)| DbxBatchOperation {
                operation_type: "update".to_string(),
                key,
                value: None,
                fields: Some(fields_json),
                ttl,
            })
            .collect();

        self.execute_batch(auth_manager, operations).await
    }

    /// Convert DbxBatchOperation to internal BatchOperation
    fn convert_batch_operation(&self, op: DbxBatchOperation) -> Result<BatchOperation, DbxError> {
        let value = if let Some(v) = op.value {
            Some(JsonUtils::string_to_json_value(&v))
        } else {
            None
        };

        let fields = if let Some(f) = op.fields {
            Some(JsonUtils::parse_fields_json(&f)?)
        } else {
            None
        };

        Ok(BatchOperation {
            operation_type: op.operation_type,
            key: op.key,
            value,
            fields,
            ttl: op.ttl.map(|t| t as u64),
        })
    }

    /// Execute mixed batch operations with chunking for large batches
    pub async fn execute_chunked_batch(
        &self,
        auth_manager: &AuthManager,
        operations: Vec<DbxBatchOperation>,
        chunk_size: usize,
    ) -> Result<Vec<DbxResponse>, DbxError> {
        if operations.is_empty() {
            return Ok(vec![]);
        }

        let chunk_size = if chunk_size == 0 { 100 } else { chunk_size };
        let mut results = Vec::new();

        for chunk in operations.chunks(chunk_size) {
            let response = self.execute_batch(auth_manager, chunk.to_vec()).await?;
            results.push(response);
        }

        Ok(results)
    }

    /// Validate batch operations before execution
    pub fn validate_batch_operations(
        &self,
        operations: &[DbxBatchOperation],
    ) -> Result<(), DbxError> {
        if operations.is_empty() {
            return Ok(());
        }

        if operations.len() > 1000 {
            return Err(DbxError::validation(
                "Batch operations cannot exceed 1000 items".to_string(),
            ));
        }

        for (index, op) in operations.iter().enumerate() {
            if op.key.is_empty() {
                return Err(DbxError::validation(format!(
                    "Operation at index {} has empty key",
                    index
                )));
            }

            if op.key.len() > 512 {
                return Err(DbxError::validation(format!(
                    "Operation at index {} has key longer than 512 characters",
                    index
                )));
            }

            match op.operation_type.as_str() {
                "get" | "delete" | "exists" => {
                    if op.value.is_some() || op.fields.is_some() {
                        return Err(DbxError::validation(format!(
                            "Operation {} at index {} should not have value or fields",
                            op.operation_type, index
                        )));
                    }
                }
                "set" => {
                    if op.value.is_none() {
                        return Err(DbxError::validation(format!(
                            "Set operation at index {} must have a value",
                            index
                        )));
                    }
                    if op.fields.is_some() {
                        return Err(DbxError::validation(format!(
                            "Set operation at index {} should not have fields",
                            index
                        )));
                    }
                }
                "update" => {
                    if op.fields.is_none() {
                        return Err(DbxError::validation(format!(
                            "Update operation at index {} must have fields",
                            index
                        )));
                    }
                    if op.value.is_some() {
                        return Err(DbxError::validation(format!(
                            "Update operation at index {} should not have value",
                            index
                        )));
                    }
                    if let Some(ref fields_json) = op.fields {
                        JsonUtils::parse_fields_json(fields_json).map_err(|_| {
                            DbxError::validation(format!(
                                "Update operation at index {} has invalid fields JSON",
                                index
                            ))
                        })?;
                    }
                }
                _ => {
                    return Err(DbxError::validation(format!(
                        "Unknown operation type '{}' at index {}",
                        op.operation_type, index
                    )));
                }
            }

            if let Some(ttl) = op.ttl {
                if ttl > 86400 * 365 {
                    return Err(DbxError::validation(format!(
                        "TTL at index {} exceeds maximum of 1 year",
                        index
                    )));
                }
            }
        }

        Ok(())
    }

    /// Create a batch builder for fluent API
    pub fn builder(&self) -> BatchBuilder {
        BatchBuilder::new()
    }
}

/// Fluent builder for batch operations
pub struct BatchBuilder {
    operations: Vec<DbxBatchOperation>,
}

impl BatchBuilder {
    /// Create new batch builder
    pub fn new() -> Self {
        Self {
            operations: Vec::new(),
        }
    }

    /// Add a get operation
    pub fn get(mut self, key: String) -> Self {
        self.operations.push(DbxBatchOperation {
            operation_type: "get".to_string(),
            key,
            value: None,
            fields: None,
            ttl: None,
        });
        self
    }

    /// Add a set operation
    pub fn set(mut self, key: String, value: String, ttl: Option<u32>) -> Self {
        self.operations.push(DbxBatchOperation {
            operation_type: "set".to_string(),
            key,
            value: Some(value),
            fields: None,
            ttl,
        });
        self
    }

    /// Add an update operation
    pub fn update(mut self, key: String, fields_json: String, ttl: Option<u32>) -> Self {
        self.operations.push(DbxBatchOperation {
            operation_type: "update".to_string(),
            key,
            value: None,
            fields: Some(fields_json),
            ttl,
        });
        self
    }

    /// Add a delete operation
    pub fn delete(mut self, key: String) -> Self {
        self.operations.push(DbxBatchOperation {
            operation_type: "delete".to_string(),
            key,
            value: None,
            fields: None,
            ttl: None,
        });
        self
    }

    /// Add an exists operation
    pub fn exists(mut self, key: String) -> Self {
        self.operations.push(DbxBatchOperation {
            operation_type: "exists".to_string(),
            key,
            value: None,
            fields: None,
            ttl: None,
        });
        self
    }

    /// Build the operations list
    pub fn build(self) -> Vec<DbxBatchOperation> {
        self.operations
    }

    /// Get the number of operations
    pub fn len(&self) -> usize {
        self.operations.len()
    }

    /// Check if the builder is empty
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }
}

impl Default for BatchBuilder {
    fn default() -> Self {
        Self::new()
    }
}
