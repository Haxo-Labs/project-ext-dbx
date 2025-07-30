use crate::error::{status_to_error, DbxError};
use crate::types::{
    ApiResponse, DataResponseData, DbxQueryResponse, DbxResponse, QueryResponseData,
};
use reqwest::Client;
use serde::Deserialize;
use uuid::Uuid;

/// HTTP utilities for requests with retry logic
pub struct HttpUtils;

impl HttpUtils {
    /// Execute HTTP request with retry logic
    pub async fn execute_with_retry<T: for<'de> Deserialize<'de>>(
        request_builder: reqwest::RequestBuilder,
        max_retries: u32,
        retry_delay_ms: u32,
    ) -> Result<T, DbxError> {
        Self::execute_with_retry_and_logging(request_builder, max_retries, retry_delay_ms, false)
            .await
    }

    /// Execute HTTP request with retry logic and optional logging
    pub async fn execute_with_retry_and_logging<T: for<'de> Deserialize<'de>>(
        request_builder: reqwest::RequestBuilder,
        max_retries: u32,
        retry_delay_ms: u32,
        enable_logging: bool,
    ) -> Result<T, DbxError> {
        let mut last_error = None;

        if enable_logging {
            // Starting request with retries
        }

        for attempt in 0..=max_retries {
            if enable_logging {
                // Attempt logging
            }

            let request = request_builder.try_clone().ok_or_else(|| {
                DbxError::network("Failed to clone request for retry".to_string())
            })?;

            match request.send().await {
                Ok(response) => {
                    let status = response.status();
                    let url = response.url().to_string();

                    if enable_logging {
                        // Response details would be logged here
                    }

                    if status.is_success() {
                        match response.json::<T>().await {
                            Ok(data) => {
                                if enable_logging {
                                    // Success logging
                                }
                                return Ok(data);
                            }
                            Err(e) => {
                                let error_msg = format!("JSON parsing failed: {}", e);
                                if enable_logging {
                                    // Error logging
                                }
                                if attempt == max_retries {
                                    return Err(DbxError::serialization(error_msg));
                                }
                                last_error = Some(DbxError::serialization(error_msg));
                            }
                        }
                    } else {
                        let _error_msg = format!("HTTP error: {} {}", status, url);
                        if enable_logging {
                            // Error logging
                        }
                        if attempt == max_retries {
                            let body = response.text().await.ok();
                            return Err(status_to_error(status, body));
                        }
                        last_error = Some(status_to_error(status, None));
                    }
                }
                Err(e) => {
                    let _error_msg = format!("Request failed: {}", e);
                    if enable_logging {
                        // Error logging
                    }
                    if attempt == max_retries {
                        return Err(DbxError::from(e));
                    }
                    last_error = Some(DbxError::from(e));
                }
            }

            if attempt < max_retries {
                if enable_logging {
                    // Retry logging
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(retry_delay_ms as u64)).await;
            }
        }

        Err(last_error.unwrap_or_else(|| DbxError::unknown("Maximum retries exceeded".to_string())))
    }

    /// Build authorization header
    pub fn build_auth_header(token: &str) -> String {
        format!("Bearer {}", token)
    }

    /// Convert API response to DbxResponse
    pub fn convert_data_response(api_response: ApiResponse<DataResponseData>) -> DbxResponse {
        let data = api_response.data.as_ref().and_then(|d| {
            d.data.as_ref().and_then(|v| match v {
                serde_json::Value::String(s) => Some(s.clone()),
                serde_json::Value::Null => None,
                other => Some(serde_json::to_string(other).unwrap_or_default()),
            })
        });

        let operation_id = api_response
            .data
            .as_ref()
            .and_then(|d| Some(d.operation_id.clone()));
        let execution_time_ms = api_response
            .data
            .as_ref()
            .and_then(|d| d.execution_time_ms.map(|t| t as u32));
        let backend = api_response.data.as_ref().and_then(|d| d.backend.clone());

        DbxResponse {
            success: api_response.success,
            data,
            error: api_response.error,
            operation_id,
            execution_time_ms,
            backend,
            metadata: None,
        }
    }

    /// Convert query response to DbxQueryResponse
    pub fn convert_query_response(
        api_response: ApiResponse<QueryResponseData>,
    ) -> DbxQueryResponse {
        match api_response.data {
            Some(data) => DbxQueryResponse {
                success: api_response.success,
                query_id: data.query_id,
                results: data
                    .results
                    .into_iter()
                    .map(|item| crate::types::DbxQueryResult {
                        key: item.key,
                        data: item.data.to_string(),
                        score: item.score,
                    })
                    .collect(),
                total_count: data.total_count.map(|c| c as u32),
                execution_time_ms: data.execution_time_ms.map(|t| t as u32),
                backend: data.backend,
                error: api_response.error,
            },
            None => DbxQueryResponse {
                success: false,
                query_id: Uuid::new_v4().to_string(),
                results: vec![],
                total_count: None,
                execution_time_ms: None,
                backend: None,
                error: api_response
                    .error
                    .or(Some("No data in response".to_string())),
            },
        }
    }

    /// Convert generic API response to DbxResponse
    pub fn convert_generic_response(api_response: ApiResponse<serde_json::Value>) -> DbxResponse {
        DbxResponse {
            success: api_response.success,
            data: api_response
                .data
                .and_then(|v| serde_json::to_string(&v).ok()),
            error: api_response.error,
            operation_id: None,
            execution_time_ms: Some(0),
            backend: None,
            metadata: None,
        }
    }
}

/// Configuration utilities
pub struct ConfigUtils;

impl ConfigUtils {
    /// Validate configuration
    pub fn validate_config(config: &crate::types::DbxConfig) -> Result<(), DbxError> {
        if !config.base_url.starts_with("http://") && !config.base_url.starts_with("https://") {
            return Err(DbxError::validation(
                "base_url must start with http:// or https://".to_string(),
            ));
        }

        if let Some(timeout) = config.timeout_ms {
            if timeout == 0 {
                return Err(DbxError::validation(
                    "timeout_ms must be greater than 0".to_string(),
                ));
            }
        }

        if let Some(retries) = config.max_retries {
            if retries > 10 {
                return Err(DbxError::validation(
                    "max_retries should not exceed 10".to_string(),
                ));
            }
        }

        if let Some(pool_size) = config.pool_size {
            if pool_size == 0 || pool_size > 100 {
                return Err(DbxError::validation(
                    "pool_size must be between 1 and 100".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Create HTTP client from configuration
    pub fn create_http_client(config: &crate::types::DbxConfig) -> Result<Client, DbxError> {
        let timeout = std::time::Duration::from_millis(config.timeout_ms.unwrap_or(30000) as u64);
        let pool_size = config.pool_size.unwrap_or(10);

        Client::builder()
            .timeout(timeout)
            .pool_max_idle_per_host(pool_size as usize)
            .build()
            .map_err(|e| DbxError::network(format!("Failed to create HTTP client: {}", e)))
    }
}

/// JSON parsing utilities
pub struct JsonUtils;

impl JsonUtils {
    /// Parse JSON value from string
    pub fn parse_json_value(json_str: &str) -> Result<serde_json::Value, DbxError> {
        serde_json::from_str(json_str)
            .map_err(|e| DbxError::serialization(format!("JSON parsing failed: {}", e)))
    }

    /// Convert string to JSON value
    pub fn string_to_json_value(s: String) -> serde_json::Value {
        serde_json::Value::String(s)
    }

    /// Serialize value to string
    pub fn serialize_to_string<T: serde::Serialize>(value: &T) -> Result<String, DbxError> {
        serde_json::to_string(value)
            .map_err(|e| DbxError::serialization(format!("Serialization failed: {}", e)))
    }

    /// Parse fields JSON
    pub fn parse_fields_json(
        fields_json: &str,
    ) -> Result<std::collections::HashMap<String, serde_json::Value>, DbxError> {
        serde_json::from_str(fields_json)
            .map_err(|e| DbxError::validation(format!("Invalid fields JSON: {}", e)))
    }
}

/// URL building utilities
pub struct UrlUtils;

impl UrlUtils {
    /// Build data endpoint URL
    pub fn data_endpoint(base_url: &str, key: &str) -> String {
        format!("{}/api/v1/data/{}", base_url, key)
    }

    /// Build batch endpoint URL
    pub fn batch_endpoint(base_url: &str) -> String {
        format!("{}/api/v1/data/batch", base_url)
    }

    /// Build health endpoint URL
    pub fn health_endpoint(base_url: &str) -> String {
        format!("{}/health", base_url)
    }

    /// Build auth login endpoint URL
    pub fn auth_login_endpoint(base_url: &str) -> String {
        format!("{}/api/v1/auth/login", base_url)
    }

    /// Build auth refresh endpoint URL
    pub fn auth_refresh_endpoint(base_url: &str) -> String {
        format!("{}/api/v1/auth/refresh", base_url)
    }

    /// Build auth logout endpoint URL
    pub fn auth_logout_endpoint(base_url: &str) -> String {
        format!("{}/api/v1/auth/logout", base_url)
    }

    /// Build auth validate endpoint URL
    pub fn auth_validate_endpoint(base_url: &str) -> String {
        format!("{}/api/v1/auth/validate", base_url)
    }

    /// Build query pattern endpoint URL
    pub fn query_pattern_endpoint(base_url: &str) -> String {
        format!("{}/api/v1/query/pattern", base_url)
    }

    /// Build query text endpoint URL
    pub fn query_text_endpoint(base_url: &str) -> String {
        format!("{}/api/v1/query/text", base_url)
    }
}
