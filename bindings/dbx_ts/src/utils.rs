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

    /// Execute HTTP request with retry logic and structured logging
    pub async fn execute_with_retry_and_logging<T: for<'de> Deserialize<'de>>(
        request_builder: reqwest::RequestBuilder,
        max_retries: u32,
        retry_delay_ms: u32,
        enable_logging: bool,
    ) -> Result<T, DbxError> {
        let mut last_error = None;

        if enable_logging {
            eprintln!(
                "[DBX] Starting request with {} retries, {}ms delay",
                max_retries, retry_delay_ms
            );
        }

        for attempt in 0..=max_retries {
            if enable_logging {
                eprintln!("[DBX] Attempt {}/{}", attempt + 1, max_retries + 1);
            }

            let request = request_builder.try_clone().ok_or_else(|| {
                DbxError::network("Failed to clone request for retry".to_string())
            })?;

            match request.send().await {
                Ok(response) => {
                    let status = response.status();
                    let url = response.url().to_string();

                    if enable_logging {
                        eprintln!("[DBX] Response: {} {}", status, url);
                        if let Some(content_type) = response.headers().get("content-type") {
                            eprintln!("[DBX] Content-Type: {:?}", content_type);
                        }
                        if let Some(content_length) = response.headers().get("content-length") {
                            eprintln!("[DBX] Content-Length: {:?}", content_length);
                        }
                    }

                    if status.is_success() {
                        match response.json::<T>().await {
                            Ok(data) => {
                                if enable_logging {
                                    eprintln!("[DBX] Successfully parsed JSON response");
                                }
                                return Ok(data);
                            }
                            Err(e) => {
                                let error_msg = format!("JSON parsing failed: {}", e);
                                if enable_logging {
                                    eprintln!("[DBX] {}", error_msg);
                                }
                                if attempt == max_retries {
                                    return Err(DbxError::serialization(error_msg));
                                }
                                last_error = Some(DbxError::serialization(error_msg));
                            }
                        }
                    } else {
                        let error_msg = format!("HTTP error: {} {}", status, url);
                        if enable_logging {
                            eprintln!("[DBX] {}", error_msg);
                        }
                        if attempt == max_retries {
                            let body = response.text().await.ok();
                            return Err(status_to_error(status, body));
                        }
                        last_error = Some(status_to_error(status, None));
                    }
                }
                Err(e) => {
                    let error_msg = format!("Request failed: {}", e);
                    if enable_logging {
                        eprintln!("[DBX] {}", error_msg);
                    }
                    if attempt == max_retries {
                        return Err(DbxError::from(e));
                    }
                    last_error = Some(DbxError::from(e));
                }
            }

            if attempt < max_retries {
                if enable_logging {
                    eprintln!("[DBX] Retrying in {}ms...", retry_delay_ms);
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(retry_delay_ms as u64)).await;
            }
        }

        Err(last_error.unwrap_or_else(|| DbxError::unknown("Maximum retries exceeded".to_string())))
    }

    /// Build authorization header from token or API key
    pub fn build_auth_header(
        token: Option<&str>,
        api_key: Option<&str>,
    ) -> Result<String, DbxError> {
        if let Some(api_key) = api_key {
            return Ok(format!("Bearer {}", api_key));
        }

        if let Some(token) = token {
            return Ok(format!("Bearer {}", token));
        }

        Err(DbxError::authentication(
            "Not authenticated. Call authenticate() first or provide API key.".to_string(),
        ))
    }

    /// Convert API response to DbxResponse
    pub fn convert_data_response(api_response: ApiResponse<DataResponseData>) -> DbxResponse {
        let data = api_response.data.as_ref().and_then(|d| {
            d.data
                .as_ref()
                .map(|v| serde_json::to_string(v).unwrap_or_default())
        });
        let operation_id = api_response.data.as_ref().map(|d| d.operation_id.clone());
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
                        data: serde_json::to_string(&item.data).unwrap_or_default(),
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
                error: api_response.error,
            },
        }
    }

    /// Convert generic API response to DbxResponse
    pub fn convert_generic_response(api_response: ApiResponse<serde_json::Value>) -> DbxResponse {
        DbxResponse {
            success: api_response.success,
            data: api_response
                .data
                .map(|d| serde_json::to_string(&d).unwrap_or_default()),
            error: api_response.error,
            operation_id: None,
            execution_time_ms: None,
            backend: None,
            metadata: None,
        }
    }
}

/// Configuration utilities
pub struct ConfigUtils;

impl ConfigUtils {
    /// Validate client configuration
    pub fn validate_config(config: &crate::types::DbxConfig) -> Result<(), DbxError> {
        if config.base_url.is_empty() {
            return Err(DbxError::invalid_config(
                "base_url cannot be empty".to_string(),
            ));
        }

        if !config.base_url.starts_with("http://") && !config.base_url.starts_with("https://") {
            return Err(DbxError::invalid_config(
                "base_url must start with http:// or https://".to_string(),
            ));
        }

        if let Some(timeout) = config.timeout_ms {
            if timeout == 0 {
                return Err(DbxError::invalid_config(
                    "timeout_ms must be greater than 0".to_string(),
                ));
            }
        }

        if let Some(retries) = config.max_retries {
            if retries > 10 {
                return Err(DbxError::invalid_config(
                    "max_retries should not exceed 10".to_string(),
                ));
            }
        }

        if let Some(pool_size) = config.pool_size {
            if pool_size == 0 || pool_size > 100 {
                return Err(DbxError::invalid_config(
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
            .pool_idle_timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| DbxError::invalid_config(format!("Failed to create HTTP client: {}", e)))
    }
}

/// JSON utilities for serialization/deserialization
pub struct JsonUtils;

impl JsonUtils {
    /// Parse JSON string to serde_json::Value
    pub fn parse_json_value(json_str: &str) -> Result<serde_json::Value, DbxError> {
        serde_json::from_str(json_str).map_err(DbxError::from)
    }

    /// Convert string to JSON value, fallback to string if invalid JSON
    pub fn string_to_json_value(value: &str) -> serde_json::Value {
        serde_json::from_str(value).unwrap_or_else(|_| serde_json::Value::String(value.to_string()))
    }

    /// Serialize value to JSON string
    pub fn serialize_to_string<T: serde::Serialize>(value: &T) -> Result<String, DbxError> {
        serde_json::to_string(value).map_err(DbxError::from)
    }

    /// Parse JSON fields for hash operations
    pub fn parse_fields_json(
        fields_json: &str,
    ) -> Result<std::collections::HashMap<String, serde_json::Value>, DbxError> {
        serde_json::from_str(fields_json)
            .map_err(|e| DbxError::validation(format!("Invalid fields JSON: {}", e)))
    }
}

/// URL utilities for building API endpoints
pub struct UrlUtils;

impl UrlUtils {
    /// Build data endpoint URL
    pub fn data_endpoint(base_url: &str, key: &str) -> String {
        format!("{}/api/v1/data/{}", base_url, key)
    }

    /// Build data exists endpoint URL
    pub fn data_exists_endpoint(base_url: &str, key: &str) -> String {
        format!("{}/api/v1/data/{}/exists", base_url, key)
    }

    /// Build batch endpoint URL
    pub fn batch_endpoint(base_url: &str) -> String {
        format!("{}/api/v1/data/batch", base_url)
    }

    /// Build query pattern endpoint URL
    pub fn query_pattern_endpoint(base_url: &str) -> String {
        format!("{}/api/v1/query/pattern", base_url)
    }

    /// Build query text endpoint URL
    pub fn query_text_endpoint(base_url: &str) -> String {
        format!("{}/api/v1/query/text", base_url)
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

    /// Build API keys endpoint URL
    pub fn api_keys_endpoint(base_url: &str) -> String {
        format!("{}/api/v1/api-keys", base_url)
    }

    /// Build API key by ID endpoint URL
    pub fn api_key_by_id_endpoint(base_url: &str, key_id: &str) -> String {
        format!("{}/api/v1/api-keys/{}", base_url, key_id)
    }

    /// Build roles endpoint URL
    pub fn roles_endpoint(base_url: &str) -> String {
        format!("{}/api/v1/roles", base_url)
    }

    /// Build role assign endpoint URL
    pub fn role_assign_endpoint(base_url: &str) -> String {
        format!("{}/api/v1/roles/assign", base_url)
    }

    /// Build rate limit policies endpoint URL
    pub fn rate_limit_policies_endpoint(base_url: &str) -> String {
        format!("{}/api/v1/rate-limit/policies", base_url)
    }

    /// Build rate limit status endpoint URL
    pub fn rate_limit_status_endpoint(base_url: &str, identifier: &str) -> String {
        format!("{}/api/v1/rate-limit/status/{}", base_url, identifier)
    }

    /// Build admin system endpoint URL
    pub fn admin_system_endpoint(base_url: &str) -> String {
        format!("{}/api/v1/admin/system", base_url)
    }

    /// Build admin metrics endpoint URL
    pub fn admin_metrics_endpoint(base_url: &str) -> String {
        format!("{}/api/v1/admin/metrics", base_url)
    }

    /// Build health endpoint URL
    pub fn health_endpoint(base_url: &str) -> String {
        format!("{}/health", base_url)
    }
}
