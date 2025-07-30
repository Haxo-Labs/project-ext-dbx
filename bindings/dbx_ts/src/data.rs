use crate::auth::AuthManager;
use crate::error::DbxError;
use crate::types::{ApiResponse, DataResponseData, DbxResponse, SetDataRequest, UpdateDataRequest};
use crate::utils::{HttpUtils, JsonUtils, UrlUtils};
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;

/// Data operations manager
pub struct DataManager {
    client: Client,
    base_url: String,
    max_retries: u32,
    retry_delay_ms: u32,
    enable_logging: bool,
}

impl DataManager {
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

    /// Set a value for a key with optional TTL
    pub async fn set(
        &self,
        auth_manager: &AuthManager,
        key: String,
        value: String,
        ttl: Option<u32>,
    ) -> Result<DbxResponse, DbxError> {
        let auth_header = auth_manager.get_auth_header().await?;
        let json_value = JsonUtils::string_to_json_value(value.clone());
        let request_data = SetDataRequest {
            value: json_value,
            ttl: ttl.map(|t| t as u64),
        };

        let request = self
            .client
            .post(&UrlUtils::data_endpoint(&self.base_url, &key))
            .header("Authorization", auth_header)
            .json(&request_data);

        let api_response: ApiResponse<DataResponseData> = self.execute_request(request).await?;

        Ok(HttpUtils::convert_data_response(api_response))
    }

    /// Get a value by key
    pub async fn get(
        &self,
        auth_manager: &AuthManager,
        key: String,
    ) -> Result<DbxResponse, DbxError> {
        let auth_header = auth_manager.get_auth_header().await?;

        let request = self
            .client
            .get(&UrlUtils::data_endpoint(&self.base_url, &key))
            .header("Authorization", auth_header);

        let api_response: ApiResponse<DataResponseData> = self.execute_request(request).await?;

        Ok(HttpUtils::convert_data_response(api_response))
    }

    /// Update fields for a key (hash operations)
    pub async fn update(
        &self,
        auth_manager: &AuthManager,
        key: String,
        fields_json: String,
        ttl: Option<u32>,
    ) -> Result<DbxResponse, DbxError> {
        let auth_header = auth_manager.get_auth_header().await?;
        let fields = JsonUtils::parse_fields_json(&fields_json)?;

        let request_data = UpdateDataRequest {
            fields,
            ttl: ttl.map(|t| t as u64),
        };

        let request = self
            .client
            .put(&UrlUtils::data_endpoint(&self.base_url, &key))
            .header("Authorization", auth_header)
            .json(&request_data);

        let api_response: ApiResponse<DataResponseData> = self.execute_request(request).await?;

        Ok(HttpUtils::convert_data_response(api_response))
    }

    /// Delete a key
    pub async fn delete(
        &self,
        auth_manager: &AuthManager,
        key: String,
    ) -> Result<DbxResponse, DbxError> {
        let auth_header = auth_manager.get_auth_header().await?;

        let request = self
            .client
            .delete(&UrlUtils::data_endpoint(&self.base_url, &key))
            .header("Authorization", auth_header);

        let api_response: ApiResponse<DataResponseData> = self.execute_request(request).await?;

        Ok(HttpUtils::convert_data_response(api_response))
    }

    /// Check if a key exists
    pub async fn exists(
        &self,
        auth_manager: &AuthManager,
        key: String,
    ) -> Result<DbxResponse, DbxError> {
        let auth_header = auth_manager.get_auth_header().await?;

        let exists_url = format!("{}/api/v1/data/{}/exists", self.base_url, key);
        let request = self
            .client
            .get(&exists_url)
            .header("Authorization", auth_header);

        let api_response: ApiResponse<DataResponseData> = self.execute_request(request).await?;

        Ok(HttpUtils::convert_data_response(api_response))
    }

    /// Get TTL for a key
    pub async fn get_ttl(
        &self,
        auth_manager: &AuthManager,
        key: String,
    ) -> Result<DbxResponse, DbxError> {
        let auth_header = auth_manager.get_auth_header().await?;

        let request = self
            .client
            .get(&format!(
                "{}/ttl",
                UrlUtils::data_endpoint(&self.base_url, &key)
            ))
            .header("Authorization", auth_header);

        let api_response: ApiResponse<DataResponseData> = self.execute_request(request).await?;

        Ok(HttpUtils::convert_data_response(api_response))
    }

    /// Set TTL for a key
    pub async fn set_ttl(
        &self,
        auth_manager: &AuthManager,
        key: String,
        ttl_seconds: u32,
    ) -> Result<DbxResponse, DbxError> {
        let auth_header = auth_manager.get_auth_header().await?;

        let request = self
            .client
            .put(&format!(
                "{}/ttl",
                UrlUtils::data_endpoint(&self.base_url, &key)
            ))
            .header("Authorization", auth_header)
            .json(&serde_json::json!({ "ttl": ttl_seconds }));

        let api_response: ApiResponse<DataResponseData> = self.execute_request(request).await?;

        Ok(HttpUtils::convert_data_response(api_response))
    }

    /// Increment a numeric value
    pub async fn increment(
        &self,
        auth_manager: &AuthManager,
        key: String,
        amount: Option<i64>,
    ) -> Result<DbxResponse, DbxError> {
        let auth_header = auth_manager.get_auth_header().await?;

        let request = self
            .client
            .post(&format!(
                "{}/incr",
                UrlUtils::data_endpoint(&self.base_url, &key)
            ))
            .header("Authorization", auth_header)
            .json(&serde_json::json!({ "amount": amount.unwrap_or(1) }));

        let api_response: ApiResponse<DataResponseData> = self.execute_request(request).await?;

        Ok(HttpUtils::convert_data_response(api_response))
    }

    /// Decrement a numeric value
    pub async fn decrement(
        &self,
        auth_manager: &AuthManager,
        key: String,
        amount: Option<i64>,
    ) -> Result<DbxResponse, DbxError> {
        let auth_header = auth_manager.get_auth_header().await?;

        let request = self
            .client
            .post(&format!(
                "{}/decr",
                UrlUtils::data_endpoint(&self.base_url, &key)
            ))
            .header("Authorization", auth_header)
            .json(&serde_json::json!({ "amount": amount.unwrap_or(1) }));

        let api_response: ApiResponse<DataResponseData> = self.execute_request(request).await?;

        Ok(HttpUtils::convert_data_response(api_response))
    }

    /// Append to a string value
    pub async fn append(
        &self,
        auth_manager: &AuthManager,
        key: String,
        value: String,
    ) -> Result<DbxResponse, DbxError> {
        let auth_header = auth_manager.get_auth_header().await?;

        let request = self
            .client
            .post(&format!(
                "{}/append",
                UrlUtils::data_endpoint(&self.base_url, &key)
            ))
            .header("Authorization", auth_header)
            .json(&serde_json::json!({ "value": value }));

        let api_response: ApiResponse<DataResponseData> = self.execute_request(request).await?;

        Ok(HttpUtils::convert_data_response(api_response))
    }

    /// Get length of a value
    pub async fn length(
        &self,
        auth_manager: &AuthManager,
        key: String,
    ) -> Result<DbxResponse, DbxError> {
        let auth_header = auth_manager.get_auth_header().await?;

        let request = self
            .client
            .get(&format!(
                "{}/length",
                UrlUtils::data_endpoint(&self.base_url, &key)
            ))
            .header("Authorization", auth_header);

        let api_response: ApiResponse<DataResponseData> = self.execute_request(request).await?;

        Ok(HttpUtils::convert_data_response(api_response))
    }

    /// Set value if key does not exist
    pub async fn set_if_not_exists(
        &self,
        auth_manager: &AuthManager,
        key: String,
        value: String,
        ttl: Option<u32>,
    ) -> Result<DbxResponse, DbxError> {
        let auth_header = auth_manager.get_auth_header().await?;
        let json_value = JsonUtils::string_to_json_value(value.clone());

        let mut request_data = HashMap::new();
        request_data.insert("value".to_string(), json_value);
        request_data.insert("if_not_exists".to_string(), serde_json::Value::Bool(true));
        if let Some(ttl) = ttl {
            request_data.insert(
                "ttl".to_string(),
                serde_json::Value::Number((ttl as u64).into()),
            );
        }

        let request = self
            .client
            .post(&UrlUtils::data_endpoint(&self.base_url, &key))
            .header("Authorization", auth_header)
            .json(&request_data);

        let api_response: ApiResponse<DataResponseData> = self.execute_request(request).await?;

        Ok(HttpUtils::convert_data_response(api_response))
    }

    /// Compare and swap operation
    pub async fn compare_and_swap(
        &self,
        auth_manager: &AuthManager,
        key: String,
        expected_value: String,
        new_value: String,
        ttl: Option<u32>,
    ) -> Result<DbxResponse, DbxError> {
        let auth_header = auth_manager.get_auth_header().await?;

        let mut request_data = HashMap::new();
        request_data.insert(
            "expected_value".to_string(),
            JsonUtils::string_to_json_value(expected_value.clone()),
        );
        request_data.insert(
            "new_value".to_string(),
            JsonUtils::string_to_json_value(new_value.clone()),
        );
        if let Some(ttl) = ttl {
            request_data.insert(
                "ttl".to_string(),
                serde_json::Value::Number((ttl as u64).into()),
            );
        }

        let request = self
            .client
            .put(&format!(
                "{}/cas",
                UrlUtils::data_endpoint(&self.base_url, &key)
            ))
            .header("Authorization", auth_header)
            .json(&request_data);

        let api_response: ApiResponse<DataResponseData> = self.execute_request(request).await?;

        Ok(HttpUtils::convert_data_response(api_response))
    }
}
