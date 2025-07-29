use crate::auth::AuthManager;
use crate::batch::BatchManager;
use crate::data::DataManager;
use crate::types::{DbxBatchOperation, DbxConfig, DbxQueryResponse, DbxResponse};
use crate::utils::{ConfigUtils, HttpUtils, UrlUtils};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use reqwest::Client;

/// DBX TypeScript Client
#[napi]
pub struct DbxClient {
    auth_manager: AuthManager,
    data_manager: DataManager,
    batch_manager: BatchManager,
    client: Client,
    base_url: String,
    config: DbxConfig,
}

#[napi]
impl DbxClient {
    /// Create a new DBX client
    #[napi(constructor)]
    pub fn new(config: DbxConfig) -> Result<Self> {
        ConfigUtils::validate_config(&config)?;
        let client = ConfigUtils::create_http_client(&config)?;

        let enable_logging = config.enable_logging.unwrap_or(false);
        let max_retries = config.max_retries.unwrap_or(3);
        let retry_delay_ms = config.retry_delay_ms.unwrap_or(1000);

        let auth_manager = AuthManager::new(
            client.clone(),
            config.base_url.clone(),
            config.api_key.clone(),
            max_retries,
            retry_delay_ms,
            enable_logging,
        );
        let data_manager = DataManager::new(
            client.clone(),
            config.base_url.clone(),
            max_retries,
            retry_delay_ms,
            enable_logging,
        );
        let batch_manager = BatchManager::new(
            client.clone(),
            config.base_url.clone(),
            max_retries,
            retry_delay_ms,
            enable_logging,
        );

        Ok(Self {
            auth_manager,
            data_manager,
            batch_manager,
            client,
            base_url: config.base_url.clone(),
            config,
        })
    }

    /// Authenticate with username and password
    #[napi]
    pub async fn authenticate(&self, username: String, password: String) -> Result<bool> {
        Ok(self.auth_manager.authenticate(username, password).await?)
    }

    /// Refresh authentication token
    #[napi]
    pub async fn refresh_auth_token(&self) -> Result<bool> {
        Ok(self.auth_manager.refresh_auth_token().await?)
    }

    /// Logout and clear tokens
    #[napi]
    pub async fn logout(&self) -> Result<bool> {
        Ok(self.auth_manager.logout().await?)
    }

    /// Set a value for a key with optional TTL
    #[napi]
    pub async fn set(&self, key: String, value: String, ttl: Option<u32>) -> Result<DbxResponse> {
        Ok(self
            .data_manager
            .set(&self.auth_manager, key, value, ttl)
            .await?)
    }

    /// Get a value by key
    #[napi]
    pub async fn get(&self, key: String) -> Result<DbxResponse> {
        Ok(self.data_manager.get(&self.auth_manager, key).await?)
    }

    /// Update fields for a key (hash operations)
    #[napi]
    pub async fn update(
        &self,
        key: String,
        fields_json: String,
        ttl: Option<u32>,
    ) -> Result<DbxResponse> {
        Ok(self
            .data_manager
            .update(&self.auth_manager, key, fields_json, ttl)
            .await?)
    }

    /// Delete a key
    #[napi]
    pub async fn delete(&self, key: String) -> Result<DbxResponse> {
        Ok(self.data_manager.delete(&self.auth_manager, key).await?)
    }

    /// Check if a key exists
    #[napi]
    pub async fn exists(&self, key: String) -> Result<DbxResponse> {
        Ok(self.data_manager.exists(&self.auth_manager, key).await?)
    }

    /// Execute batch operations
    #[napi]
    pub async fn batch(&self, operations: Vec<DbxBatchOperation>) -> Result<DbxResponse> {
        self.batch_manager.validate_batch_operations(&operations)?;
        Ok(self
            .batch_manager
            .execute_batch(&self.auth_manager, operations)
            .await?)
    }

    /// Execute multiple get operations
    #[napi]
    pub async fn batch_get(&self, keys: Vec<String>) -> Result<DbxResponse> {
        Ok(self
            .batch_manager
            .batch_get(&self.auth_manager, keys)
            .await?)
    }

    /// Execute multiple set operations
    #[napi]
    pub async fn batch_set(
        &self,
        items: Vec<(String, String, Option<u32>)>,
    ) -> Result<DbxResponse> {
        Ok(self
            .batch_manager
            .batch_set(&self.auth_manager, items)
            .await?)
    }

    /// Execute multiple delete operations
    #[napi]
    pub async fn batch_delete(&self, keys: Vec<String>) -> Result<DbxResponse> {
        Ok(self
            .batch_manager
            .batch_delete(&self.auth_manager, keys)
            .await?)
    }

    /// Search by key pattern
    #[napi]
    pub async fn query_pattern(
        &self,
        pattern: String,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<DbxQueryResponse> {
        let auth_header = self.auth_manager.get_auth_header().await?;
        let request_data = crate::types::PatternSearchRequest {
            pattern,
            limit: limit.map(|l| l as usize),
            offset: offset.map(|o| o as usize),
        };

        let request = self
            .client
            .post(&UrlUtils::query_pattern_endpoint(&self.base_url))
            .header("Authorization", auth_header)
            .json(&request_data);

        let api_response: crate::types::ApiResponse<crate::types::QueryResponseData> =
            HttpUtils::execute_with_retry(
                request,
                self.config.max_retries.unwrap_or(3),
                self.config.retry_delay_ms.unwrap_or(1000),
            )
            .await?;

        Ok(HttpUtils::convert_query_response(api_response))
    }

    /// Text search across data
    #[napi]
    pub async fn query_text(
        &self,
        query: String,
        fields: Option<Vec<String>>,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<DbxQueryResponse> {
        let auth_header = self.auth_manager.get_auth_header().await?;
        let request_data = crate::types::TextSearchRequest {
            query,
            fields,
            limit: limit.map(|l| l as usize),
            offset: offset.map(|o| o as usize),
        };

        let request = self
            .client
            .post(&UrlUtils::query_text_endpoint(&self.base_url))
            .header("Authorization", auth_header)
            .json(&request_data);

        let api_response: crate::types::ApiResponse<crate::types::QueryResponseData> =
            HttpUtils::execute_with_retry(
                request,
                self.config.max_retries.unwrap_or(3),
                self.config.retry_delay_ms.unwrap_or(1000),
            )
            .await?;

        Ok(HttpUtils::convert_query_response(api_response))
    }

    /// Health check (public endpoint)
    #[napi]
    pub async fn health(&self) -> Result<DbxResponse> {
        let request = self.client.get(&UrlUtils::health_endpoint(&self.base_url));

        let api_response: crate::types::ApiResponse<serde_json::Value> =
            HttpUtils::execute_with_retry(
                request,
                self.config.max_retries.unwrap_or(3),
                self.config.retry_delay_ms.unwrap_or(1000),
            )
            .await?;

        Ok(HttpUtils::convert_generic_response(api_response))
    }

    /// Get current authentication status
    #[napi]
    pub async fn is_authenticated(&self) -> bool {
        self.auth_manager.is_authenticated().await
    }

    /// Get current configuration
    #[napi]
    pub fn get_config(&self) -> DbxConfig {
        self.config.clone()
    }

    /// Validate current session
    #[napi]
    pub async fn validate_session(&self) -> Result<bool> {
        Ok(self.auth_manager.validate_session().await?)
    }

    /// Get TTL for a key
    #[napi]
    pub async fn get_ttl(&self, key: String) -> Result<DbxResponse> {
        Ok(self.data_manager.get_ttl(&self.auth_manager, key).await?)
    }

    /// Set TTL for a key
    #[napi]
    pub async fn set_ttl(&self, key: String, ttl_seconds: u32) -> Result<DbxResponse> {
        Ok(self
            .data_manager
            .set_ttl(&self.auth_manager, key, ttl_seconds)
            .await?)
    }

    /// Increment a numeric value
    #[napi]
    pub async fn increment(&self, key: String, amount: Option<i64>) -> Result<DbxResponse> {
        Ok(self
            .data_manager
            .increment(&self.auth_manager, key, amount)
            .await?)
    }

    /// Decrement a numeric value
    #[napi]
    pub async fn decrement(&self, key: String, amount: Option<i64>) -> Result<DbxResponse> {
        Ok(self
            .data_manager
            .decrement(&self.auth_manager, key, amount)
            .await?)
    }

    /// Append to a string value
    #[napi]
    pub async fn append(&self, key: String, value: String) -> Result<DbxResponse> {
        Ok(self
            .data_manager
            .append(&self.auth_manager, key, value)
            .await?)
    }

    /// Get length of a value
    #[napi]
    pub async fn length(&self, key: String) -> Result<DbxResponse> {
        Ok(self.data_manager.length(&self.auth_manager, key).await?)
    }

    /// Set value if key does not exist
    #[napi]
    pub async fn set_if_not_exists(
        &self,
        key: String,
        value: String,
        ttl: Option<u32>,
    ) -> Result<DbxResponse> {
        Ok(self
            .data_manager
            .set_if_not_exists(&self.auth_manager, key, value, ttl)
            .await?)
    }

    /// Compare and swap operation
    #[napi]
    pub async fn compare_and_swap(
        &self,
        key: String,
        expected_value: String,
        new_value: String,
        ttl: Option<u32>,
    ) -> Result<DbxResponse> {
        Ok(self
            .data_manager
            .compare_and_swap(&self.auth_manager, key, expected_value, new_value, ttl)
            .await?)
    }

    /// Auto-refresh token if needed
    #[napi]
    pub async fn auto_refresh_if_needed(&self) -> Result<()> {
        if self.config.auto_refresh_token.unwrap_or(true) {
            Ok(self.auth_manager.auto_refresh_if_needed().await?)
        } else {
            Ok(())
        }
    }
}
