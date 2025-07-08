use napi::bindgen_prelude::*;
use napi_derive::napi;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;

/// Configuration for DBX client
#[napi(object)]
pub struct DbxConfig {
    /// DBX API base URL (e.g., "http://localhost:3000")
    pub base_url: String,
    /// Authentication username
    pub username: Option<String>,
    /// Authentication password
    pub password: Option<String>,
    /// Request timeout in milliseconds (default: 5000)
    pub timeout_ms: Option<u32>,
}

/// Response structure for API calls
#[napi(object)]
pub struct DbxResponse {
    pub success: bool,
    pub data: Option<String>,
    pub error: Option<String>,
    pub operation_id: Option<String>,
    pub execution_time_ms: Option<u32>,
    pub backend: Option<String>,
}

/// DBX client for interacting with the Universal Database API
#[napi]
pub struct DbxClient {
    client: Client,
    base_url: String,
    auth_token: RwLock<Option<String>>,
}

#[derive(Serialize, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize, Deserialize)]
struct LoginResponse {
    success: bool,
    data: Option<AuthData>,
    error: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct AuthData {
    access_token: String,
    refresh_token: String,
    token_type: String,
    expires_in: i64,
}

#[derive(Serialize, Deserialize)]
struct SetDataRequest {
    value: serde_json::Value,
    ttl: Option<u64>,
}

#[derive(Serialize, Deserialize)]
struct UpdateDataRequest {
    fields: HashMap<String, serde_json::Value>,
    ttl: Option<u64>,
}

#[derive(Serialize, Deserialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct DataResponseData {
    operation_id: String,
    success: bool,
    data: Option<serde_json::Value>,
    execution_time_ms: Option<u64>,
    backend: Option<String>,
}

impl DbxClient {
    /// Helper function to convert API response to DbxResponse
    fn convert_data_response(api_response: ApiResponse<DataResponseData>) -> DbxResponse {
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
        }
    }
}

impl DbxClient {
    /// Create a new DBX client
    #[napi(constructor)]
    pub fn new(config: DbxConfig) -> Result<Self> {
        let timeout = std::time::Duration::from_millis(config.timeout_ms.unwrap_or(5000) as u64);
        let client = Client::builder().timeout(timeout).build().map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to create HTTP client: {}", e),
            )
        })?;

        Ok(Self {
            client,
            base_url: config.base_url,
            auth_token: RwLock::new(None),
        })
    }

    /// Authenticate with the DBX API
    #[napi]
    pub async fn authenticate(&self, username: String, password: String) -> Result<bool> {
        let login_request = LoginRequest { username, password };

        let response = self
            .client
            .post(&format!("{}/auth/login", self.base_url))
            .json(&login_request)
            .send()
            .await
            .map_err(|e| {
                Error::new(
                    Status::GenericFailure,
                    format!("Login request failed: {}", e),
                )
            })?;

        let login_response: LoginResponse = response.json().await.map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to parse login response: {}", e),
            )
        })?;

        if login_response.success {
            if let Some(auth_data) = login_response.data {
                let mut token = self.auth_token.write().await;
                *token = Some(auth_data.access_token);
                Ok(true)
            } else {
                Err(Error::new(
                    Status::GenericFailure,
                    "No auth data in successful login response".to_string(),
                ))
            }
        } else {
            let error_msg = login_response
                .error
                .unwrap_or("Authentication failed".to_string());
            Err(Error::new(Status::GenericFailure, error_msg))
        }
    }

    /// Get authorization header
    async fn get_auth_header(&self) -> Result<String> {
        let token = self.auth_token.read().await;
        match token.as_ref() {
            Some(t) => Ok(format!("Bearer {}", t)),
            None => Err(Error::new(
                Status::GenericFailure,
                "Not authenticated. Call authenticate() first.".to_string(),
            )),
        }
    }

    /// Set a value for a key
    #[napi]
    pub async fn set(&self, key: String, value: String, ttl: Option<u32>) -> Result<DbxResponse> {
        let auth_header = self.get_auth_header().await?;
        let json_value: serde_json::Value =
            serde_json::from_str(&value).unwrap_or_else(|_| serde_json::Value::String(value));
        let request = SetDataRequest {
            value: json_value,
            ttl: ttl.map(|t| t as u64),
        };

        let response = self
            .client
            .post(&format!("{}/api/v1/data/{}", self.base_url, key))
            .header("Authorization", auth_header)
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                Error::new(Status::GenericFailure, format!("Set request failed: {}", e))
            })?;

        let api_response: ApiResponse<DataResponseData> = response.json().await.map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to parse response: {}", e),
            )
        })?;

        Ok(Self::convert_data_response(api_response))
    }

    /// Get a value by key
    #[napi]
    pub async fn get(&self, key: String) -> Result<DbxResponse> {
        let auth_header = self.get_auth_header().await?;

        let response = self
            .client
            .get(&format!("{}/api/v1/data/{}", self.base_url, key))
            .header("Authorization", auth_header)
            .send()
            .await
            .map_err(|e| {
                Error::new(Status::GenericFailure, format!("Get request failed: {}", e))
            })?;

        let api_response: ApiResponse<DataResponseData> = response.json().await.map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to parse response: {}", e),
            )
        })?;

        Ok(Self::convert_data_response(api_response))
    }

    /// Update fields for a key (hash operations)
    #[napi]
    pub async fn update(
        &self,
        key: String,
        fields_json: String,
        ttl: Option<u32>,
    ) -> Result<DbxResponse> {
        let auth_header = self.get_auth_header().await?;
        let fields: HashMap<String, serde_json::Value> =
            serde_json::from_str(&fields_json).unwrap_or_else(|_| HashMap::new());
        let request = UpdateDataRequest {
            fields,
            ttl: ttl.map(|t| t as u64),
        };

        let response = self
            .client
            .put(&format!("{}/api/v1/data/{}", self.base_url, key))
            .header("Authorization", auth_header)
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                Error::new(
                    Status::GenericFailure,
                    format!("Update request failed: {}", e),
                )
            })?;

        let api_response: ApiResponse<DataResponseData> = response.json().await.map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to parse response: {}", e),
            )
        })?;

        Ok(Self::convert_data_response(api_response))
    }

    /// Delete a key
    #[napi]
    pub async fn delete(&self, key: String) -> Result<DbxResponse> {
        let auth_header = self.get_auth_header().await?;

        let response = self
            .client
            .delete(&format!("{}/api/v1/data/{}", self.base_url, key))
            .header("Authorization", auth_header)
            .send()
            .await
            .map_err(|e| {
                Error::new(
                    Status::GenericFailure,
                    format!("Delete request failed: {}", e),
                )
            })?;

        let api_response: ApiResponse<DataResponseData> = response.json().await.map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to parse response: {}", e),
            )
        })?;

        Ok(Self::convert_data_response(api_response))
    }

    /// Check if a key exists
    #[napi]
    pub async fn exists(&self, key: String) -> Result<DbxResponse> {
        let auth_header = self.get_auth_header().await?;

        let response = self
            .client
            .get(&format!("{}/api/v1/data/{}/exists", self.base_url, key))
            .header("Authorization", auth_header)
            .send()
            .await
            .map_err(|e| {
                Error::new(
                    Status::GenericFailure,
                    format!("Exists request failed: {}", e),
                )
            })?;

        let api_response: ApiResponse<DataResponseData> = response.json().await.map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to parse response: {}", e),
            )
        })?;

        Ok(Self::convert_data_response(api_response))
    }

    /// Health check
    #[napi]
    pub async fn health(&self) -> Result<DbxResponse> {
        let response = self
            .client
            .get(&format!("{}/health", self.base_url))
            .send()
            .await
            .map_err(|e| {
                Error::new(
                    Status::GenericFailure,
                    format!("Health check failed: {}", e),
                )
            })?;

        let api_response: ApiResponse<serde_json::Value> = response.json().await.map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to parse health response: {}", e),
            )
        })?;

        Ok(DbxResponse {
            success: api_response.success,
            data: api_response
                .data
                .map(|v| serde_json::to_string(&v).unwrap_or_default()),
            error: api_response.error,
            operation_id: None,
            execution_time_ms: None,
            backend: None,
        })
    }
}
