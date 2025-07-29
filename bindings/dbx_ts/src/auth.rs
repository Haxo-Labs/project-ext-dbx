use crate::error::DbxError;
use crate::types::{ApiResponse, LoginRequest, LoginResponse, RefreshRequest};
use crate::utils::{HttpUtils, UrlUtils};
use reqwest::Client;
use serde::Deserialize;
use tokio::sync::RwLock;

/// Authentication manager for DBX client
pub struct AuthManager {
    client: Client,
    base_url: String,
    access_token: RwLock<Option<String>>,
    refresh_token: RwLock<Option<String>>,
    api_key: Option<String>,
    max_retries: u32,
    retry_delay_ms: u32,
    enable_logging: bool,
}

impl AuthManager {
    /// Create new authentication manager
    pub fn new(
        client: Client,
        base_url: String,
        api_key: Option<String>,
        max_retries: u32,
        retry_delay_ms: u32,
        enable_logging: bool,
    ) -> Self {
        Self {
            client,
            base_url,
            access_token: RwLock::new(None),
            refresh_token: RwLock::new(None),
            api_key,
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

    /// Authenticate with username and password
    pub async fn authenticate(&self, username: String, password: String) -> Result<bool, DbxError> {
        let login_request = LoginRequest { username, password };

        let request = self
            .client
            .post(&UrlUtils::auth_login_endpoint(&self.base_url))
            .json(&login_request);

        let login_response: LoginResponse = self.execute_request(request).await?;

        if login_response.success {
            if let Some(auth_data) = login_response.data {
                let mut access_token = self.access_token.write().await;
                let mut refresh_token = self.refresh_token.write().await;
                *access_token = Some(auth_data.access_token);
                *refresh_token = Some(auth_data.refresh_token);
                Ok(true)
            } else {
                Err(DbxError::authentication(
                    "No auth data in successful login response".to_string(),
                ))
            }
        } else {
            let error_msg = login_response
                .error
                .unwrap_or("Authentication failed".to_string());
            Err(DbxError::authentication(error_msg))
        }
    }

    /// Refresh authentication token
    pub async fn refresh_auth_token(&self) -> Result<bool, DbxError> {
        let refresh_token = {
            let token = self.refresh_token.read().await;
            match token.as_ref() {
                Some(t) => t.clone(),
                None => {
                    return Err(DbxError::authentication(
                        "No refresh token available".to_string(),
                    ))
                }
            }
        };

        let refresh_request = RefreshRequest { refresh_token };

        let request = self
            .client
            .post(&UrlUtils::auth_refresh_endpoint(&self.base_url))
            .json(&refresh_request);

        let login_response: LoginResponse = self.execute_request(request).await?;

        if login_response.success {
            if let Some(auth_data) = login_response.data {
                let mut access_token = self.access_token.write().await;
                let mut refresh_token = self.refresh_token.write().await;
                *access_token = Some(auth_data.access_token);
                *refresh_token = Some(auth_data.refresh_token);
                Ok(true)
            } else {
                Err(DbxError::authentication(
                    "No auth data in refresh response".to_string(),
                ))
            }
        } else {
            let error_msg = login_response
                .error
                .unwrap_or("Token refresh failed".to_string());
            Err(DbxError::authentication(error_msg))
        }
    }

    /// Logout and clear tokens
    pub async fn logout(&self) -> Result<bool, DbxError> {
        if let Ok(auth_header) = self.get_auth_header().await {
            let request = self
                .client
                .post(&UrlUtils::auth_logout_endpoint(&self.base_url))
                .header("Authorization", auth_header);

            let _: ApiResponse<String> = self.execute_request(request).await?;
        }

        let mut access_token = self.access_token.write().await;
        let mut refresh_token = self.refresh_token.write().await;
        *access_token = None;
        *refresh_token = None;

        Ok(true)
    }

    /// Get authorization header
    pub async fn get_auth_header(&self) -> Result<String, DbxError> {
        if let Some(api_key) = &self.api_key {
            return HttpUtils::build_auth_header(None, Some(api_key));
        }

        let token = self.access_token.read().await;
        HttpUtils::build_auth_header(token.as_deref(), None)
    }

    /// Check if currently authenticated
    pub async fn is_authenticated(&self) -> bool {
        if self.api_key.is_some() {
            return true;
        }

        let token = self.access_token.read().await;
        token.is_some()
    }

    /// Validate current session
    pub async fn validate_session(&self) -> Result<bool, DbxError> {
        if let Ok(auth_header) = self.get_auth_header().await {
            let request = self
                .client
                .get(&UrlUtils::auth_validate_endpoint(&self.base_url))
                .header("Authorization", auth_header);

            match self
                .execute_request::<ApiResponse<serde_json::Value>>(request)
                .await
            {
                Ok(response) => Ok(response.success),
                Err(_) => Ok(false),
            }
        } else {
            Ok(false)
        }
    }

    /// Get current access token (for internal use)
    pub async fn get_access_token(&self) -> Option<String> {
        let token = self.access_token.read().await;
        token.clone()
    }

    /// Get current refresh token (for internal use)
    pub async fn get_refresh_token(&self) -> Option<String> {
        let token = self.refresh_token.read().await;
        token.clone()
    }

    /// Set tokens manually (for testing or external token management)
    pub async fn set_tokens(&self, access_token: String, refresh_token: Option<String>) {
        let mut access = self.access_token.write().await;
        let mut refresh = self.refresh_token.write().await;
        *access = Some(access_token);
        if let Some(refresh_token) = refresh_token {
            *refresh = Some(refresh_token);
        }
    }

    /// Clear all tokens
    pub async fn clear_tokens(&self) {
        let mut access = self.access_token.write().await;
        let mut refresh = self.refresh_token.write().await;
        *access = None;
        *refresh = None;
    }

    /// Auto-refresh token if needed (checks if token is about to expire)
    pub async fn auto_refresh_if_needed(&self) -> Result<(), DbxError> {
        if self.api_key.is_some() {
            return Ok(());
        }

        if !self.validate_session().await? {
            if self.get_refresh_token().await.is_some() {
                self.refresh_auth_token().await?;
            } else {
                return Err(DbxError::authentication(
                    "Session expired and no refresh token available".to_string(),
                ));
            }
        }

        Ok(())
    }
}
