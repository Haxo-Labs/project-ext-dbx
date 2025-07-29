use crate::models::{ApiKey, ApiKeyContext, ApiKeyUsageStats, CreateApiKeyRequest, UserRole};
use chrono::{Duration, Timelike, Utc};
use dbx_core::{DataOperation, DataValue, UniversalBackend};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

/// API Key management errors
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ApiKeyError {
    #[error("API key not found")]
    KeyNotFound,
    #[error("Invalid API key format")]
    InvalidKeyFormat,
    #[error("API key has expired")]
    KeyExpired,
    #[error("API key is inactive")]
    KeyInactive,
    #[error("Insufficient permissions")]
    InsufficientPermissions,
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    #[error("Key generation failed")]
    KeyGenerationFailed,
    #[error("Database error: {0}")]
    DatabaseError(String),
    #[error("Validation error: {0}")]
    ValidationError(String),
    #[error("API key name already exists")]
    KeyNameExists,
}

/// API Key service for generation, validation, and management
#[derive(Clone)]
pub struct ApiKeyService {
    backend: Arc<dyn UniversalBackend>,
}

impl ApiKeyService {
    /// Create a new API key service
    pub fn new(backend: Arc<dyn UniversalBackend>) -> Self {
        Self { backend }
    }

    /// Generate a secure API key
    pub fn generate_api_key() -> Result<(String, String), ApiKeyError> {
        // Generate a secure random key using cryptographically secure RNG
        let prefix = "dbx";
        let separator = "_";

        // Generate 32 bytes of secure random data
        let rng = SystemRandom::new();
        let mut random_bytes = [0u8; 32];
        rng.fill(&mut random_bytes)
            .map_err(|_| ApiKeyError::KeyGenerationFailed)?;

        // Encode as hex (64 characters)
        let random_part: String = random_bytes.iter().map(|b| format!("{:02x}", b)).collect();

        let full_key = format!("{}{}{}", prefix, separator, random_part);
        let key_prefix = format!("{}{}****", prefix, separator);

        if full_key.len() < 32 {
            return Err(ApiKeyError::KeyGenerationFailed);
        }

        Ok((full_key, key_prefix))
    }

    /// Hash an API key for secure storage using SHA-256
    pub fn hash_api_key(key: &str) -> Result<String, ApiKeyError> {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        let result = hasher.finalize();
        Ok(format!("{:x}", result))
    }

    /// Generate a cryptographically secure salt for key derivation
    pub fn generate_salt() -> Result<[u8; 32], ApiKeyError> {
        let rng = SystemRandom::new();
        let mut salt = [0u8; 32];
        rng.fill(&mut salt)
            .map_err(|_| ApiKeyError::KeyGenerationFailed)?;
        Ok(salt)
    }

    /// Create a key derivation hash
    pub fn derive_key_hash(key: &str, salt: &[u8]) -> Result<String, ApiKeyError> {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        hasher.update(salt);

        // Multiple rounds for key stretching
        let mut result = hasher.finalize();
        for _ in 0..10000 {
            let mut hasher = Sha256::new();
            hasher.update(&result);
            hasher.update(salt);
            result = hasher.finalize();
        }

        Ok(format!("{:x}", result))
    }

    /// Validate API key format
    pub fn validate_key_format(key: &str) -> bool {
        key.starts_with("dbx_") && key.len() >= 32
    }

    /// Extract key prefix for display
    pub fn extract_key_prefix(key: &str) -> String {
        if let Some(underscore_pos) = key.find('_') {
            if underscore_pos + 5 < key.len() {
                format!(
                    "{}{}****",
                    &key[..underscore_pos + 1],
                    &key[underscore_pos + 1..underscore_pos + 5]
                )
            } else {
                format!("{}****", &key[..underscore_pos + 1])
            }
        } else {
            "****".to_string()
        }
    }

    /// Create a new API key
    pub async fn create_api_key(
        &self,
        request: CreateApiKeyRequest,
        owner_id: &str,
        owner_username: &str,
    ) -> Result<(ApiKey, String), ApiKeyError> {
        // Validate request
        if request.name.trim().is_empty() {
            return Err(ApiKeyError::ValidationError(
                "Name cannot be empty".to_string(),
            ));
        }

        if request.name.len() > 100 {
            return Err(ApiKeyError::ValidationError(
                "Name too long (max 100 characters)".to_string(),
            ));
        }

        // Check if key name already exists for this user
        if self.key_name_exists(owner_id, &request.name).await? {
            return Err(ApiKeyError::KeyNameExists);
        }

        // Generate secure API key
        let (api_key, key_prefix) = Self::generate_api_key()?;
        let key_hash = Self::hash_api_key(&api_key)?;

        let now = Utc::now();
        let expires_at = request
            .expires_in_days
            .map(|days| now + Duration::days(days as i64));

        // Validate rate limiting configuration
        if let (Some(requests), Some(window)) = (
            request.rate_limit_requests,
            request.rate_limit_window_seconds,
        ) {
            if requests == 0 || window == 0 {
                return Err(ApiKeyError::ValidationError(
                    "Rate limit values must be greater than 0".to_string(),
                ));
            }
        }

        let api_key_obj = ApiKey {
            id: Uuid::new_v4().to_string(),
            name: request.name.trim().to_string(),
            description: request
                .description
                .map(|d| d.trim().to_string())
                .filter(|d| !d.is_empty()),
            key_prefix: key_prefix.clone(),
            key_hash,
            permission: request.permission,
            owner_id: owner_id.to_string(),
            owner_username: owner_username.to_string(),
            created_at: now,
            updated_at: now,
            expires_at,
            is_active: true,
            usage_stats: ApiKeyUsageStats::default(),
            rate_limit_requests: request.rate_limit_requests,
            rate_limit_window_seconds: request.rate_limit_window_seconds,
        };

        // Store in backend
        self.store_api_key(&api_key_obj).await?;

        Ok((api_key_obj, api_key))
    }

    /// Validate an API key and return context
    pub async fn validate_api_key(&self, key: &str) -> Result<ApiKeyContext, ApiKeyError> {
        // Validate format
        if !Self::validate_key_format(key) {
            return Err(ApiKeyError::InvalidKeyFormat);
        }

        // Hash the key to find it in storage
        let key_hash = Self::hash_api_key(key)?;

        // Retrieve from backend
        let api_key = self.get_api_key_by_hash(&key_hash).await?;

        // Check if key is active
        if !api_key.is_active {
            return Err(ApiKeyError::KeyInactive);
        }

        // Check expiration
        if let Some(expires_at) = api_key.expires_at {
            if Utc::now() > expires_at {
                return Err(ApiKeyError::KeyExpired);
            }
        }

        // Check rate limiting
        self.check_rate_limit(&api_key).await?;

        // Update usage statistics
        self.update_usage_stats(&api_key.id).await?;

        // Convert permission to user role
        let user_role = UserRole::from(api_key.permission.clone());

        Ok(ApiKeyContext { api_key, user_role })
    }

    /// Store API key in backend
    async fn store_api_key(&self, api_key: &ApiKey) -> Result<(), ApiKeyError> {
        use dbx_core::{DataOperation, DataValue};

        // Store by ID
        let key_id = format!("api_key:id:{}", api_key.id);
        let api_key_json = serde_json::to_string(api_key)
            .map_err(|e| ApiKeyError::DatabaseError(e.to_string()))?;

        self.backend
            .execute_data(DataOperation::Set {
                key: key_id,
                value: DataValue::String(api_key_json.clone()),
                ttl: None,
            })
            .await
            .map_err(|e| ApiKeyError::DatabaseError(e.to_string()))?;

        // Store by hash for quick lookup
        let key_hash = format!("api_key:hash:{}", api_key.key_hash);
        self.backend
            .execute_data(DataOperation::Set {
                key: key_hash,
                value: DataValue::String(api_key.id.clone()),
                ttl: None,
            })
            .await
            .map_err(|e| ApiKeyError::DatabaseError(e.to_string()))?;

        // Add to user's key set (using JSON array)
        let user_keys = format!("api_keys:user:{}", api_key.owner_id);
        self.add_to_set(&user_keys, &api_key.id).await?;

        // Add to name index for duplicate checking
        let name_key = format!("api_key:name:{}:{}", api_key.owner_id, api_key.name);
        self.backend
            .execute_data(DataOperation::Set {
                key: name_key,
                value: DataValue::String(api_key.id.clone()),
                ttl: None,
            })
            .await
            .map_err(|e| ApiKeyError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Add member to a set (using JSON array)
    async fn add_to_set(&self, key: &str, member: &str) -> Result<(), ApiKeyError> {
        use dbx_core::{DataOperation, DataValue};

        // Get current set members
        let mut members: Vec<String> = match self
            .backend
            .execute_data(DataOperation::Get {
                key: key.to_string(),
                fields: None,
            })
            .await
        {
            Ok(result) => {
                if result.success {
                    if let Some(DataValue::String(json)) = result.data {
                        serde_json::from_str(&json).unwrap_or_else(|_| Vec::new())
                    } else {
                        Vec::new()
                    }
                } else {
                    Vec::new()
                }
            }
            Err(e) => return Err(ApiKeyError::DatabaseError(e.to_string())),
        };

        // Add member if not already present
        if !members.contains(&member.to_string()) {
            members.push(member.to_string());
            let json = serde_json::to_string(&members)
                .map_err(|e| ApiKeyError::DatabaseError(e.to_string()))?;

            self.backend
                .execute_data(DataOperation::Set {
                    key: key.to_string(),
                    value: DataValue::String(json),
                    ttl: None,
                })
                .await
                .map_err(|e| ApiKeyError::DatabaseError(e.to_string()))?;
        }

        Ok(())
    }

    /// Get API key by hash
    async fn get_api_key_by_hash(&self, key_hash: &str) -> Result<ApiKey, ApiKeyError> {
        use dbx_core::{DataOperation, DataValue};

        // Get API key ID from hash
        let hash_key = format!("api_key:hash:{}", key_hash);
        let api_key_id = match self
            .backend
            .execute_data(DataOperation::Get {
                key: hash_key,
                fields: None,
            })
            .await
        {
            Ok(result) => {
                if result.success {
                    if let Some(DataValue::String(id)) = result.data {
                        id
                    } else {
                        return Err(ApiKeyError::KeyNotFound);
                    }
                } else {
                    return Err(ApiKeyError::KeyNotFound);
                }
            }
            Err(e) => return Err(ApiKeyError::DatabaseError(e.to_string())),
        };

        // Get API key by ID
        self.get_api_key_by_id(&api_key_id).await
    }

    /// Get API key by ID
    pub async fn get_api_key_by_id(&self, id: &str) -> Result<ApiKey, ApiKeyError> {
        use dbx_core::{DataOperation, DataValue};

        let key_id = format!("api_key:id:{}", id);
        let api_key_json = match self
            .backend
            .execute_data(DataOperation::Get {
                key: key_id,
                fields: None,
            })
            .await
        {
            Ok(result) => {
                if result.success {
                    if let Some(DataValue::String(json)) = result.data {
                        json
                    } else {
                        return Err(ApiKeyError::KeyNotFound);
                    }
                } else {
                    return Err(ApiKeyError::KeyNotFound);
                }
            }
            Err(e) => return Err(ApiKeyError::DatabaseError(e.to_string())),
        };

        let api_key: ApiKey = serde_json::from_str(&api_key_json)
            .map_err(|e| ApiKeyError::DatabaseError(e.to_string()))?;

        Ok(api_key)
    }

    /// Check if key name exists for user
    async fn key_name_exists(&self, owner_id: &str, name: &str) -> Result<bool, ApiKeyError> {
        let name_key = format!("api_key:name:{}:{}", owner_id, name);

        match self
            .backend
            .execute_data(DataOperation::Get {
                key: name_key,
                fields: None,
            })
            .await
        {
            Ok(result) => {
                if result.success {
                    Ok(result.data.is_some())
                } else {
                    Ok(false)
                }
            }
            Err(e) => Err(ApiKeyError::DatabaseError(e.to_string())),
        }
    }

    /// Get user's API keys with pagination and optional filtering
    pub async fn get_user_keys_paginated(
        &self,
        owner_id: &str,
        offset: usize,
        limit: usize,
        name_filter: Option<&str>,
    ) -> Result<Vec<ApiKey>, ApiKeyError> {
        // Get user's key IDs from set
        let user_keys = format!("api_keys:user:{}", owner_id);
        let key_ids = self.get_set_members(&user_keys).await?;

        let mut keys = Vec::new();
        for key_id in key_ids.iter().skip(offset).take(limit) {
            if let Ok(api_key) = self.get_api_key_by_id(key_id).await {
                if let Some(filter) = name_filter {
                    if api_key.name.contains(filter) {
                        keys.push(api_key);
                    }
                } else {
                    keys.push(api_key);
                }
            }
        }

        Ok(keys)
    }

    /// List API keys for a user with pagination
    pub async fn list_user_api_keys(
        &self,
        owner_id: &str,
        limit: u32,
        offset: u32,
        active_only: bool,
    ) -> Result<(Vec<ApiKey>, u32), ApiKeyError> {
        let keys = self
            .get_user_keys_paginated(owner_id, offset as usize, limit as usize, None)
            .await?;

        let filtered_keys: Vec<ApiKey> = if active_only {
            keys.into_iter().filter(|key| key.is_active).collect()
        } else {
            keys
        };

        let total = filtered_keys.len() as u32;
        Ok((filtered_keys, total))
    }

    /// Update an API key
    pub async fn update_api_key(
        &self,
        id: &str,
        owner_id: &str,
        name: Option<String>,
    ) -> Result<ApiKey, ApiKeyError> {
        let mut api_key = self.get_api_key_by_id(id).await?;

        // Verify ownership
        if api_key.owner_id != owner_id {
            return Err(ApiKeyError::KeyNotFound);
        }

        // Update name if provided
        if let Some(new_name) = name {
            if new_name.trim().is_empty() {
                return Err(ApiKeyError::ValidationError(
                    "Name cannot be empty".to_string(),
                ));
            }
            api_key.name = new_name.trim().to_string();
        }

        api_key.updated_at = Utc::now();

        // Store updated API key
        self.store_api_key(&api_key).await?;

        Ok(api_key)
    }

    /// Rotate an API key (generate new key, keep same metadata)
    pub async fn rotate_api_key(
        &self,
        id: &str,
        owner_id: &str,
    ) -> Result<(ApiKey, String), ApiKeyError> {
        let mut api_key = self.get_api_key_by_id(id).await?;

        // Verify ownership
        if api_key.owner_id != owner_id {
            return Err(ApiKeyError::KeyNotFound);
        }

        // Generate new key
        let (new_api_key_str, new_key_prefix) = Self::generate_api_key()?;
        let new_key_hash = Self::hash_api_key(&new_api_key_str)?;

        // Update API key with new hash and prefix
        api_key.key_hash = new_key_hash;
        api_key.key_prefix = new_key_prefix;
        api_key.updated_at = Utc::now();

        // Store updated API key
        self.store_api_key(&api_key).await?;

        Ok((api_key, new_api_key_str))
    }

    /// Get set members (using JSON array)
    async fn get_set_members(&self, key: &str) -> Result<Vec<String>, ApiKeyError> {
        match self
            .backend
            .execute_data(DataOperation::Get {
                key: key.to_string(),
                fields: None,
            })
            .await
        {
            Ok(result) => {
                if result.success {
                    if let Some(DataValue::String(json)) = result.data {
                        serde_json::from_str(&json)
                            .map_err(|e| ApiKeyError::DatabaseError(e.to_string()))
                    } else {
                        Ok(Vec::new())
                    }
                } else {
                    Ok(Vec::new())
                }
            }
            Err(e) => Err(ApiKeyError::DatabaseError(e.to_string())),
        }
    }

    /// Get API key usage stats by ID
    pub async fn get_key_usage_stats(&self, key_id: &str) -> Result<ApiKeyUsageStats, ApiKeyError> {
        let usage_key = format!("api_key:usage:{}", key_id);

        match self
            .backend
            .execute_data(DataOperation::Get {
                key: usage_key,
                fields: None,
            })
            .await
        {
            Ok(result) => {
                if result.success {
                    if let Some(DataValue::String(json)) = result.data {
                        serde_json::from_str(&json)
                            .map_err(|e| ApiKeyError::DatabaseError(e.to_string()))
                    } else {
                        Ok(ApiKeyUsageStats {
                            total_requests: 0,
                            last_used_at: None,
                            requests_today: 0,
                            requests_this_hour: 0,
                            last_reset_date: None,
                            last_reset_hour: None,
                        })
                    }
                } else {
                    Ok(ApiKeyUsageStats {
                        total_requests: 0,
                        last_used_at: None,
                        requests_today: 0,
                        requests_this_hour: 0,
                        last_reset_date: None,
                        last_reset_hour: None,
                    })
                }
            }
            Err(e) => Err(ApiKeyError::DatabaseError(e.to_string())),
        }
    }

    /// Update API key usage statistics
    pub async fn update_usage_stats(&self, key_id: &str) -> Result<(), ApiKeyError> {
        let usage_key = format!("api_key:usage:{}", key_id);
        let now = Utc::now();

        // Get current stats or create new ones
        let mut stats =
            self.get_key_usage_stats(key_id)
                .await
                .unwrap_or_else(|_| ApiKeyUsageStats {
                    total_requests: 0,
                    last_used_at: None,
                    requests_today: 0,
                    requests_this_hour: 0,
                    last_reset_date: None,
                    last_reset_hour: None,
                });

        // Update stats
        stats.total_requests += 1;
        stats.last_used_at = Some(now);

        // Request tracking with time-based resets
        let current_date = now.date_naive();
        let current_hour = now.hour();

        // Reset daily counter if date changed
        if stats
            .last_reset_date
            .map_or(true, |last_date| last_date != current_date)
        {
            stats.requests_today = 0;
            stats.last_reset_date = Some(current_date);
        }

        // Reset hourly counter if hour changed
        if stats
            .last_reset_hour
            .map_or(true, |last_hour| last_hour != current_hour)
        {
            stats.requests_this_hour = 0;
            stats.last_reset_hour = Some(current_hour);
        }

        stats.requests_today += 1;
        stats.requests_this_hour += 1;

        // Store updated stats
        let stats_json =
            serde_json::to_string(&stats).map_err(|e| ApiKeyError::DatabaseError(e.to_string()))?;

        self.backend
            .execute_data(DataOperation::Set {
                key: usage_key,
                value: DataValue::String(stats_json),
                ttl: None,
            })
            .await
            .map_err(|e| ApiKeyError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Delete API key and clean up related data
    pub async fn delete_api_key(&self, key_id: &str, owner_id: &str) -> Result<(), ApiKeyError> {
        // Get the API key to get its hash for cleanup
        let api_key = self.get_api_key_by_id(key_id).await?;

        // Delete main API key record
        let key_id_key = format!("api_key:id:{}", key_id);
        self.backend
            .execute_data(DataOperation::Delete {
                key: key_id_key,
                fields: None,
            })
            .await
            .map_err(|e| ApiKeyError::DatabaseError(e.to_string()))?;

        // Delete hash lookup
        let hash_key = format!("api_key:hash:{}", api_key.key_hash);
        self.backend
            .execute_data(DataOperation::Delete {
                key: hash_key,
                fields: None,
            })
            .await
            .map_err(|e| ApiKeyError::DatabaseError(e.to_string()))?;

        // Remove from user's key set
        let user_keys = format!("api_keys:user:{}", owner_id);
        self.remove_from_set(&user_keys, key_id).await?;

        // Delete name index
        let name_key = format!("api_key:name:{}:{}", owner_id, api_key.name);
        self.backend
            .execute_data(DataOperation::Delete {
                key: name_key,
                fields: None,
            })
            .await
            .map_err(|e| ApiKeyError::DatabaseError(e.to_string()))?;

        // Delete usage stats
        let usage_key = format!("api_key:usage:{}", key_id);
        self.backend
            .execute_data(DataOperation::Delete {
                key: usage_key,
                fields: None,
            })
            .await
            .map_err(|e| ApiKeyError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Remove member from a set (using JSON array)
    async fn remove_from_set(&self, key: &str, member: &str) -> Result<(), ApiKeyError> {
        // Get current set members
        let mut members: Vec<String> = match self
            .backend
            .execute_data(DataOperation::Get {
                key: key.to_string(),
                fields: None,
            })
            .await
        {
            Ok(result) => {
                if result.success {
                    if let Some(DataValue::String(json)) = result.data {
                        serde_json::from_str(&json).unwrap_or_else(|_| Vec::new())
                    } else {
                        Vec::new()
                    }
                } else {
                    Vec::new()
                }
            }
            Err(e) => return Err(ApiKeyError::DatabaseError(e.to_string())),
        };

        // Remove member if present
        if let Some(pos) = members.iter().position(|x| x == member) {
            members.remove(pos);
            let json = serde_json::to_string(&members)
                .map_err(|e| ApiKeyError::DatabaseError(e.to_string()))?;

            self.backend
                .execute_data(DataOperation::Set {
                    key: key.to_string(),
                    value: DataValue::String(json),
                    ttl: None,
                })
                .await
                .map_err(|e| ApiKeyError::DatabaseError(e.to_string()))?;
        }

        Ok(())
    }

    /// Check rate limits for API key
    pub async fn check_rate_limit(&self, api_key: &ApiKey) -> Result<bool, ApiKeyError> {
        // Get rate limit settings
        let (requests, window_seconds) = match (
            api_key.rate_limit_requests,
            api_key.rate_limit_window_seconds,
        ) {
            (Some(requests), Some(window)) => (requests, window),
            _ => {
                // No rate limits configured, allow request
                return Ok(true);
            }
        };

        let now = Utc::now().timestamp();
        let _window_start = now - window_seconds as i64;

        let rate_limit_key = format!("rate_limit:{}:{}", api_key.id, now / window_seconds as i64);

        // Get current request count in window
        let current_count = match self
            .backend
            .execute_data(DataOperation::Get {
                key: rate_limit_key.clone(),
                fields: None,
            })
            .await
        {
            Ok(result) => {
                if result.success {
                    if let Some(DataValue::String(count_str)) = result.data {
                        count_str.parse::<u32>().unwrap_or(0)
                    } else if let Some(DataValue::Int(count)) = result.data {
                        count as u32
                    } else {
                        0
                    }
                } else {
                    0
                }
            }
            Err(_) => 0,
        };

        if current_count >= requests {
            return Ok(false);
        }

        // Increment counter
        let new_count = current_count + 1;
        let _ = self
            .backend
            .execute_data(DataOperation::Set {
                key: rate_limit_key,
                value: DataValue::Int(new_count as i64),
                ttl: Some(window_seconds as u64),
            })
            .await;

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ApiKeyPermission, UserRole};

    #[test]
    fn test_generate_api_key() {
        let (key, prefix) = ApiKeyService::generate_api_key().unwrap();

        assert!(key.starts_with("dbx_"));
        assert!(key.len() >= 32);
        assert!(prefix.starts_with("dbx_"));
        assert!(prefix.ends_with("****"));
        assert!(ApiKeyService::validate_key_format(&key));
    }

    #[test]
    fn test_hash_api_key() {
        let key = "dbx_test_key_12345678901234567890123456789";
        let hash1 = ApiKeyService::hash_api_key(key).unwrap();
        let hash2 = ApiKeyService::hash_api_key(key).unwrap();

        assert_eq!(hash1, hash2); // Same key should produce same hash
        assert!(hash1.len() == 64); // SHA256 produces 64-char hex string
    }

    #[test]
    fn test_validate_key_format() {
        assert!(ApiKeyService::validate_key_format(
            "dbx_12345678901234567890123456789"
        ));
        assert!(!ApiKeyService::validate_key_format("invalid_key"));
        assert!(!ApiKeyService::validate_key_format("dbx_short"));
        assert!(!ApiKeyService::validate_key_format(
            "wrong_prefix_12345678901234567890123456789"
        ));
    }

    #[test]
    fn test_extract_key_prefix() {
        let key = "dbx_abcdef1234567890123456789";
        let prefix = ApiKeyService::extract_key_prefix(&key);
        assert_eq!(prefix, "dbx_abcd****");
    }

    #[test]
    fn test_api_key_permissions_conversion() {
        assert_eq!(
            UserRole::from(ApiKeyPermission::ReadOnly),
            UserRole::ReadOnly
        );
        assert_eq!(UserRole::from(ApiKeyPermission::ReadWrite), UserRole::User);
        assert_eq!(UserRole::from(ApiKeyPermission::Admin), UserRole::Admin);
    }

    #[test]
    fn test_api_key_error_display() {
        let error = ApiKeyError::KeyNotFound;
        assert_eq!(error.to_string(), "API key not found");

        let error = ApiKeyError::ValidationError("Test validation error".to_string());
        assert_eq!(error.to_string(), "Validation error: Test validation error");
    }

    #[test]
    fn test_create_api_key_request_validation() {
        let request = CreateApiKeyRequest {
            name: "Test API Key".to_string(),
            description: Some("Test description".to_string()),
            permission: ApiKeyPermission::ReadWrite,
            expires_in_days: Some(30),
            rate_limit_requests: Some(1000),
            rate_limit_window_seconds: Some(3600),
        };

        assert_eq!(request.name, "Test API Key");
        assert_eq!(request.permission, ApiKeyPermission::ReadWrite);
        assert_eq!(request.expires_in_days, Some(30));
        assert_eq!(request.rate_limit_requests, Some(1000));
        assert_eq!(request.rate_limit_window_seconds, Some(3600));
    }

    #[test]
    fn test_api_key_usage_stats_default() {
        let stats = ApiKeyUsageStats::default();

        assert_eq!(stats.total_requests, 0);
        assert!(stats.last_used_at.is_none());
        assert_eq!(stats.requests_today, 0);
        assert_eq!(stats.requests_this_hour, 0);
    }

    #[test]
    fn test_key_generation_multiple_keys() {
        let mut keys = Vec::new();
        for _ in 0..10 {
            let (key, _) = ApiKeyService::generate_api_key().unwrap();
            keys.push(key);
        }

        // All keys should be unique
        let mut sorted_keys = keys.clone();
        sorted_keys.sort();
        sorted_keys.dedup();
        assert_eq!(sorted_keys.len(), keys.len());

        // All keys should be valid format
        for key in &keys {
            assert!(ApiKeyService::validate_key_format(key));
        }
    }

    #[test]
    fn test_hash_consistency() {
        let key = "dbx_test_key_consistent_12345678901234567890";
        let hash1 = ApiKeyService::hash_api_key(key).unwrap();
        let hash2 = ApiKeyService::hash_api_key(key).unwrap();
        let hash3 = ApiKeyService::hash_api_key(key).unwrap();

        assert_eq!(hash1, hash2);
        assert_eq!(hash2, hash3);
    }

    #[test]
    fn test_hash_different_keys() {
        let key1 = "dbx_test_key1_12345678901234567890";
        let key2 = "dbx_test_key2_12345678901234567890";

        let hash1 = ApiKeyService::hash_api_key(key1).unwrap();
        let hash2 = ApiKeyService::hash_api_key(key2).unwrap();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_prefix_extraction_edge_cases() {
        // Normal case
        assert_eq!(
            ApiKeyService::extract_key_prefix("dbx_abcdefghijk"),
            "dbx_abcd****"
        );

        // Short key after underscore
        assert_eq!(ApiKeyService::extract_key_prefix("dbx_ab"), "dbx_****");

        // No underscore
        assert_eq!(ApiKeyService::extract_key_prefix("dbxabcdefghijk"), "****");

        // Multiple underscores
        assert_eq!(
            ApiKeyService::extract_key_prefix("dbx_test_abcdefghijk"),
            "dbx_test****"
        );
    }

    #[test]
    fn test_permission_to_string() {
        assert_eq!(ApiKeyPermission::ReadOnly.to_string(), "readonly");
        assert_eq!(ApiKeyPermission::ReadWrite.to_string(), "readwrite");
        assert_eq!(ApiKeyPermission::Admin.to_string(), "admin");
    }

    // Unit tests for API key operations

    #[tokio::test]
    async fn test_api_key_service_creation() {
        // Test API key request structure validation

        let request = CreateApiKeyRequest {
            name: "Test Key".to_string(),
            description: Some("Test description".to_string()),
            permission: ApiKeyPermission::ReadWrite,
            expires_in_days: Some(30),
            rate_limit_requests: None,
            rate_limit_window_seconds: None,
        };

        // Validation tests that don't require backend storage
        assert!(!request.name.is_empty());
        assert!(request.name.len() <= 100);
        assert_eq!(request.permission, ApiKeyPermission::ReadWrite);
    }

    #[tokio::test]
    async fn test_validation_logic_without_backend() {
        // Test validation logic that doesn't require backend connection

        // Test key format validation
        let valid_key = "dbx_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(ApiKeyService::validate_key_format(valid_key));

        let invalid_key = "invalid_key";
        assert!(!ApiKeyService::validate_key_format(invalid_key));

        // Test hash generation
        let hash = ApiKeyService::hash_api_key(valid_key).unwrap();
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
