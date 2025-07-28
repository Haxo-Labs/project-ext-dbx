use crate::{
    auth::{ApiKeyError, RbacService},
    constants::errors::ErrorMessages,
    models::{ApiResponse, Claims, CreateUserRequest, RbacContext, User, UserInfo, UserRole},
};
use async_trait::async_trait;
use axum::{
    extract::rejection::JsonRejection,
    extract::{Query, Request, State},
    http::{header, HeaderMap, StatusCode, Uri},
    middleware::Next,
    response::{IntoResponse, Json},
};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, Utc};
use dbx_core::{DataOperation, DataValue};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration as StdDuration, Instant};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::error;
use uuid::Uuid;

/// Authentication response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub user: UserInfo,
}

#[derive(Debug, Clone)]
struct AuthAttempt {
    timestamp: Instant,
    ip_address: String,
    username: Option<String>,
    success: bool,
}

#[derive(Debug, Clone)]
struct AccountLockout {
    locked_until: Instant,
    attempt_count: u32,
    lockout_duration: StdDuration,
}

impl AccountLockout {
    fn new(attempt_count: u32) -> Self {
        let lockout_duration = Self::calculate_lockout_duration(attempt_count);
        Self {
            locked_until: Instant::now() + lockout_duration,
            attempt_count,
            lockout_duration,
        }
    }

    fn is_locked(&self) -> bool {
        Instant::now() < self.locked_until
    }

    fn time_remaining(&self) -> StdDuration {
        self.locked_until.saturating_duration_since(Instant::now())
    }

    fn calculate_lockout_duration(attempt_count: u32) -> StdDuration {
        match attempt_count {
            1..=3 => StdDuration::from_secs(0),      // No lockout
            4..=5 => StdDuration::from_secs(60),     // 1 minute
            6..=7 => StdDuration::from_secs(300),    // 5 minutes
            8..=10 => StdDuration::from_secs(900),   // 15 minutes
            11..=15 => StdDuration::from_secs(3600), // 1 hour
            _ => StdDuration::from_secs(86400),      // 24 hours
        }
    }
}

#[derive(Clone)]
pub struct AuthRateLimiter {
    // Track attempts by username
    username_attempts: Arc<RwLock<HashMap<String, VecDeque<AuthAttempt>>>>,
    // Track attempts by IP address
    ip_attempts: Arc<RwLock<HashMap<String, VecDeque<AuthAttempt>>>>,
    // Account lockouts
    account_lockouts: Arc<RwLock<HashMap<String, AccountLockout>>>,
    // IP lockouts
    ip_lockouts: Arc<RwLock<HashMap<String, AccountLockout>>>,
    // Configuration
    max_attempts_per_username: u32,
    max_attempts_per_ip: u32,
    time_window_seconds: u64,
}

impl AuthRateLimiter {
    pub fn new() -> Self {
        Self {
            username_attempts: Arc::new(RwLock::new(HashMap::new())),
            ip_attempts: Arc::new(RwLock::new(HashMap::new())),
            account_lockouts: Arc::new(RwLock::new(HashMap::new())),
            ip_lockouts: Arc::new(RwLock::new(HashMap::new())),
            max_attempts_per_username: 5, // 5 attempts per username
            max_attempts_per_ip: 20,      // 20 attempts per IP
            time_window_seconds: 900,     // 15 minute window
        }
    }

    pub async fn check_rate_limit(
        &self,
        username: &str,
        ip_address: &str,
    ) -> Result<(), AuthError> {
        // Check account lockout first
        {
            let lockouts = self.account_lockouts.read().await;
            if let Some(lockout) = lockouts.get(username) {
                if lockout.is_locked() {
                    return Err(AuthError::AccountLocked(lockout.time_remaining()));
                }
            }
        }

        // Check IP lockout
        {
            let ip_lockouts = self.ip_lockouts.read().await;
            if let Some(lockout) = ip_lockouts.get(ip_address) {
                if lockout.is_locked() {
                    return Err(AuthError::RateLimitExceeded);
                }
            }
        }

        // Check username attempt rate
        {
            let mut username_attempts = self.username_attempts.write().await;
            let attempts = username_attempts
                .entry(username.to_string())
                .or_insert_with(VecDeque::new);

            // Clean old attempts
            let cutoff = Instant::now() - StdDuration::from_secs(self.time_window_seconds);
            while let Some(front) = attempts.front() {
                if front.timestamp < cutoff {
                    attempts.pop_front();
                } else {
                    break;
                }
            }

            if attempts.len() as u32 >= self.max_attempts_per_username {
                // Create account lockout
                let mut lockouts = self.account_lockouts.write().await;
                let attempt_count = attempts.len() as u32;
                lockouts.insert(username.to_string(), AccountLockout::new(attempt_count));
                return Err(AuthError::RateLimitExceeded);
            }
        }

        // Check IP attempt rate
        {
            let mut ip_attempts = self.ip_attempts.write().await;
            let attempts = ip_attempts
                .entry(ip_address.to_string())
                .or_insert_with(VecDeque::new);

            // Clean old attempts
            let cutoff = Instant::now() - StdDuration::from_secs(self.time_window_seconds);
            while let Some(front) = attempts.front() {
                if front.timestamp < cutoff {
                    attempts.pop_front();
                } else {
                    break;
                }
            }

            if attempts.len() as u32 >= self.max_attempts_per_ip {
                // Create IP lockout
                let mut ip_lockouts = self.ip_lockouts.write().await;
                let attempt_count = attempts.len() as u32;
                ip_lockouts.insert(ip_address.to_string(), AccountLockout::new(attempt_count));
                return Err(AuthError::RateLimitExceeded);
            }
        }

        Ok(())
    }

    pub async fn record_attempt(&self, username: &str, ip_address: &str, success: bool) {
        let attempt = AuthAttempt {
            timestamp: Instant::now(),
            ip_address: ip_address.to_string(),
            username: Some(username.to_string()),
            success,
        };

        // Record for username
        {
            let mut username_attempts = self.username_attempts.write().await;
            let attempts = username_attempts
                .entry(username.to_string())
                .or_insert_with(VecDeque::new);
            attempts.push_back(attempt.clone());
        }

        // Record for IP
        {
            let mut ip_attempts = self.ip_attempts.write().await;
            let attempts = ip_attempts
                .entry(ip_address.to_string())
                .or_insert_with(VecDeque::new);
            attempts.push_back(attempt);
        }

        // If successful, reset lockouts
        if success {
            self.account_lockouts.write().await.remove(username);
            // Don't reset IP lockout on success since one successful auth doesn't mean IP is safe
        }
    }

    pub async fn is_account_locked(&self, username: &str) -> Option<StdDuration> {
        let lockouts = self.account_lockouts.read().await;
        if let Some(lockout) = lockouts.get(username) {
            if lockout.is_locked() {
                Some(lockout.time_remaining())
            } else {
                None
            }
        } else {
            None
        }
    }

    pub async fn unlock_account(&self, username: &str) -> Result<(), AuthError> {
        self.account_lockouts.write().await.remove(username);
        Ok(())
    }

    pub fn start_cleanup_task(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let limiter = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(600)); // Clean every 10 minutes
            loop {
                interval.tick().await;
                limiter.cleanup_expired_data().await;
            }
        })
    }

    async fn cleanup_expired_data(&self) {
        let cutoff = Instant::now() - StdDuration::from_secs(self.time_window_seconds * 2);

        // Clean expired attempts
        {
            let mut username_attempts = self.username_attempts.write().await;
            for attempts in username_attempts.values_mut() {
                while let Some(front) = attempts.front() {
                    if front.timestamp < cutoff {
                        attempts.pop_front();
                    } else {
                        break;
                    }
                }
            }
            username_attempts.retain(|_, attempts| !attempts.is_empty());
        }

        {
            let mut ip_attempts = self.ip_attempts.write().await;
            for attempts in ip_attempts.values_mut() {
                while let Some(front) = attempts.front() {
                    if front.timestamp < cutoff {
                        attempts.pop_front();
                    } else {
                        break;
                    }
                }
            }
            ip_attempts.retain(|_, attempts| !attempts.is_empty());
        }

        // Clean expired lockouts
        {
            let mut lockouts = self.account_lockouts.write().await;
            lockouts.retain(|_, lockout| lockout.is_locked());
        }

        {
            let mut ip_lockouts = self.ip_lockouts.write().await;
            ip_lockouts.retain(|_, lockout| lockout.is_locked());
        }
    }
}

/// Authentication errors
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("User not found")]
    UserNotFound,
    #[error("Token expired")]
    TokenExpired,
    #[error("Invalid token")]
    InvalidToken,
    #[error("Database error: {0}")]
    DatabaseError(String),
    #[error("Internal error: {0}")]
    InternalError(String),
    #[error("Token revoked")]
    TokenRevoked,
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    #[error("Account locked for {0:?}")]
    AccountLocked(StdDuration),
}

/// User store operations trait
#[async_trait]
pub trait UserStoreOperations {
    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>, AuthError>;
    async fn get_user_by_id(&self, user_id: &str) -> Result<Option<User>, AuthError>;
    async fn create_user(&self, request: CreateUserRequest) -> Result<User, AuthError>;
    async fn verify_password(&self, username: &str, password: &str) -> Result<bool, AuthError>;
    async fn update_last_login(&self, user_id: &str) -> Result<(), AuthError>;
}

/// Handle database errors and convert them to HTTP responses
pub fn handle_redis_error(_error: impl std::fmt::Display) -> (StatusCode, Json<ApiResponse<()>>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ApiResponse::<()>::error(
            ErrorMessages::INTERNAL_SERVER_ERROR.to_string(),
        )),
    )
}

/// Custom error handler for JSON extraction errors
pub async fn handle_json_rejection(rejection: JsonRejection) -> impl IntoResponse {
    let (status, error_message) = match rejection {
        JsonRejection::JsonDataError(_) => (StatusCode::BAD_REQUEST, "Invalid JSON data"),
        JsonRejection::JsonSyntaxError(_) => (StatusCode::BAD_REQUEST, "Invalid JSON syntax"),
        JsonRejection::MissingJsonContentType(_) => (
            StatusCode::BAD_REQUEST,
            "Missing Content-Type: application/json header",
        ),
        JsonRejection::BytesRejection(_) => {
            (StatusCode::BAD_REQUEST, "Failed to read request body")
        }
        _ => (StatusCode::BAD_REQUEST, "Invalid request body"),
    };

    (
        status,
        Json(ApiResponse::<()>::error(error_message.to_string())),
    )
}

#[derive(Clone)]
pub struct UserStore {
    backend: Arc<dyn dbx_core::UniversalBackend>,
}

impl UserStore {
    pub fn new(backend: Arc<dyn dbx_core::UniversalBackend>) -> Self {
        Self { backend }
    }

    fn hash_password(password: &str) -> Result<String, AuthError> {
        hash(password, DEFAULT_COST).map_err(|e| AuthError::InternalError(e.to_string()))
    }

    fn verify_password_hash(password: &str, hash: &str) -> Result<bool, AuthError> {
        verify(password, hash).map_err(|e| AuthError::InternalError(e.to_string()))
    }
}

#[async_trait]
impl UserStoreOperations for UserStore {
    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>, AuthError> {
        use dbx_core::{DataOperation, DataValue};

        let key = format!("user:username:{}", username);

        match self
            .backend
            .execute_data(DataOperation::Get { key, fields: None })
            .await
        {
            Ok(result) => {
                if result.success {
                    if let Some(DataValue::String(json)) = result.data {
                        let user: User = serde_json::from_str(&json).map_err(|e| {
                            AuthError::InternalError(format!("JSON parse error: {}", e))
                        })?;
                        Ok(Some(user))
                    } else {
                        Ok(None)
                    }
                } else {
                    Ok(None)
                }
            }
            Err(e) => Err(AuthError::DatabaseError(e.to_string())),
        }
    }

    async fn get_user_by_id(&self, user_id: &str) -> Result<Option<User>, AuthError> {
        use dbx_core::{DataOperation, DataValue};

        let key = format!("user:id:{}", user_id);

        match self
            .backend
            .execute_data(DataOperation::Get { key, fields: None })
            .await
        {
            Ok(result) => {
                if result.success {
                    if let Some(DataValue::String(json)) = result.data {
                        let user: User = serde_json::from_str(&json).map_err(|e| {
                            AuthError::InternalError(format!("JSON parse error: {}", e))
                        })?;
                        Ok(Some(user))
                    } else {
                        Ok(None)
                    }
                } else {
                    Ok(None)
                }
            }
            Err(e) => Err(AuthError::DatabaseError(e.to_string())),
        }
    }

    async fn create_user(&self, request: CreateUserRequest) -> Result<User, AuthError> {
        // Check if user already exists
        if self
            .get_user_by_username(&request.username)
            .await?
            .is_some()
        {
            return Err(AuthError::UserAlreadyExists);
        }

        let user_id = Uuid::new_v4().to_string();
        let password_hash = Self::hash_password(&request.password)?;

        let user = User {
            id: user_id.clone(),
            username: request.username.clone(),
            password_hash,
            role: request.role,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            is_active: true,
        };

        let user_json = serde_json::to_string(&user)
            .map_err(|e| AuthError::InternalError(format!("JSON serialize error: {}", e)))?;

        // Store user by ID
        let id_key = format!("user:id:{}", user_id);
        self.backend
            .execute_data(DataOperation::Set {
                key: id_key,
                value: DataValue::String(user_json.clone()),
                ttl: None,
            })
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        // Store user by username
        let username_key = format!("user:username:{}", request.username);
        self.backend
            .execute_data(DataOperation::Set {
                key: username_key,
                value: DataValue::String(user_json),
                ttl: None,
            })
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(user)
    }

    async fn verify_password(&self, username: &str, password: &str) -> Result<bool, AuthError> {
        if let Some(user) = self.get_user_by_username(username).await? {
            if !user.is_active {
                return Ok(false);
            }
            Self::verify_password_hash(password, &user.password_hash)
        } else {
            Ok(false)
        }
    }

    async fn update_last_login(&self, user_id: &str) -> Result<(), AuthError> {
        if let Some(mut user) = self.get_user_by_id(user_id).await? {
            user.updated_at = Utc::now();

            let user_json = serde_json::to_string(&user)
                .map_err(|e| AuthError::InternalError(format!("JSON serialize error: {}", e)))?;

            // Update both keys
            let id_key = format!("user:id:{}", user_id);
            self.backend
                .execute_data(DataOperation::Set {
                    key: id_key,
                    value: DataValue::String(user_json.clone()),
                    ttl: None,
                })
                .await
                .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

            let username_key = format!("user:username:{}", user.username);
            self.backend
                .execute_data(DataOperation::Set {
                    key: username_key,
                    value: DataValue::String(user_json),
                    ttl: None,
                })
                .await
                .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
struct TokenCacheEntry {
    claims: Claims,
    user: User,
    cached_at: Instant,
}

impl TokenCacheEntry {
    fn new(claims: Claims, user: User) -> Self {
        Self {
            claims,
            user,
            cached_at: Instant::now(),
        }
    }

    fn is_expired(&self, cache_ttl_seconds: u64) -> bool {
        self.cached_at.elapsed().as_secs() > cache_ttl_seconds
    }
}

// JWT Authentication Middleware and Services

#[derive(Clone)]
pub struct JwtService {
    config: crate::config::JwtConfig,
    user_store: Arc<UserStore>,
    token_cache: Arc<RwLock<HashMap<String, TokenCacheEntry>>>,
    blacklist: Arc<RwLock<HashSet<String>>>,
    cache_ttl_seconds: u64,
}

impl JwtService {
    pub fn new(config: crate::config::JwtConfig, user_store: Arc<UserStore>) -> Self {
        Self {
            config,
            user_store,
            token_cache: Arc::new(RwLock::new(HashMap::new())),
            blacklist: Arc::new(RwLock::new(HashSet::new())),
            cache_ttl_seconds: 300, // 5 minutes default cache TTL
        }
    }

    pub fn with_cache_ttl(mut self, cache_ttl_seconds: u64) -> Self {
        self.cache_ttl_seconds = cache_ttl_seconds;
        self
    }

    pub async fn revoke_token(&self, token: &str) -> Result<(), AuthError> {
        // Add token to blacklist
        self.blacklist.write().await.insert(token.to_string());

        // Remove from cache if present
        self.token_cache.write().await.remove(token);

        Ok(())
    }

    pub async fn is_token_blacklisted(&self, token: &str) -> bool {
        self.blacklist.read().await.contains(token)
    }

    pub async fn clear_expired_cache_entries(&self) {
        let mut cache = self.token_cache.write().await;
        cache.retain(|_, entry| !entry.is_expired(self.cache_ttl_seconds));
    }

    pub fn start_cache_cleanup_task(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let service = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300)); // Clean every 5 minutes
            loop {
                interval.tick().await;
                service.clear_expired_cache_entries().await;

                // Also clean blacklist periodically to prevent indefinite growth
                let mut blacklist = service.blacklist.write().await;
                if blacklist.len() > 10000 {
                    // Keep only recent entries or implement proper TTL for blacklist
                    blacklist.clear();
                }
            }
        })
    }

    pub fn generate_token(
        &self,
        user: &User,
        token_type: crate::models::TokenType,
    ) -> Result<String, AuthError> {
        let expiration = match token_type {
            crate::models::TokenType::Access => self.config.access_token_expiration,
            crate::models::TokenType::Refresh => self.config.refresh_token_expiration,
        };

        let exp = (Utc::now() + Duration::seconds(expiration as i64)).timestamp();

        let claims = Claims {
            sub: user.id.clone(),
            username: user.username.clone(),
            role: user.role.clone(),
            permissions: vec![], // Permissions handled by RBAC system
            exp,
            iat: Utc::now().timestamp(),
            iss: self.config.issuer.clone(),
            token_type,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.config.secret.as_ref()),
        )
        .map_err(|e| AuthError::InternalError(format!("Token generation failed: {}", e)))
    }

    pub async fn validate_token(&self, token: &str) -> Result<Claims, AuthError> {
        // Check blacklist first
        if self.is_token_blacklisted(token).await {
            return Err(AuthError::TokenRevoked);
        }

        // Check cache
        {
            let cache = self.token_cache.read().await;
            if let Some(entry) = cache.get(token) {
                if !entry.is_expired(self.cache_ttl_seconds) {
                    return Ok(entry.claims.clone());
                }
            }
        }

        // Validate cryptographically
        let claims = self.validate_token_crypto(token)?;

        // Cache the result if validation succeeded
        if let Ok(user) = self.user_store.get_user_by_id(&claims.sub).await {
            if let Some(user) = user {
                let entry = TokenCacheEntry::new(claims.clone(), user);
                self.token_cache
                    .write()
                    .await
                    .insert(token.to_string(), entry);
            }
        }

        Ok(claims)
    }

    fn validate_token_crypto(&self, token: &str) -> Result<Claims, AuthError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[self.config.issuer.clone()]);

        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.config.secret.as_ref()),
            &validation,
        )
        .map_err(|e| {
            if e.to_string().contains("ExpiredSignature") {
                AuthError::TokenExpired
            } else {
                AuthError::InvalidToken
            }
        })?;

        Ok(token_data.claims)
    }

    pub async fn authenticate_user(
        &self,
        username: &str,
        password: &str,
    ) -> Result<AuthResponse, AuthError> {
        if !self.user_store.verify_password(username, password).await? {
            return Err(AuthError::InvalidCredentials);
        }

        let user = self
            .user_store
            .get_user_by_username(username)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        self.user_store.update_last_login(&user.id).await?;

        let access_token = self.generate_token(&user, crate::models::TokenType::Access)?;
        let refresh_token = self.generate_token(&user, crate::models::TokenType::Refresh)?;

        Ok(AuthResponse {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: self.config.access_token_expiration as i64,
            user: UserInfo {
                id: user.id,
                username: user.username,
                role: user.role,
            },
        })
    }

    pub async fn refresh_token(&self, refresh_token: &str) -> Result<AuthResponse, AuthError> {
        let claims = self.validate_token(refresh_token).await?;

        if claims.token_type != crate::models::TokenType::Refresh {
            return Err(AuthError::InvalidToken);
        }

        let user = self
            .user_store
            .get_user_by_id(&claims.sub)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        let access_token = self.generate_token(&user, crate::models::TokenType::Access)?;
        let new_refresh_token = self.generate_token(&user, crate::models::TokenType::Refresh)?;

        Ok(AuthResponse {
            access_token,
            refresh_token: new_refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: self.config.access_token_expiration as i64,
            user: UserInfo {
                id: user.id,
                username: user.username,
                role: user.role,
            },
        })
    }

    pub async fn get_user_by_token(&self, token: &str) -> Result<User, AuthError> {
        // Check blacklist first
        if self.is_token_blacklisted(token).await {
            return Err(AuthError::TokenRevoked);
        }

        // Check cache first
        {
            let cache = self.token_cache.read().await;
            if let Some(entry) = cache.get(token) {
                if !entry.is_expired(self.cache_ttl_seconds) {
                    return Ok(entry.user.clone());
                }
            }
        }

        // Validate token and get user
        let claims = self.validate_token_crypto(token)?;
        let user = self
            .user_store
            .get_user_by_id(&claims.sub)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        // Cache the result
        let entry = TokenCacheEntry::new(claims, user.clone());
        self.token_cache
            .write()
            .await
            .insert(token.to_string(), entry);

        Ok(user)
    }
}

fn extract_api_key_from_request(headers: &HeaderMap, uri: &Uri) -> Option<String> {
    // Check X-API-Key header
    if let Some(api_key) = headers.get("X-API-Key") {
        if let Ok(key_str) = api_key.to_str() {
            return Some(key_str.to_string());
        }
    }

    // Check Authorization header
    if let Some(auth_header) = headers.get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(key) = auth_str.strip_prefix("ApiKey ") {
                return Some(key.to_string());
            }
        }
    }

    // Check query parameter
    if let Some(query) = uri.query() {
        for param in query.split('&') {
            if let Some((key, value)) = param.split_once('=') {
                if key == "api_key" {
                    return Some(value.to_string());
                }
            }
        }
    }

    None
}

/// RBAC authentication middleware that creates RBAC context from JWT/API key
pub async fn rbac_auth_middleware(
    State((jwt_service, api_key_service, rbac_service)): State<(
        Arc<JwtService>,
        Arc<crate::auth::ApiKeyService>,
        Arc<RbacService>,
    )>,
    mut request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    // Try API key authentication first
    if let Some(api_key) = extract_api_key_from_request(request.headers(), request.uri()) {
        match api_key_service.validate_api_key(&api_key).await {
            Ok(api_key_context) => {
                // Get user roles via RBAC service
                let roles: Vec<String> = rbac_service
                    .get_user_role_assignments(&api_key_context.api_key.owner_id)
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .map(|assignment| assignment.role_name)
                    .collect();

                let rbac_context = RbacContext {
                    user_id: api_key_context.api_key.owner_id.clone(),
                    username: api_key_context.api_key.owner_username.clone(),
                    role: roles.first().cloned(),
                    roles,
                    rbac_service: rbac_service.clone(),
                    ip_address: crate::middleware::security::extract_trusted_client_ip(
                        request.headers(),
                        request.extensions().get::<std::net::SocketAddr>(),
                    )
                    .map(|ip| ip.to_string()),
                    user_agent: request
                        .headers()
                        .get("user-agent")
                        .and_then(|h| h.to_str().ok())
                        .map(|ua| ua.to_string()),
                };

                request.extensions_mut().insert(api_key_context);
                request.extensions_mut().insert(rbac_context);
                return Ok(next.run(request).await);
            }
            Err(ApiKeyError::RateLimitExceeded) => {
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(ApiResponse::<()>::error("Rate limit exceeded".to_string())),
                ));
            }
            Err(_) => {
                // Continue to JWT authentication
            }
        }
    }

    // Try JWT authentication
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok());

    if let Some(token) = auth_header.and_then(|auth| auth.strip_prefix("Bearer ")) {
        match jwt_service.get_user_by_token(token).await {
            Ok(user) => {
                // Get user roles via RBAC service
                let roles: Vec<String> = rbac_service
                    .get_user_role_assignments(&user.id)
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .map(|assignment| assignment.role_name)
                    .collect();

                let rbac_context = RbacContext {
                    user_id: user.id.clone(),
                    username: user.username.clone(),
                    role: roles.first().cloned(),
                    roles,
                    rbac_service: rbac_service.clone(),
                    ip_address: crate::middleware::security::extract_trusted_client_ip(
                        request.headers(),
                        request.extensions().get::<std::net::SocketAddr>(),
                    )
                    .map(|ip| ip.to_string()),
                    user_agent: request
                        .headers()
                        .get("user-agent")
                        .and_then(|h| h.to_str().ok())
                        .map(|ua| ua.to_string()),
                };

                request.extensions_mut().insert(user);
                request.extensions_mut().insert(rbac_context);
                return Ok(next.run(request).await);
            }
            Err(_) => {
                // Continue to unauthorized response
            }
        }
    }

    // No valid authentication found
    Err((
        StatusCode::UNAUTHORIZED,
        Json(ApiResponse::<()>::error(
            "Authentication required".to_string(),
        )),
    ))
}

/// Permission checking middleware that uses RBAC service
pub async fn rbac_permission_check_middleware(
    request: Request,
    next: Next,
    permission_type: crate::auth::permissions::PermissionType,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    // Get RBAC context from request extensions
    let rbac_context = request.extensions().get::<RbacContext>().ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ApiResponse::<()>::error(
                "Authentication required".to_string(),
            )),
        )
    })?;

    // Check permission using RBAC service
    let permission_check = rbac_context
        .rbac_service
        .check_user_permission(
            &rbac_context.user_id,
            permission_type.clone(),
            rbac_context.clone(),
        )
        .await;

    match permission_check {
        Ok(true) => Ok(next.run(request).await),
        Ok(false) => Err((
            StatusCode::FORBIDDEN,
            Json(ApiResponse::<()>::error(
                "Insufficient permissions".to_string(),
            )),
        )),
        Err(e) => {
            eprintln!("Permission check error: {:?}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<()>::error(
                    "Permission check failed".to_string(),
                )),
            ))
        }
    }
}

// Define RbacContext struct for middleware use
#[derive(Clone)]
pub struct RbacContextMiddleware {
    pub user_id: String,
    pub username: String,
    pub roles: Vec<String>,
    pub rbac_service: Arc<RbacService>,
}

/// Flexible data operation permission middleware that can handle different permission types
pub async fn data_read_permission_middleware(
    State(rbac_service): State<Arc<RbacService>>,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    rbac_permission_check_middleware(
        request,
        next,
        crate::auth::permissions::PermissionType::StringGet,
    )
    .await
}

pub async fn data_write_permission_middleware(
    State(rbac_service): State<Arc<RbacService>>,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    rbac_permission_check_middleware(
        request,
        next,
        crate::auth::permissions::PermissionType::StringSet,
    )
    .await
}

/// Extract query parameters for pagination
#[derive(Debug, Clone, Deserialize)]
pub struct PaginationQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

impl Default for PaginationQuery {
    fn default() -> Self {
        Self {
            page: Some(1),
            limit: Some(20),
        }
    }
}

impl PaginationQuery {
    pub fn validate(&self) -> Result<(), String> {
        if let Some(page) = self.page {
            if page == 0 {
                return Err("Page must be greater than 0".to_string());
            }
        }

        if let Some(limit) = self.limit {
            if limit == 0 || limit > 100 {
                return Err("Limit must be between 1 and 100".to_string());
            }
        }

        Ok(())
    }

    pub fn get_offset(&self) -> u32 {
        let page = self.page.unwrap_or(1);
        let limit = self.limit.unwrap_or(20);
        (page - 1) * limit
    }

    pub fn get_limit(&self) -> u32 {
        self.limit.unwrap_or(20)
    }
}

/// Pagination middleware that validates query parameters
pub async fn pagination_middleware(
    Query(query): Query<PaginationQuery>,
    mut request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    query
        .validate()
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ApiResponse::<()>::error(e))))?;

    request.extensions_mut().insert(query);
    Ok(next.run(request).await)
}

/// Permission checking middleware using RBAC service
pub async fn permission_check_middleware(
    State(rbac_service): State<Arc<RbacService>>,
    request: Request,
    next: Next,
    required_permission: crate::auth::permissions::PermissionType,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    // Get RBAC context from request extensions (set by RBAC auth middleware)
    let rbac_context = request
        .extensions()
        .get::<RbacContext>()
        .cloned()
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::<()>::error(
                    "Authentication required".to_string(),
                )),
            )
        })?;

    // Check permission using RBAC service
    match rbac_service
        .check_user_permission(
            &rbac_context.user_id,
            required_permission.clone(),
            rbac_context.clone(),
        )
        .await
    {
        Ok(has_permission) => {
            if has_permission {
                Ok(next.run(request).await)
            } else {
                Err((
                    StatusCode::FORBIDDEN,
                    Json(ApiResponse::<()>::error(format!(
                        "Insufficient permissions. Required: {:?}",
                        required_permission
                    ))),
                ))
            }
        }
        Err(e) => {
            error!(
                user_id = %rbac_context.user_id,
                permission = ?required_permission,
                error = %e,
                "Permission check failed"
            );
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<()>::error(
                    "Permission check failed".to_string(),
                )),
            ))
        }
    }
}

/// Middleware for string operations
pub async fn string_get_permission_middleware(
    State(rbac_service): State<Arc<RbacService>>,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    permission_check_middleware(
        State(rbac_service),
        request,
        next,
        crate::auth::permissions::PermissionType::StringGet,
    )
    .await
}

pub async fn string_set_permission_middleware(
    State(rbac_service): State<Arc<RbacService>>,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    permission_check_middleware(
        State(rbac_service),
        request,
        next,
        crate::auth::permissions::PermissionType::StringSet,
    )
    .await
}

/// Middleware for hash operations
pub async fn hash_get_permission_middleware(
    State(rbac_service): State<Arc<RbacService>>,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    permission_check_middleware(
        State(rbac_service),
        request,
        next,
        crate::auth::permissions::PermissionType::HashGet,
    )
    .await
}

pub async fn hash_set_permission_middleware(
    State(rbac_service): State<Arc<RbacService>>,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    permission_check_middleware(
        State(rbac_service),
        request,
        next,
        crate::auth::permissions::PermissionType::HashSet,
    )
    .await
}

/// Middleware for set operations
pub async fn set_members_permission_middleware(
    State(rbac_service): State<Arc<RbacService>>,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    permission_check_middleware(
        State(rbac_service),
        request,
        next,
        crate::auth::permissions::PermissionType::SetMembers,
    )
    .await
}

pub async fn set_add_permission_middleware(
    State(rbac_service): State<Arc<RbacService>>,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    permission_check_middleware(
        State(rbac_service),
        request,
        next,
        crate::auth::permissions::PermissionType::SetAdd,
    )
    .await
}

/// Middleware for admin operations
pub async fn admin_info_permission_middleware(
    State(rbac_service): State<Arc<RbacService>>,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    permission_check_middleware(
        State(rbac_service),
        request,
        next,
        crate::auth::permissions::PermissionType::AdminInfo,
    )
    .await
}

pub async fn admin_ping_permission_middleware(
    State(rbac_service): State<Arc<RbacService>>,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    permission_check_middleware(
        State(rbac_service),
        request,
        next,
        crate::auth::permissions::PermissionType::AdminPing,
    )
    .await
}

pub async fn admin_flush_permission_middleware(
    State(rbac_service): State<Arc<RbacService>>,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    permission_check_middleware(
        State(rbac_service),
        request,
        next,
        crate::auth::permissions::PermissionType::AdminFlush,
    )
    .await
}

/// Middleware for role management operations
pub async fn role_manage_permission_middleware(
    State(rbac_service): State<Arc<RbacService>>,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    permission_check_middleware(
        State(rbac_service),
        request,
        next,
        crate::auth::permissions::PermissionType::RoleManage,
    )
    .await
}

/// Middleware for audit log viewing
pub async fn audit_view_permission_middleware(
    State(rbac_service): State<Arc<RbacService>>,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    permission_check_middleware(
        State(rbac_service),
        request,
        next,
        crate::auth::permissions::PermissionType::AuditView,
    )
    .await
}
