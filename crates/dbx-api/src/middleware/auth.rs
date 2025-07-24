use crate::{
    auth::{permissions::PermissionType, ApiKeyError, ApiKeyService, RbacConfig, RbacService},
    config::JwtConfig,
    constants::errors::ErrorMessages,
    models::{
        ApiKeyContext, ApiResponse, AuthResponse, Claims, CreateUserRequest,
        PermissionCheckContext, RbacContext, TokenType, User, UserInfo, UserRole,
    },
};
use async_trait::async_trait;
use axum::{
    extract::{rejection::JsonRejection, Query, Request, State},
    http::{header, HeaderMap, StatusCode, Uri},
    middleware::Next,
    response::{IntoResponse, Json},
};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, Utc};
use dbx_adapter::redis::client::RedisPool;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

/// Handle Redis errors and convert them to HTTP responses
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

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("User not found")]
    UserNotFound,
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("Token expired")]
    TokenExpired,
    #[error("Invalid token")]
    InvalidToken,
    #[error("Database error: {0}")]
    DatabaseError(String),
    #[error("Internal error: {0}")]
    InternalError(String),
}

#[async_trait]
pub trait UserStoreOperations {
    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>, AuthError>;
    async fn get_user_by_id(&self, user_id: &str) -> Result<Option<User>, AuthError>;
    async fn create_user(&self, user: CreateUserRequest) -> Result<User, AuthError>;
    async fn verify_password(&self, username: &str, password: &str) -> Result<bool, AuthError>;
    async fn update_last_login(&self, user_id: &str) -> Result<(), AuthError>;
}

#[derive(Clone)]
pub struct UserStore {
    redis_pool: Arc<RedisPool>,
}

impl UserStore {
    pub fn new(redis_pool: Arc<RedisPool>) -> Self {
        Self { redis_pool }
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
        let conn = self
            .redis_pool
            .get_connection()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        let conn_arc = Arc::new(std::sync::Mutex::new(conn));

        let key = format!("user:username:{}", username);
        let user_json = dbx_adapter::redis::primitives::string::RedisString::new(conn_arc)
            .get(&key)
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        if let Some(json) = user_json {
            let user: User = serde_json::from_str(&json)
                .map_err(|e| AuthError::InternalError(format!("JSON parse error: {}", e)))?;
            Ok(Some(user))
        } else {
            Ok(None)
        }
    }

    async fn get_user_by_id(&self, user_id: &str) -> Result<Option<User>, AuthError> {
        let conn = self
            .redis_pool
            .get_connection()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        let conn_arc = Arc::new(std::sync::Mutex::new(conn));

        let key = format!("user:id:{}", user_id);
        let user_json = dbx_adapter::redis::primitives::string::RedisString::new(conn_arc)
            .get(&key)
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        if let Some(json) = user_json {
            let user: User = serde_json::from_str(&json)
                .map_err(|e| AuthError::InternalError(format!("JSON parse error: {}", e)))?;
            Ok(Some(user))
        } else {
            Ok(None)
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

        let conn = self
            .redis_pool
            .get_connection()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        let conn_arc = Arc::new(std::sync::Mutex::new(conn));

        let user_json = serde_json::to_string(&user)
            .map_err(|e| AuthError::InternalError(format!("JSON serialize error: {}", e)))?;

        // Store user by ID
        let id_key = format!("user:id:{}", user_id);
        dbx_adapter::redis::primitives::string::RedisString::new(conn_arc.clone())
            .set(&id_key, &user_json)
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        // Store user by username
        let username_key = format!("user:username:{}", request.username);
        dbx_adapter::redis::primitives::string::RedisString::new(conn_arc)
            .set(&username_key, &user_json)
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

            let conn = self
                .redis_pool
                .get_connection()
                .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
            let conn_arc = Arc::new(std::sync::Mutex::new(conn));

            let user_json = serde_json::to_string(&user)
                .map_err(|e| AuthError::InternalError(format!("JSON serialize error: {}", e)))?;

            // Update both keys
            let id_key = format!("user:id:{}", user_id);
            dbx_adapter::redis::primitives::string::RedisString::new(conn_arc.clone())
                .set(&id_key, &user_json)
                .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

            let username_key = format!("user:username:{}", user.username);
            dbx_adapter::redis::primitives::string::RedisString::new(conn_arc)
                .set(&username_key, &user_json)
                .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        }

        Ok(())
    }
}

// JWT Authentication Middleware and Services

#[derive(Clone)]
pub struct JwtService {
    config: JwtConfig,
    user_store: Arc<UserStore>,
}

impl JwtService {
    pub fn new(config: JwtConfig, user_store: Arc<UserStore>) -> Self {
        Self { config, user_store }
    }

    pub fn generate_token(&self, user: &User, token_type: TokenType) -> Result<String, AuthError> {
        let expiration = match token_type {
            TokenType::Access => self.config.access_token_expiration,
            TokenType::Refresh => self.config.refresh_token_expiration,
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

    pub fn validate_token(&self, token: &str) -> Result<Claims, AuthError> {
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

        let access_token = self.generate_token(&user, TokenType::Access)?;
        let refresh_token = self.generate_token(&user, TokenType::Refresh)?;

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
        let claims = self.validate_token(refresh_token)?;

        if claims.token_type != TokenType::Refresh {
            return Err(AuthError::InvalidToken);
        }

        let user = self
            .user_store
            .get_user_by_id(&claims.sub)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        let access_token = self.generate_token(&user, TokenType::Access)?;
        let new_refresh_token = self.generate_token(&user, TokenType::Refresh)?;

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
        let claims = self.validate_token(token)?;
        self.user_store
            .get_user_by_id(&claims.sub)
            .await?
            .ok_or(AuthError::UserNotFound)
    }
}

pub async fn jwt_auth_middleware(
    State(jwt_service): State<Arc<JwtService>>,
    mut request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok());

    let token = auth_header
        .and_then(|auth| auth.strip_prefix("Bearer "))
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::<()>::error(
                    "Missing or invalid token".to_string(),
                )),
            )
        })?;

    let user = jwt_service.get_user_by_token(token).await.map_err(|e| {
        let (status, message) = match e {
            AuthError::TokenExpired => (StatusCode::UNAUTHORIZED, "Token expired"),
            AuthError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token"),
            AuthError::UserNotFound => (StatusCode::UNAUTHORIZED, "User not found"),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "Authentication error"),
        };

        (status, Json(ApiResponse::<()>::error(message.to_string())))
    })?;

    // Store user in request extensions
    request.extensions_mut().insert(user);

    Ok(next.run(request).await)
}

// API Key Authentication Middleware

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

/// API key authentication middleware
pub async fn api_key_auth_middleware(
    State(api_key_service): State<Arc<ApiKeyService>>,
    mut request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    let api_key =
        extract_api_key_from_request(request.headers(), request.uri()).ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::<()>::error("Missing API key".to_string())),
            )
        })?;

    let api_key_context = api_key_service
        .validate_api_key(&api_key)
        .await
        .map_err(|e| {
            let (status, message) = match e {
                ApiKeyError::KeyNotFound => (StatusCode::UNAUTHORIZED, "Invalid API key"),
                ApiKeyError::InvalidKeyFormat => {
                    (StatusCode::BAD_REQUEST, "Invalid API key format")
                }
                ApiKeyError::KeyExpired => (StatusCode::UNAUTHORIZED, "API key has expired"),
                ApiKeyError::KeyInactive => (StatusCode::UNAUTHORIZED, "API key is inactive"),
                ApiKeyError::RateLimitExceeded => {
                    (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded")
                }
                _ => (StatusCode::INTERNAL_SERVER_ERROR, "Authentication error"),
            };

            (status, Json(ApiResponse::<()>::error(message.to_string())))
        })?;

    // Store API key context in request extensions
    request.extensions_mut().insert(api_key_context);

    Ok(next.run(request).await)
}

/// Flexible authentication middleware that accepts JWT tokens or API keys
pub async fn flexible_auth_middleware(
    State((jwt_service, api_key_service)): State<(Arc<JwtService>, Arc<ApiKeyService>)>,
    mut request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    // Try API key authentication first
    if let Some(api_key) = extract_api_key_from_request(request.headers(), request.uri()) {
        match api_key_service.validate_api_key(&api_key).await {
            Ok(api_key_context) => {
                request.extensions_mut().insert(api_key_context);
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
                request.extensions_mut().insert(user);
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

/// Role checking middleware for flexible authentication contexts
pub async fn require_admin_role(
    mut request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    // Check for JWT user
    if let Some(user) = request.extensions().get::<User>() {
        if user.role == UserRole::Admin {
            return Ok(next.run(request).await);
        }
    }

    // Check for API key context
    if let Some(api_key_context) = request.extensions().get::<ApiKeyContext>() {
        if api_key_context.user_role == UserRole::Admin {
            return Ok(next.run(request).await);
        }
    }

    Err((
        StatusCode::FORBIDDEN,
        Json(ApiResponse::<()>::error("Admin role required".to_string())),
    ))
}

/// User role checking middleware for flexible authentication contexts
pub async fn require_user_role(
    mut request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    // Check for JWT user
    if let Some(user) = request.extensions().get::<User>() {
        if matches!(user.role, UserRole::User | UserRole::Admin) {
            return Ok(next.run(request).await);
        }
    }

    // Check for API key context
    if let Some(api_key_context) = request.extensions().get::<ApiKeyContext>() {
        if matches!(api_key_context.user_role, UserRole::User | UserRole::Admin) {
            return Ok(next.run(request).await);
        }
    }

    Err((
        StatusCode::FORBIDDEN,
        Json(ApiResponse::<()>::error(
            "User role or higher required".to_string(),
        )),
    ))
}

/// ReadOnly role checking middleware for flexible authentication contexts
pub async fn require_readonly_role(
    mut request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    // Check for JWT user
    if let Some(user) = request.extensions().get::<User>() {
        if matches!(
            user.role,
            UserRole::ReadOnly | UserRole::User | UserRole::Admin
        ) {
            return Ok(next.run(request).await);
        }
    }

    // Check for API key context
    if let Some(api_key_context) = request.extensions().get::<ApiKeyContext>() {
        if matches!(
            api_key_context.user_role,
            UserRole::ReadOnly | UserRole::User | UserRole::Admin
        ) {
            return Ok(next.run(request).await);
        }
    }

    Err((
        StatusCode::FORBIDDEN,
        Json(ApiResponse::<()>::error(
            "Authentication required".to_string(),
        )),
    ))
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

use crate::auth::permissions::Permission;

/// Permission checking middleware using RBAC service
pub async fn permission_check_middleware(
    request: Request,
    next: Next,
    permission_type: PermissionType,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    // Get user from request extensions (set by auth middleware)
    let user = request.extensions().get::<User>().ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ApiResponse::<()>::error(
                "Authentication required".to_string(),
            )),
        )
    })?;

    // Simple role-based permission check
    let has_permission = match permission_type {
        PermissionType::StringGet
        | PermissionType::StringSet
        | PermissionType::HashGet
        | PermissionType::HashSet
        | PermissionType::SetMembers
        | PermissionType::SetAdd => {
            matches!(user.role, UserRole::User | UserRole::Admin)
                || (user.role == UserRole::ReadOnly
                    && matches!(
                        permission_type,
                        PermissionType::StringGet
                            | PermissionType::HashGet
                            | PermissionType::SetMembers
                    ))
        }
        PermissionType::AdminPing | PermissionType::AdminFlush => user.role == UserRole::Admin,
        PermissionType::RoleManage => user.role == UserRole::Admin,
        PermissionType::AuditView => user.role == UserRole::Admin,
        _ => false,
    };

    if !has_permission {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiResponse::<()>::error(
                "Insufficient permissions".to_string(),
            )),
        ));
    }

    Ok(next.run(request).await)
}

/// Middleware for string operations
pub async fn string_get_permission_middleware(
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    permission_check_middleware(request, next, PermissionType::StringGet).await
}

pub async fn string_set_permission_middleware(
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    permission_check_middleware(request, next, PermissionType::StringSet).await
}

/// Middleware for hash operations
pub async fn hash_get_permission_middleware(
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    permission_check_middleware(request, next, PermissionType::HashGet).await
}

pub async fn hash_set_permission_middleware(
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    permission_check_middleware(request, next, PermissionType::HashSet).await
}

/// Middleware for set operations
pub async fn set_members_permission_middleware(
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    permission_check_middleware(request, next, PermissionType::SetMembers).await
}

pub async fn set_add_permission_middleware(
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    permission_check_middleware(request, next, PermissionType::SetAdd).await
}

/// Middleware for admin operations
pub async fn admin_ping_permission_middleware(
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    permission_check_middleware(request, next, PermissionType::AdminPing).await
}

pub async fn admin_flush_permission_middleware(
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    permission_check_middleware(request, next, PermissionType::AdminFlush).await
}

/// Middleware for role management operations
pub async fn role_manage_permission_middleware(
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    permission_check_middleware(request, next, PermissionType::RoleManage).await
}

/// Middleware for audit log viewing
pub async fn audit_view_permission_middleware(
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    permission_check_middleware(request, next, PermissionType::AuditView).await
}

/// RBAC authentication middleware that creates RBAC context from JWT/API key
pub async fn rbac_auth_middleware(
    State((jwt_service, api_key_service, rbac_service)): State<(
        Arc<JwtService>,
        Arc<ApiKeyService>,
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
                let roles = rbac_service
                    .get_user_role_assignments(&api_key_context.api_key.owner_id)
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .map(|assignment| assignment.role_name)
                    .collect();

                let rbac_context = RbacContext {
                    user_id: api_key_context.api_key.owner_id.clone(),
                    username: api_key_context.api_key.owner_username.clone(),
                    roles,
                    rbac_service: rbac_service.clone(),
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
                let roles = rbac_service
                    .get_user_role_assignments(&user.id)
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .map(|assignment| assignment.role_name)
                    .collect();

                let rbac_context = RbacContext {
                    user_id: user.id.clone(),
                    username: user.username.clone(),
                    roles,
                    rbac_service: rbac_service.clone(),
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
    permission_type: PermissionType,
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
        .check_permission(
            &rbac_context.user_id,
            permission_type.clone(),
            PermissionCheckContext {
                user_id: Some(rbac_context.user_id.clone()),
                username: Some(rbac_context.username.clone()),
                role: rbac_context.roles.first().cloned(),
                resource: request.uri().path().to_string(),
                action: request.method().to_string(),
                permission_required: format!("{:?}", permission_type).to_lowercase(),
                ip_address: request
                    .headers()
                    .get("x-forwarded-for")
                    .or_else(|| request.headers().get("x-real-ip"))
                    .and_then(|h| h.to_str().ok())
                    .map(|ip| ip.split(',').next().unwrap_or(ip).trim().to_string()),
                user_agent: request
                    .headers()
                    .get("user-agent")
                    .and_then(|h| h.to_str().ok())
                    .map(|ua| ua.to_string()),
            },
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

// Additional middleware for data operation permission patterns
pub async fn data_read_permission_middleware(
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    permission_check_middleware(request, next, PermissionType::StringGet).await
}

pub async fn data_write_permission_middleware(
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    permission_check_middleware(request, next, PermissionType::StringSet).await
}
