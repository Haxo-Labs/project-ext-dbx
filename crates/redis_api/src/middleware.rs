use crate::{
    config::JwtConfig,
    constants::errors::ErrorMessages,
    models::{
        ApiResponse, AuthResponse, Claims, CreateUserRequest, TokenType, User, UserInfo, UserRole,
    },
};
use async_trait::async_trait;
use axum::{
    extract::{rejection::JsonRejection, Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::Next,
    response::IntoResponse,
    response::Json,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, Utc};
use dbx_adapter::redis::client::RedisPool;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use redis;
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

// JWT Authentication Middleware and Services

/// JWT Authentication Service
#[derive(Clone)]
pub struct JwtService {
    config: JwtConfig,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl JwtService {
    /// Create a new JWT service
    pub fn new(config: JwtConfig) -> Self {
        let secret = config.secret.as_bytes();
        let encoding_key = EncodingKey::from_secret(secret);
        let decoding_key = DecodingKey::from_secret(secret);

        Self {
            config,
            encoding_key,
            decoding_key,
        }
    }

    /// Generate access and refresh tokens for a user
    pub fn generate_tokens(&self, user: &User) -> Result<AuthResponse, AuthError> {
        let now = Utc::now();
        let access_exp = now + Duration::seconds(self.config.access_token_expiration as i64);
        let refresh_exp = now + Duration::seconds(self.config.refresh_token_expiration as i64);

        // Access token claims
        let access_claims = Claims {
            sub: user.id.clone(),
            username: user.username.clone(),
            role: user.role.clone(),
            exp: access_exp.timestamp(),
            iat: now.timestamp(),
            iss: self.config.issuer.clone(),
            token_type: TokenType::Access,
        };

        // Refresh token claims
        let refresh_claims = Claims {
            sub: user.id.clone(),
            username: user.username.clone(),
            role: user.role.clone(),
            exp: refresh_exp.timestamp(),
            iat: now.timestamp(),
            iss: self.config.issuer.clone(),
            token_type: TokenType::Refresh,
        };

        let access_token = encode(&Header::default(), &access_claims, &self.encoding_key)
            .map_err(|_| AuthError::TokenGeneration)?;

        let refresh_token = encode(&Header::default(), &refresh_claims, &self.encoding_key)
            .map_err(|_| AuthError::TokenGeneration)?;

        Ok(AuthResponse {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: self.config.access_token_expiration as i64,
            user: UserInfo {
                id: user.id.clone(),
                username: user.username.clone(),
                role: user.role.clone(),
            },
        })
    }

    /// Validate a JWT token
    pub fn validate_token(&self, token: &str) -> Result<Claims, AuthError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[&self.config.issuer]);
        validation.validate_exp = true; // Enable expiration validation

        decode::<Claims>(token, &self.decoding_key, &validation)
            .map(|token_data| token_data.claims)
            .map_err(|e| {
                match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::InvalidToken,
                    _ => AuthError::InvalidToken,
                }
            })
    }

    /// Refresh an access token using a refresh token
    pub fn refresh_token(&self, refresh_token: &str) -> Result<AuthResponse, AuthError> {
        let claims = self.validate_token(refresh_token)?;

        // Verify this is a refresh token
        if claims.token_type != TokenType::Refresh {
            return Err(AuthError::InvalidTokenType);
        }

        // Create a mock user from claims for token generation
        let user = User {
            id: claims.sub.clone(),
            username: claims.username.clone(),
            password_hash: String::new(),
            role: claims.role,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            is_active: true,
        };

        std::thread::sleep(std::time::Duration::from_millis(10));

        self.generate_tokens(&user)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Invalid token")]
    InvalidToken,
    #[error("Token generation failed")]
    TokenGeneration,
    #[error("Invalid token type")]
    InvalidTokenType,
    #[error("Insufficient permissions")]
    InsufficientPermissions,
    #[error("User not found")]
    UserNotFound,
    #[error("User already exists")]
    UserExists,
    #[error("Password hashing failed")]
    PasswordHashingFailed,
    #[error("Database error: {0}")]
    DatabaseError(String),
    #[error("Validation error: {0}")]
    ValidationError(String),
    #[error("User already exists")]
    UserAlreadyExists,
}

impl From<bcrypt::BcryptError> for AuthError {
    fn from(_: bcrypt::BcryptError) -> Self {
        AuthError::PasswordHashingFailed
    }
}

fn extract_token_from_header(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|auth_header| {
            if auth_header.starts_with("Bearer ") {
                Some(auth_header[7..].to_string())
            } else {
                None
            }
        })
}

pub async fn jwt_auth_middleware(
    State(jwt_service): State<Arc<JwtService>>,
    mut request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    let token = extract_token_from_header(request.headers()).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ApiResponse::<()>::error(
                "Missing authorization token".to_string(),
            )),
        )
    })?;

    let claims = jwt_service.validate_token(&token).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ApiResponse::<()>::error(
                "Invalid or expired token".to_string(),
            )),
        )
    })?;

    if claims.token_type != TokenType::Access {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ApiResponse::<()>::error("Invalid token type".to_string())),
        ));
    }

    request.extensions_mut().insert(claims);

    Ok(next.run(request).await)
}

pub async fn require_admin_role(
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    let claims = request.extensions().get::<Claims>().ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ApiResponse::<()>::error(
                "Authentication required".to_string(),
            )),
        )
    })?;

    if claims.role != UserRole::Admin {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiResponse::<()>::error("Admin role required".to_string())),
        ));
    }

    Ok(next.run(request).await)
}

pub async fn require_user_role(
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    let claims = request.extensions().get::<Claims>().ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ApiResponse::<()>::error(
                "Authentication required".to_string(),
            )),
        )
    })?;

    if !matches!(claims.role, UserRole::Admin | UserRole::User) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiResponse::<()>::error("User role required".to_string())),
        ));
    }

    Ok(next.run(request).await)
}

pub async fn require_readonly_role(
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    let _claims = request.extensions().get::<Claims>().ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ApiResponse::<()>::error(
                "Authentication required".to_string(),
            )),
        )
    })?;

    Ok(next.run(request).await)
}

#[async_trait]
pub trait UserStoreOperations {
    async fn create_user(&self, user: &User) -> Result<(), AuthError>;
    async fn get_user(&self, username: &str) -> Result<Option<User>, AuthError>;
    async fn authenticate(&self, username: &str, password: &str) -> Result<User, AuthError>;
    async fn update_user(&self, user: &User) -> Result<(), AuthError>;
    async fn delete_user(&self, username: &str) -> Result<bool, AuthError>;
}

pub enum UserStore {
    Redis(RedisUserStore),
    #[cfg(test)]
    Mock(Box<dyn UserStoreOperations + Send + Sync>),
}

#[async_trait]
impl UserStoreOperations for UserStore {
    async fn create_user(&self, user: &User) -> Result<(), AuthError> {
        match self {
            UserStore::Redis(store) => store.create_user(user).await,
            #[cfg(test)]
            UserStore::Mock(store) => store.create_user(user).await,
        }
    }

    async fn get_user(&self, username: &str) -> Result<Option<User>, AuthError> {
        match self {
            UserStore::Redis(store) => store.get_user(username).await,
            #[cfg(test)]
            UserStore::Mock(store) => store.get_user(username).await,
        }
    }

    async fn authenticate(&self, username: &str, password: &str) -> Result<User, AuthError> {
        match self {
            UserStore::Redis(store) => store.authenticate(username, password).await,
            #[cfg(test)]
            UserStore::Mock(store) => store.authenticate(username, password).await,
        }
    }

    async fn update_user(&self, user: &User) -> Result<(), AuthError> {
        match self {
            UserStore::Redis(store) => store.update_user(user).await,
            #[cfg(test)]
            UserStore::Mock(store) => store.update_user(user).await,
        }
    }

    async fn delete_user(&self, username: &str) -> Result<bool, AuthError> {
        match self {
            UserStore::Redis(store) => store.delete_user(username).await,
            #[cfg(test)]
            UserStore::Mock(store) => store.delete_user(username).await,
        }
    }
}

impl UserStore {
    pub async fn new(redis_pool: Arc<RedisPool>) -> Result<Self, AuthError> {
        let store = RedisUserStore::new(redis_pool).await?;
        Ok(UserStore::Redis(store))
    }

    pub async fn new_with_admin(
        redis_pool: Arc<RedisPool>,
        admin_username: &str,
        admin_password: &str,
    ) -> Result<Self, AuthError> {
        let store = RedisUserStore::new(redis_pool).await?;
        store
            .create_default_admin(admin_username, admin_password)
            .await?;
        Ok(UserStore::Redis(store))
    }
}

pub struct RedisUserStore {
    redis_pool: Arc<RedisPool>,
}

#[async_trait]
impl UserStoreOperations for RedisUserStore {
    async fn create_user(&self, user: &User) -> Result<(), AuthError> {
        if self.get_user(&user.username).await?.is_some() {
            return Err(AuthError::UserExists);
        }

        let conn = self
            .redis_pool
            .get_connection()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        let conn_arc = Arc::new(std::sync::Mutex::new(conn));

        let user_key = format!("user:{}", user.username);
        let user_json =
            serde_json::to_string(user).map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        dbx_adapter::redis::primitives::string::RedisString::new(conn_arc)
            .set(&user_key, &user_json)
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn get_user(&self, username: &str) -> Result<Option<User>, AuthError> {
        let conn = self
            .redis_pool
            .get_connection()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        let conn_arc = Arc::new(std::sync::Mutex::new(conn));

        let user_key = format!("user:{}", username);
        let user_json = dbx_adapter::redis::primitives::string::RedisString::new(conn_arc)
            .get(&user_key)
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        match user_json {
            Some(json) => {
                let user: User = serde_json::from_str(&json)
                    .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
                Ok(Some(user))
            }
            None => Ok(None),
        }
    }

    async fn authenticate(&self, username: &str, password: &str) -> Result<User, AuthError> {
        let user = self
            .get_user(username)
            .await?
            .ok_or(AuthError::InvalidCredentials)?;

        if !user.is_active {
            return Err(AuthError::InvalidCredentials);
        }

        if verify(password, &user.password_hash).map_err(|_| AuthError::InvalidCredentials)? {
            Ok(user)
        } else {
            Err(AuthError::InvalidCredentials)
        }
    }

    async fn update_user(&self, user: &User) -> Result<(), AuthError> {
        let conn = self
            .redis_pool
            .get_connection()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        let conn_arc = Arc::new(std::sync::Mutex::new(conn));

        let user_key = format!("user:{}", user.username);
        let mut updated_user = user.clone();
        updated_user.updated_at = Utc::now();

        let user_json = serde_json::to_string(&updated_user)
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        dbx_adapter::redis::primitives::string::RedisString::new(conn_arc)
            .set(&user_key, &user_json)
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn delete_user(&self, username: &str) -> Result<bool, AuthError> {
        let conn = self
            .redis_pool
            .get_connection()
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        let conn_arc = Arc::new(std::sync::Mutex::new(conn));

        let user_key = format!("user:{}", username);

        // Use Redis DEL command directly to get the count of deleted keys
        let deleted_count: i32 = {
            let mut conn = conn_arc.lock().unwrap();
            redis::cmd("DEL")
                .arg(&user_key)
                .query(&mut *conn)
                .map_err(|e| AuthError::DatabaseError(e.to_string()))?
        };

        Ok(deleted_count > 0)
    }
}

impl RedisUserStore {
    pub async fn new(redis_pool: Arc<RedisPool>) -> Result<Self, AuthError> {
        Ok(Self { redis_pool })
    }

    async fn create_default_admin(&self, username: &str, password: &str) -> Result<(), AuthError> {
        if self.get_user(username).await?.is_none() {
            let admin_user = CreateUserRequest {
                username: username.to_string(),
                password: password.to_string(),
                role: UserRole::Admin,
            };
            self.create_user_from_request(admin_user).await?;
        }
        Ok(())
    }

    pub async fn create_user_from_request(
        &self,
        request: CreateUserRequest,
    ) -> Result<User, AuthError> {
        if self.get_user(&request.username).await?.is_some() {
            return Err(AuthError::UserExists);
        }

        let password_hash =
            hash(&request.password, DEFAULT_COST).map_err(|_| AuthError::PasswordHashingFailed)?;

        let user = User {
            id: Uuid::new_v4().to_string(),
            username: request.username.clone(),
            password_hash,
            role: request.role,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            is_active: true,
        };

        self.create_user(&user).await?;
        Ok(user)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::JwtConfig;
    use crate::models::{Claims, TokenType, User, UserRole};
    use chrono::Utc;
    use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn create_test_jwt_config() -> JwtConfig {
        JwtConfig {
            secret: "test_secret_key_with_32_chars_min".to_string(),
            issuer: "test_issuer".to_string(),
            access_token_expiration: 3600,
            refresh_token_expiration: 86400,
        }
    }

    fn create_test_user() -> User {
        User {
            id: "test_user_id".to_string(),
            username: "testuser".to_string(),
            password_hash: "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewRgWgHZfb2aQ4He".to_string(),
            role: UserRole::User,
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    // Mock UserStore for testing
    #[derive(Debug, Clone)]
    struct MockUserStore {
        users: Arc<RwLock<HashMap<String, User>>>,
    }

    impl MockUserStore {
        fn new() -> Self {
            Self {
                users: Arc::new(RwLock::new(HashMap::new())),
            }
        }

        async fn add_user(&self, user: User) {
            self.users.write().await.insert(user.username.clone(), user);
        }
    }

    #[async_trait]
    impl UserStoreOperations for MockUserStore {
        async fn create_user(&self, user: &User) -> Result<(), AuthError> {
            let mut users = self.users.write().await;
            if users.contains_key(&user.username) {
                return Err(AuthError::UserExists);
            }
            users.insert(user.username.clone(), user.clone());
            Ok(())
        }

        async fn get_user(&self, username: &str) -> Result<Option<User>, AuthError> {
            let users = self.users.read().await;
            Ok(users.get(username).cloned())
        }

        async fn authenticate(&self, username: &str, password: &str) -> Result<User, AuthError> {
            let users = self.users.read().await;
            let user = users.get(username).ok_or(AuthError::UserNotFound)?;

            if verify(password, &user.password_hash).map_err(|_| AuthError::InvalidCredentials)? {
                Ok(user.clone())
            } else {
                Err(AuthError::InvalidCredentials)
            }
        }

        async fn update_user(&self, user: &User) -> Result<(), AuthError> {
            let mut users = self.users.write().await;
            users.insert(user.username.clone(), user.clone());
            Ok(())
        }

        async fn delete_user(&self, username: &str) -> Result<bool, AuthError> {
            let mut users = self.users.write().await;
            Ok(users.remove(username).is_some())
        }
    }

    #[test]
    fn test_jwt_service_creation() {
        let config = create_test_jwt_config();
        let jwt_service = JwtService::new(config);

        assert!(jwt_service.config.secret.len() >= 32);
        assert_eq!(jwt_service.config.issuer, "test_issuer");
    }

    #[test]
    fn test_token_generation() {
        let config = create_test_jwt_config();
        let jwt_service = JwtService::new(config);
        let user = create_test_user();

        let auth_response = jwt_service.generate_tokens(&user).unwrap();

        assert!(!auth_response.access_token.is_empty());
        assert!(!auth_response.refresh_token.is_empty());
        assert_eq!(auth_response.token_type, "Bearer");
        assert_eq!(auth_response.expires_in, 3600);
        assert_eq!(auth_response.user.id, user.id);
        assert_eq!(auth_response.user.username, user.username);
        assert_eq!(auth_response.user.role, user.role);
    }

    #[test]
    fn test_token_validation_success() {
        let config = create_test_jwt_config();
        let jwt_service = JwtService::new(config);
        let user = create_test_user();

        let auth_response = jwt_service.generate_tokens(&user).unwrap();
        let claims = jwt_service.validate_token(&auth_response.access_token).unwrap();

        assert_eq!(claims.sub, user.id);
        assert_eq!(claims.username, user.username);
        assert_eq!(claims.role, user.role);
        assert_eq!(claims.token_type, TokenType::Access);
        assert_eq!(claims.iss, "test_issuer");
    }

    #[test]
    fn test_token_validation_invalid_token() {
        let config = create_test_jwt_config();
        let jwt_service = JwtService::new(config);

        let result = jwt_service.validate_token("invalid_token");
        assert!(matches!(result, Err(AuthError::InvalidToken)));
    }

    #[test]
    fn test_token_validation_wrong_secret() {
        let config = create_test_jwt_config();
        let jwt_service = JwtService::new(config);

        let mut wrong_config = create_test_jwt_config();
        wrong_config.secret = "wrong_secret_key_with_32_chars_min".to_string();
        let wrong_jwt_service = JwtService::new(wrong_config);

        let user = create_test_user();
        let auth_response = wrong_jwt_service.generate_tokens(&user).unwrap();

        let result = jwt_service.validate_token(&auth_response.access_token);
        assert!(matches!(result, Err(AuthError::InvalidToken)));
    }

    #[test]
    fn test_refresh_token_validation() {
        let config = create_test_jwt_config();
        let jwt_service = JwtService::new(config);
        let user = create_test_user();

        let auth_response = jwt_service.generate_tokens(&user).unwrap();
        let refresh_claims = jwt_service.validate_token(&auth_response.refresh_token).unwrap();

        assert_eq!(refresh_claims.token_type, TokenType::Refresh);
        assert_eq!(refresh_claims.sub, user.id);
    }

    #[test]
    fn test_refresh_token_success() {
        let config = create_test_jwt_config();
        let jwt_service = JwtService::new(config);
        let user = create_test_user();

        let auth_response = jwt_service.generate_tokens(&user).unwrap();
        let new_auth_response = jwt_service.refresh_token(&auth_response.refresh_token).unwrap();

        assert!(!new_auth_response.access_token.is_empty());
        assert!(!new_auth_response.refresh_token.is_empty());
        assert_eq!(new_auth_response.user.id, user.id);

        // Verify tokens are valid JWT tokens with correct claims
        let access_claims = jwt_service.validate_token(&new_auth_response.access_token).unwrap();
        let refresh_claims = jwt_service.validate_token(&new_auth_response.refresh_token).unwrap();
        
        assert_eq!(access_claims.token_type, TokenType::Access);
        assert_eq!(refresh_claims.token_type, TokenType::Refresh);
        assert_eq!(access_claims.username, user.username);
        assert_eq!(refresh_claims.username, user.username);
    }

    #[test]
    fn test_refresh_token_with_access_token_fails() {
        let config = create_test_jwt_config();
        let jwt_service = JwtService::new(config);
        let user = create_test_user();

        let auth_response = jwt_service.generate_tokens(&user).unwrap();
        let result = jwt_service.refresh_token(&auth_response.access_token);

        assert!(matches!(result, Err(AuthError::InvalidTokenType)));
    }

    #[test]
    fn test_extract_token_from_header() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer test_token".parse().unwrap());

        let token = extract_token_from_header(&headers);
        assert_eq!(token, Some("test_token".to_string()));
    }

    #[test]
    fn test_extract_token_from_header_missing() {
        let headers = HeaderMap::new();
        let token = extract_token_from_header(&headers);
        assert!(token.is_none());
    }

    #[test]
    fn test_extract_token_from_header_invalid_format() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Invalid token".parse().unwrap());

        let token = extract_token_from_header(&headers);
        assert!(token.is_none());
    }

    #[test]
    fn test_extract_token_from_header_only_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer".parse().unwrap());

        let token = extract_token_from_header(&headers);
        assert!(token.is_none());
    }

    #[test]
    fn test_auth_error_display() {
        assert_eq!(AuthError::InvalidCredentials.to_string(), "Invalid credentials");
        assert_eq!(AuthError::InvalidToken.to_string(), "Invalid token");
        assert_eq!(AuthError::TokenGeneration.to_string(), "Token generation failed");
        assert_eq!(AuthError::InvalidTokenType.to_string(), "Invalid token type");
        assert_eq!(AuthError::InsufficientPermissions.to_string(), "Insufficient permissions");
        assert_eq!(AuthError::UserNotFound.to_string(), "User not found");
        assert_eq!(AuthError::UserExists.to_string(), "User already exists");
        assert_eq!(AuthError::PasswordHashingFailed.to_string(), "Password hashing failed");
        assert_eq!(AuthError::DatabaseError("test".to_string()).to_string(), "Database error: test");
    }

    #[test]
    fn test_auth_error_debug() {
        let error = AuthError::InvalidCredentials;
        let debug_str = format!("{:?}", error);
        assert_eq!(debug_str, "InvalidCredentials");
    }

    #[tokio::test]
    async fn test_mock_user_store_create_user() {
        let store = MockUserStore::new();
        let user = create_test_user();

        let result = store.create_user(&user).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_mock_user_store_create_duplicate_user() {
        let store = MockUserStore::new();
        let user = create_test_user();

        store.create_user(&user).await.unwrap();
        let result = store.create_user(&user).await;
        assert!(matches!(result, Err(AuthError::UserExists)));
    }

    #[tokio::test]
    async fn test_mock_user_store_get_user() {
        let store = MockUserStore::new();
        let user = create_test_user();

        store.create_user(&user).await.unwrap();
        let retrieved_user = store.get_user(&user.username).await.unwrap();
        assert!(retrieved_user.is_some());
        assert_eq!(retrieved_user.unwrap().username, user.username);
    }

    #[tokio::test]
    async fn test_mock_user_store_get_nonexistent_user() {
        let store = MockUserStore::new();
        let result = store.get_user("nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_mock_user_store_authenticate_success() {
        let store = MockUserStore::new();
        let password = "testpass123";
        let hash = hash(password, DEFAULT_COST).unwrap();
        let mut user = create_test_user();
        user.password_hash = hash;

        store.create_user(&user).await.unwrap();
        let result = store.authenticate(&user.username, password).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_mock_user_store_authenticate_wrong_password() {
        let store = MockUserStore::new();
        let password = "testpass123";
        let hash = hash(password, DEFAULT_COST).unwrap();
        let mut user = create_test_user();
        user.password_hash = hash;

        store.create_user(&user).await.unwrap();
        let result = store.authenticate(&user.username, "wrongpass").await;
        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn test_mock_user_store_authenticate_nonexistent_user() {
        let store = MockUserStore::new();
        let result = store.authenticate("nonexistent", "password").await;
        assert!(matches!(result, Err(AuthError::UserNotFound)));
    }

    #[tokio::test]
    async fn test_mock_user_store_update_user() {
        let store = MockUserStore::new();
        let mut user = create_test_user();
        store.create_user(&user).await.unwrap();

        user.role = UserRole::Admin;
        let result = store.update_user(&user).await;
        assert!(result.is_ok());

        let updated_user = store.get_user(&user.username).await.unwrap().unwrap();
        assert_eq!(updated_user.role, UserRole::Admin);
    }

    #[tokio::test]
    async fn test_mock_user_store_delete_user() {
        let store = MockUserStore::new();
        let user = create_test_user();
        store.create_user(&user).await.unwrap();

        let result = store.delete_user(&user.username).await;
        assert!(result.is_ok());
        assert!(result.unwrap());

        let deleted_user = store.get_user(&user.username).await.unwrap();
        assert!(deleted_user.is_none());
    }

    #[tokio::test]
    async fn test_mock_user_store_delete_nonexistent_user() {
        let store = MockUserStore::new();
        let result = store.delete_user("nonexistent").await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_token_claims_validation() {
        let config = create_test_jwt_config();
        let jwt_service = JwtService::new(config);
        let user = create_test_user();

        let auth_response = jwt_service.generate_tokens(&user).unwrap();

        // Manually decode and verify claims structure
        let decoding_key = DecodingKey::from_secret("test_secret_key_with_32_chars_min".as_bytes());
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&["test_issuer"]);

        let token_data = decode::<Claims>(&auth_response.access_token, &decoding_key, &validation).unwrap();
        let claims = token_data.claims;

        assert!(claims.exp > Utc::now().timestamp());
        assert!(claims.iat <= Utc::now().timestamp());
        assert_eq!(claims.iss, "test_issuer");
    }

    #[test]
    fn test_expired_token_validation() {
        let config = create_test_jwt_config();
        let jwt_service = JwtService::new(config);
        
        // Create a simple expired token by using jsonwebtoken directly
        let expired_claims = Claims {
            sub: "test_user_id".to_string(),
            username: "testuser".to_string(),
            role: UserRole::User,
            exp: Utc::now().timestamp() - 3600, // Expired 1 hour ago
            iat: Utc::now().timestamp() - 7200, // Issued 2 hours ago
            iss: "test_issuer".to_string(),
            token_type: TokenType::Access,
        };

        let expired_token = encode(&Header::default(), &expired_claims, &jwt_service.encoding_key).unwrap();

        // The token should be expired
        let result = jwt_service.validate_token(&expired_token);
        assert!(matches!(result, Err(AuthError::InvalidToken)));
    }

    #[test]
    fn test_handle_redis_error() {
        let error = "Redis connection failed";
        let (status, response) = handle_redis_error(error);

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!response.success);
        assert_eq!(response.error, Some(ErrorMessages::INTERNAL_SERVER_ERROR.to_string()));
    }

    #[test]
    fn test_user_role_permissions() {
        let admin_user = User {
            id: "admin".to_string(),
            username: "admin".to_string(),
            password_hash: "hash".to_string(),
            role: UserRole::Admin,
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let regular_user = User {
            id: "user".to_string(),
            username: "user".to_string(),
            password_hash: "hash".to_string(),
            role: UserRole::User,
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let readonly_user = User {
            id: "readonly".to_string(),
            username: "readonly".to_string(),
            password_hash: "hash".to_string(),
            role: UserRole::ReadOnly,
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert_eq!(admin_user.role, UserRole::Admin);
        assert_eq!(regular_user.role, UserRole::User);
        assert_eq!(readonly_user.role, UserRole::ReadOnly);
    }

    #[test]
    fn test_token_type_validation() {
        let access_token_type = TokenType::Access;
        let refresh_token_type = TokenType::Refresh;

        assert_ne!(access_token_type, refresh_token_type);

        let config = create_test_jwt_config();
        let jwt_service = JwtService::new(config);
        let user = create_test_user();

        let auth_response = jwt_service.generate_tokens(&user).unwrap();
        let access_claims = jwt_service.validate_token(&auth_response.access_token).unwrap();
        let refresh_claims = jwt_service.validate_token(&auth_response.refresh_token).unwrap();

        assert_eq!(access_claims.token_type, TokenType::Access);
        assert_eq!(refresh_claims.token_type, TokenType::Refresh);
    }



    #[test]
    fn test_validate_role_functions() {
        // Test role validation logic (Admin < User < ReadOnly)
        assert!(UserRole::Admin >= UserRole::Admin);
        assert!(UserRole::Admin <= UserRole::User);
        assert!(UserRole::Admin <= UserRole::ReadOnly);
        assert!(UserRole::User <= UserRole::ReadOnly);
        assert!(!(UserRole::ReadOnly <= UserRole::User));
        assert!(!(UserRole::ReadOnly <= UserRole::Admin));
    }

    #[test]
    fn test_jwt_service_config() {
        let config = create_test_jwt_config();
        let jwt_service = JwtService::new(config);

        // Test the service was created with proper config
        assert_eq!(jwt_service.config.issuer, "test_issuer");
        assert_eq!(jwt_service.config.access_token_expiration, 3600);
        assert_eq!(jwt_service.config.refresh_token_expiration, 86400);
    }

    #[test]
    fn test_user_role_comparison() {
        // Test role hierarchy (Admin < User < ReadOnly based on enum position)
        assert!(UserRole::Admin < UserRole::User);
        assert!(UserRole::User < UserRole::ReadOnly);
        assert!(UserRole::Admin < UserRole::ReadOnly);
        
        // Test equality
        assert_eq!(UserRole::Admin, UserRole::Admin);
        assert_eq!(UserRole::User, UserRole::User);
        assert_eq!(UserRole::ReadOnly, UserRole::ReadOnly);
    }

    #[tokio::test]
    async fn test_user_store_mock_operations() {
        let mock_store = MockUserStore::new();
        let user_store = UserStore::Mock(Box::new(mock_store));

        let user = create_test_user();
        
        // Test create user
        let result = user_store.create_user(&user).await;
        assert!(result.is_ok());

        // Test get user
        let retrieved = user_store.get_user(&user.username).await;
        assert!(retrieved.is_ok());

        // Test update user  
        let mut updated_user = user.clone();
        updated_user.role = UserRole::Admin;
        let result = user_store.update_user(&updated_user).await;
        assert!(result.is_ok());

        // Test delete user
        let result = user_store.delete_user(&user.username).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_token_expiration_calculation() {
        let config = create_test_jwt_config();
        let jwt_service = JwtService::new(config);
        let user = create_test_user();

        let auth_response = jwt_service.generate_tokens(&user).unwrap();
        
        // Verify tokens are different (access vs refresh)
        assert_ne!(auth_response.access_token, auth_response.refresh_token);
        
        // Verify token structure
        assert!(!auth_response.access_token.is_empty());
        assert!(!auth_response.refresh_token.is_empty());
        assert_eq!(auth_response.token_type, "Bearer");
        assert_eq!(auth_response.expires_in, 3600);
    }

    #[test]
    fn test_invalid_jwt_formats() {
        let config = create_test_jwt_config();
        let jwt_service = JwtService::new(config);

        // Test various invalid token formats
        assert!(jwt_service.validate_token("").is_err());
        assert!(jwt_service.validate_token("invalid").is_err());
        assert!(jwt_service.validate_token("invalid.token").is_err());
        assert!(jwt_service.validate_token("invalid.token.format").is_err());
        assert!(jwt_service.validate_token("eyJhbGciOiJIUzI1NiJ9.invalid.signature").is_err());
    }

    #[test]
    fn test_user_store_operations_error_handling() {
        let mock_store = MockUserStore::new();
        let user_store = UserStore::Mock(Box::new(mock_store));

        // Test getting non-existent user should return Ok(None), not an error
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let result = runtime.block_on(async {
            user_store.get_user("nonexistent").await
        });
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_jwt_service_comprehensive() {
        let config = create_test_jwt_config();
        let jwt_service = JwtService::new(config);
        let user = create_test_user();

        // Test full token lifecycle
        let auth_response = jwt_service.generate_tokens(&user).unwrap();
        
        // Validate access token
        let access_claims = jwt_service.validate_token(&auth_response.access_token).unwrap();
        assert_eq!(access_claims.username, user.username);
        assert_eq!(access_claims.role, user.role);
        assert_eq!(access_claims.token_type, TokenType::Access);
        
        // Validate refresh token
        let refresh_claims = jwt_service.validate_token(&auth_response.refresh_token).unwrap();
        assert_eq!(refresh_claims.username, user.username);
        assert_eq!(refresh_claims.role, user.role);
        assert_eq!(refresh_claims.token_type, TokenType::Refresh);
        
        // Test token refresh
        let new_auth_response = jwt_service.refresh_token(&auth_response.refresh_token).unwrap();
        assert!(!new_auth_response.access_token.is_empty());
        assert!(!new_auth_response.refresh_token.is_empty());
        assert_eq!(new_auth_response.user.username, user.username);
    }

    #[test]
    fn test_claims_validation_edge_cases() {
        let config = create_test_jwt_config();
        let jwt_service = JwtService::new(config);
        
        // Test claims with edge case values
        let user = User {
            id: "test-id-with-special-chars-123!@#".to_string(),
            username: "test.user+name@example.com".to_string(),
            password_hash: "hash123".to_string(),
            role: UserRole::Admin,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            is_active: true,
        };

        let auth_response = jwt_service.generate_tokens(&user).unwrap();
        let claims = jwt_service.validate_token(&auth_response.access_token).unwrap();
        
        assert_eq!(claims.sub, user.id);
        assert_eq!(claims.username, user.username);
        assert_eq!(claims.role, user.role);
    }

    #[test]
    fn test_auth_error_from_bcrypt() {
        // Test conversion from bcrypt error
        let bcrypt_error = bcrypt::BcryptError::CostNotAllowed(50);
        let auth_error: AuthError = bcrypt_error.into();
        
        // Should convert to PasswordHashingFailed error
        assert_eq!(auth_error.to_string(), "Password hashing failed");
    }
}
