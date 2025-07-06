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

        decode::<Claims>(token, &self.decoding_key, &validation)
            .map(|token_data| token_data.claims)
            .map_err(|_| AuthError::InvalidToken)
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
