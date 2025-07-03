use axum::{
    extract::{rejection::JsonRejection, Request, State},
    http::{header, StatusCode, HeaderMap},
    middleware::Next,
    response::IntoResponse,
    response::Json,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation, Algorithm};
use std::sync::Arc;

use uuid::Uuid;

use crate::{
    config::JwtConfig,
    constants::errors::ErrorMessages,
    models::{ApiResponse, Claims, TokenType, User, UserRole, AuthResponse, UserInfo},
};

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
        let access_exp = now + Duration::seconds(self.config.access_token_expiration);
        let refresh_exp = now + Duration::seconds(self.config.refresh_token_expiration);

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
            expires_in: self.config.access_token_expiration,
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
    let token = extract_token_from_header(request.headers())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::<()>::error("Missing authorization token".to_string())),
            )
        })?;

    let claims = jwt_service.validate_token(&token).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ApiResponse::<()>::error("Invalid or expired token".to_string())),
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
    let claims = request.extensions().get::<Claims>()
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::<()>::error("Authentication required".to_string())),
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
    let claims = request.extensions().get::<Claims>()
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::<()>::error("Authentication required".to_string())),
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
    let _claims = request.extensions().get::<Claims>()
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::<()>::error("Authentication required".to_string())),
            )
        })?;

    Ok(next.run(request).await)
}

pub struct UserStore {
    users: std::collections::HashMap<String, User>,
}

impl UserStore {
    pub fn new() -> Self {
        let mut users = std::collections::HashMap::new();
        let admin_user = User {
            id: Uuid::new_v4().to_string(),
            username: "admin".to_string(),
            role: UserRole::Admin,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            is_active: true,
        };

        let regular_user = User {
            id: Uuid::new_v4().to_string(),
            username: "user".to_string(),
            role: UserRole::User,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            is_active: true,
        };

        let readonly_user = User {
            id: Uuid::new_v4().to_string(),
            username: "readonly".to_string(),
            role: UserRole::ReadOnly,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            is_active: true,
        };

        users.insert("admin".to_string(), admin_user);
        users.insert("user".to_string(), regular_user);
        users.insert("readonly".to_string(), readonly_user);

        Self { users }
    }

    pub fn authenticate(&self, username: &str, password: &str) -> Option<&User> {
        let demo_passwords = [
            ("admin", "admin123"),
            ("user", "user123"),
            ("readonly", "readonly123"),
        ];

        if demo_passwords.iter().any(|(u, p)| *u == username && *p == password) {
            self.users.get(username)
        } else {
            None
        }
    }

    pub fn get_user(&self, username: &str) -> Option<&User> {
        self.users.get(username)
    }
}
