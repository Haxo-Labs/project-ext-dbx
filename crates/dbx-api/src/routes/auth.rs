use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use std::sync::Arc;

use crate::{
    middleware::{AuthError, JwtService, UserStore, UserStoreOperations},
    models::{
        ApiResponse, AuthResponse, Claims, LoginRequest, RefreshRequest, TokenValidationResponse,
        UserInfo,
    },
};

/// Create authentication routes
pub fn create_auth_routes(jwt_service: Arc<JwtService>, user_store: Arc<UserStore>) -> Router {
    Router::new()
        .route("/login", post(login))
        .route("/refresh", post(refresh_token))
        .route("/logout", post(logout))
        .route("/validate", get(validate_token))
        .route("/me", get(get_current_user))
        .with_state((jwt_service, user_store))
}

/// Login endpoint
pub async fn login(
    State((jwt_service, user_store)): State<(Arc<JwtService>, Arc<UserStore>)>,
    Json(login_request): Json<LoginRequest>,
) -> Result<Json<ApiResponse<AuthResponse>>, (StatusCode, Json<ApiResponse<()>>)> {
    let user = user_store
        .verify_password(&login_request.username, &login_request.password)
        .await
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::<()>::error("Invalid credentials".to_string())),
            )
        })?;

    if !user {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ApiResponse::<()>::error("Invalid credentials".to_string())),
        ));
    }

    let user = user_store
        .get_user_by_username(&login_request.username)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<()>::error("Database error".to_string())),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::<()>::error("User not found".to_string())),
            )
        })?;

    let auth_response = jwt_service
        .authenticate_user(&login_request.username, &login_request.password)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<()>::error(
                    "Failed to generate tokens".to_string(),
                )),
            )
        })?;

    Ok(Json(ApiResponse::success(auth_response)))
}

/// Refresh token endpoint
pub async fn refresh_token(
    State((jwt_service, _)): State<(Arc<JwtService>, Arc<UserStore>)>,
    Json(refresh_request): Json<RefreshRequest>,
) -> Result<Json<ApiResponse<AuthResponse>>, (StatusCode, Json<ApiResponse<()>>)> {
    let auth_response = jwt_service
        .refresh_token(&refresh_request.refresh_token)
        .await
        .map_err(|err| match err {
            AuthError::TokenExpired => (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::<()>::error(
                    "Refresh token expired".to_string(),
                )),
            ),
            AuthError::InvalidToken => (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::<()>::error(
                    "Invalid refresh token".to_string(),
                )),
            ),
            AuthError::UserNotFound => (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::<()>::error("User not found".to_string())),
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<()>::error("Token refresh failed".to_string())),
            ),
        })?;

    Ok(Json(ApiResponse::success(auth_response)))
}

/// Logout endpoint (for client-side token invalidation)
pub async fn logout() -> Json<ApiResponse<String>> {
    Json(ApiResponse::success("Logged out successfully".to_string()))
}

/// Validate token endpoint
pub async fn validate_token(
    Extension(claims): Extension<Claims>,
) -> Json<ApiResponse<TokenValidationResponse>> {
    let response = TokenValidationResponse {
        valid: true,
        user: Some(UserInfo {
            id: claims.sub,
            username: claims.username,
            role: claims.role,
        }),
        expires_at: Some(chrono::DateTime::from_timestamp(claims.exp, 0).unwrap_or_default()),
    };

    Json(ApiResponse::success(response))
}

/// Get current user information
pub async fn get_current_user(Extension(claims): Extension<Claims>) -> Json<ApiResponse<UserInfo>> {
    let user_info = UserInfo {
        id: claims.sub,
        username: claims.username,
        role: claims.role,
    };

    Json(ApiResponse::success(user_info))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::JwtConfig;
    use crate::middleware::{JwtService, UserStore, UserStoreOperations};
    use crate::models::{LoginRequest, RefreshRequest, TokenType, User, UserRole};
    use async_trait::async_trait;
    use axum::{extract::State, http::StatusCode, Json};
    use bcrypt::{hash, DEFAULT_COST};
    use chrono::Utc;
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

    // TODO: Fix tests to match actual UserStoreOperations trait methods
    /*
    struct MockUserStore {
        users: Arc<RwLock<HashMap<String, User>>>,
    }

    impl MockUserStore {
        fn new() -> Self {
            Self {
                users: Arc::new(RwLock::new(HashMap::new())),
            }
        }

        async fn add_user(&self, username: &str, password: &str, role: UserRole) -> User {
            let password_hash = bcrypt::hash(password, bcrypt::DEFAULT_COST).unwrap();
            let user = User {
                id: uuid::Uuid::new_v4().to_string(),
                username: username.to_string(),
                password_hash,
                role,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                is_active: true,
            };

            let mut users = self.users.write().await;
            users.insert(username.to_string(), user.clone());
            user
        }
    }

    // Rest of test implementations would go here
    */
}
