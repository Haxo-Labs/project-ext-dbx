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
        .authenticate(&login_request.username, &login_request.password)
        .await
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::<()>::error("Invalid credentials".to_string())),
            )
        })?;

    if !user.is_active {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ApiResponse::<()>::error("Account is disabled".to_string())),
        ));
    }

    let auth_response = jwt_service.generate_tokens(&user).map_err(|_| {
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
        .map_err(|err| match err {
            AuthError::InvalidToken => (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::<()>::error(
                    "Invalid refresh token".to_string(),
                )),
            ),
            AuthError::InvalidTokenType => (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<()>::error("Invalid token type".to_string())),
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<()>::error(
                    "Failed to refresh token".to_string(),
                )),
            ),
        })?;

    Ok(Json(ApiResponse::success(auth_response)))
}

/// Logout endpoint (for client-side token invalidation)
pub async fn logout() -> Json<ApiResponse<String>> {
    Json(ApiResponse::success("Successfully logged out".to_string()))
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
    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use std::collections::HashMap;
    use tower::ServiceExt;

    use crate::{
        config::JwtConfig,
        constants::defaults::Defaults,
        models::{User, UserRole},
    };

    struct MockUserStore {
        users: HashMap<String, User>,
    }

    impl MockUserStore {
        fn new() -> Self {
            let mut users = HashMap::new();

            users.insert(
                "admin".to_string(),
                User {
                    id: uuid::Uuid::new_v4().to_string(),
                    username: "admin".to_string(),
                    password_hash: "$2b$12$example_hash_for_admin123".to_string(),
                    role: UserRole::Admin,
                    is_active: true,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                },
            );

            Self { users }
        }
    }

    #[async_trait]
    impl crate::middleware::UserStoreOperations for MockUserStore {
        async fn create_user(&self, _user: &User) -> Result<(), crate::middleware::AuthError> {
            Ok(())
        }

        async fn get_user(
            &self,
            username: &str,
        ) -> Result<Option<User>, crate::middleware::AuthError> {
            Ok(self.users.get(username).cloned())
        }

        async fn authenticate(
            &self,
            username: &str,
            password: &str,
        ) -> Result<User, crate::middleware::AuthError> {
            if let Some(user) = self.users.get(username) {
                if password == "admin123" {
                    Ok(user.clone())
                } else {
                    Err(crate::middleware::AuthError::InvalidCredentials)
                }
            } else {
                Err(crate::middleware::AuthError::InvalidCredentials)
            }
        }

        async fn update_user(&self, _user: &User) -> Result<(), crate::middleware::AuthError> {
            Ok(())
        }

        async fn delete_user(&self, _username: &str) -> Result<bool, crate::middleware::AuthError> {
            Ok(true)
        }
    }

    fn create_test_jwt_service() -> Arc<JwtService> {
        let config = JwtConfig {
            secret: "test-secret-at-least-32-characters-long".to_string(),
            access_token_expiration: 900,
            refresh_token_expiration: 604800,
            issuer: "dbx-test-api".to_string(),
        };
        Arc::new(JwtService::new(config))
    }

    fn create_test_user_store() -> Arc<UserStore> {
        Arc::new(UserStore::Mock(Box::new(MockUserStore::new())))
    }

    #[tokio::test]
    async fn test_login_success() {
        let jwt_service = create_test_jwt_service();
        let user_store = create_test_user_store();
        let app = create_auth_routes(jwt_service, user_store);

        let login_request = LoginRequest {
            username: "admin".to_string(),
            password: "admin123".to_string(),
        };

        let request = Request::builder()
            .method(Method::POST)
            .uri("/login")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&login_request).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_login_invalid_credentials() {
        let jwt_service = create_test_jwt_service();
        let user_store = create_test_user_store();
        let app = create_auth_routes(jwt_service, user_store);

        let login_request = LoginRequest {
            username: "admin".to_string(),
            password: "wrong_password".to_string(),
        };

        let request = Request::builder()
            .method(Method::POST)
            .uri("/login")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&login_request).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
