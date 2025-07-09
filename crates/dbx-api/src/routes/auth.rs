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

    // Mock UserStore implementation for testing
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

        async fn add_user(&self, username: &str, password: &str, role: UserRole) -> User {
            let password_hash = hash(password, DEFAULT_COST).unwrap();
            let user = User {
                id: format!("user_{}", username),
                username: username.to_string(),
                password_hash,
                role,
                is_active: true,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };
            self.users
                .write()
                .await
                .insert(username.to_string(), user.clone());
            user
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

            if bcrypt::verify(password, &user.password_hash)
                .map_err(|_| AuthError::InvalidCredentials)?
            {
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

    #[tokio::test]
    async fn test_login_success() {
        let jwt_config = create_test_jwt_config();
        let jwt_service = Arc::new(JwtService::new(jwt_config));
        let mock_store = MockUserStore::new();
        mock_store
            .add_user("testuser", "testpass123", UserRole::User)
            .await;

        let request = LoginRequest {
            username: "testuser".to_string(),
            password: "testpass123".to_string(),
        };

        let result = login(
            State((jwt_service, Arc::new(UserStore::Mock(Box::new(mock_store))))),
            Json(request),
        )
        .await;

        match result {
            Ok(response) => {
                assert!(response.success);
                assert!(response.data.is_some());
                let auth_response = response.data.as_ref().unwrap();
                assert!(!auth_response.access_token.is_empty());
                assert!(!auth_response.refresh_token.is_empty());
                assert_eq!(auth_response.user.username, "testuser");
            }
            Err(_) => panic!("Expected successful login"),
        }
    }

    #[tokio::test]
    async fn test_login_invalid_credentials() {
        let jwt_config = create_test_jwt_config();
        let jwt_service = Arc::new(JwtService::new(jwt_config));
        let mock_store = MockUserStore::new();
        mock_store
            .add_user("testuser", "testpass123", UserRole::User)
            .await;

        let request = LoginRequest {
            username: "testuser".to_string(),
            password: "wrongpassword".to_string(),
        };

        let result = login(
            State((jwt_service, Arc::new(UserStore::Mock(Box::new(mock_store))))),
            Json(request),
        )
        .await;

        match result {
            Ok(_) => panic!("Expected authentication failure"),
            Err((status, response)) => {
                assert_eq!(status, StatusCode::UNAUTHORIZED);
                assert!(!response.success);
                assert!(response.error.is_some());
            }
        }
    }

    #[tokio::test]
    async fn test_login_user_not_found() {
        let jwt_config = create_test_jwt_config();
        let jwt_service = Arc::new(JwtService::new(jwt_config));
        let mock_store = MockUserStore::new();

        let request = LoginRequest {
            username: "nonexistent".to_string(),
            password: "password".to_string(),
        };

        let result = login(
            State((jwt_service, Arc::new(UserStore::Mock(Box::new(mock_store))))),
            Json(request),
        )
        .await;

        match result {
            Ok(_) => panic!("Expected user not found error"),
            Err((status, response)) => {
                assert_eq!(status, StatusCode::UNAUTHORIZED);
                assert!(!response.success);
                assert!(response.error.is_some());
            }
        }
    }

    #[tokio::test]
    async fn test_refresh_token_success() {
        let jwt_config = create_test_jwt_config();
        let jwt_service = Arc::new(JwtService::new(jwt_config));
        let mock_store = MockUserStore::new();
        let user = mock_store
            .add_user("testuser", "testpass123", UserRole::User)
            .await;

        let auth_response = jwt_service.generate_tokens(&user).unwrap();

        let request = RefreshRequest {
            refresh_token: auth_response.refresh_token,
        };

        let result = refresh_token(
            State((jwt_service, Arc::new(UserStore::Mock(Box::new(mock_store))))),
            Json(request),
        )
        .await;

        match result {
            Ok(response) => {
                assert!(response.success);
                assert!(response.data.is_some());
                let new_auth_response = response.data.as_ref().unwrap();
                assert!(!new_auth_response.access_token.is_empty());
                assert!(!new_auth_response.refresh_token.is_empty());
                assert_eq!(new_auth_response.user.username, "testuser");
            }
            Err(_) => panic!("Expected successful token refresh"),
        }
    }

    #[tokio::test]
    async fn test_refresh_token_invalid_token() {
        let jwt_config = create_test_jwt_config();
        let jwt_service = Arc::new(JwtService::new(jwt_config));
        let mock_store = MockUserStore::new();

        let request = RefreshRequest {
            refresh_token: "invalid_token".to_string(),
        };

        let result = refresh_token(
            State((jwt_service, Arc::new(UserStore::Mock(Box::new(mock_store))))),
            Json(request),
        )
        .await;

        match result {
            Ok(_) => panic!("Expected token validation failure"),
            Err((status, response)) => {
                assert_eq!(status, StatusCode::UNAUTHORIZED);
                assert!(!response.success);
                assert!(response.error.is_some());
            }
        }
    }

    #[tokio::test]
    async fn test_refresh_token_with_access_token() {
        let jwt_config = create_test_jwt_config();
        let jwt_service = Arc::new(JwtService::new(jwt_config));
        let mock_store = MockUserStore::new();
        let user = mock_store
            .add_user("testuser", "testpass123", UserRole::User)
            .await;

        let auth_response = jwt_service.generate_tokens(&user).unwrap();

        let request = RefreshRequest {
            refresh_token: auth_response.access_token, // Using access token instead of refresh token
        };

        let result = refresh_token(
            State((jwt_service, Arc::new(UserStore::Mock(Box::new(mock_store))))),
            Json(request),
        )
        .await;

        match result {
            Ok(_) => panic!("Expected token type validation failure"),
            Err((status, response)) => {
                assert_eq!(status, StatusCode::BAD_REQUEST); // Changed from UNAUTHORIZED to BAD_REQUEST
                assert!(!response.success);
                assert!(response.error.is_some());
            }
        }
    }

    #[tokio::test]
    async fn test_logout_endpoint() {
        let response = logout().await;
        assert!(response.success);
        assert_eq!(response.data, Some("Logged out successfully".to_string()));
    }

    #[tokio::test]
    async fn test_get_current_user() {
        let claims = Claims {
            sub: "testuser".to_string(),
            username: "testuser".to_string(),
            exp: 0,
            iat: 0,
            iss: "test_issuer".to_string(),
            role: UserRole::User,
            token_type: TokenType::Access,
        };

        let response = get_current_user(Extension(claims)).await;
        assert!(response.success);
        assert!(response.data.is_some());
        let user_info = response.data.as_ref().unwrap();
        assert_eq!(user_info.username, "testuser");
        assert_eq!(user_info.role, UserRole::User);
    }

    #[tokio::test]
    async fn test_validate_token_endpoint() {
        let claims = Claims {
            sub: "testuser".to_string(),
            username: "testuser".to_string(),
            exp: 0,
            iat: 0,
            iss: "test_issuer".to_string(),
            role: UserRole::User,
            token_type: TokenType::Access,
        };

        let response = validate_token(Extension(claims)).await;
        assert!(response.success);
        assert!(response.data.is_some());
        let validation_response = response.data.as_ref().unwrap();
        assert!(validation_response.valid);
        assert!(validation_response.user.is_some());
        let user_info = validation_response.user.as_ref().unwrap();
        assert_eq!(user_info.username, "testuser");
        assert_eq!(user_info.role, UserRole::User);
    }

    #[tokio::test]
    async fn test_create_auth_routes() {
        let jwt_config = create_test_jwt_config();
        let jwt_service = Arc::new(JwtService::new(jwt_config));
        let mock_store = MockUserStore::new();
        let user_store = Arc::new(UserStore::Mock(Box::new(mock_store)));

        let _router = create_auth_routes(jwt_service, user_store);
        // Test that the router was created successfully
        // Router creation compilation verification
    }

    #[tokio::test]
    async fn test_mock_user_store_operations() {
        let mock_store = MockUserStore::new();
        let user = mock_store
            .add_user("testuser", "testpass123", UserRole::User)
            .await;

        // Test get_user
        let retrieved_user = mock_store.get_user("testuser").await.unwrap();
        assert!(retrieved_user.is_some());
        assert_eq!(retrieved_user.unwrap().username, "testuser");

        // Test authenticate
        let authenticated_user = mock_store
            .authenticate("testuser", "testpass123")
            .await
            .unwrap();
        assert_eq!(authenticated_user.username, "testuser");

        // Test invalid authentication
        let auth_result = mock_store.authenticate("testuser", "wrongpassword").await;
        assert!(auth_result.is_err());

        // Test update_user
        let mut updated_user = user.clone();
        updated_user.is_active = false;
        assert!(mock_store.update_user(&updated_user).await.is_ok());

        // Test delete_user
        assert!(mock_store.delete_user("testuser").await.unwrap());
        assert!(!mock_store.delete_user("nonexistent").await.unwrap());
    }
}
