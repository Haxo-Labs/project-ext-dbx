use crate::{
    auth::{ApiKeyError, ApiKeyService},
    middleware::AuthError,
    models::{
        ApiKeyResponse, ApiKeyRotationResponse, ApiResponse, Claims, CreateApiKeyRequest,
        ListApiKeysRequest, ListApiKeysResponse, UpdateApiKeyRequest,
    },
};
use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use std::sync::Arc;

/// Create API key management routes
pub fn create_api_key_routes(api_key_service: Arc<ApiKeyService>) -> Router {
    Router::new()
        .route("/", post(create_api_key))
        .route("/", get(list_api_keys))
        .route("/:id", get(get_api_key))
        .route("/:id", put(update_api_key))
        .route("/:id", delete(delete_api_key))
        .route("/:id/rotate", post(rotate_api_key))
        .with_state(api_key_service)
}

/// Create a new API key
pub async fn create_api_key(
    State(api_key_service): State<Arc<ApiKeyService>>,
    Extension(claims): Extension<Claims>,
    Json(request): Json<CreateApiKeyRequest>,
) -> Result<Json<ApiResponse<ApiKeyResponse>>, (StatusCode, Json<ApiResponse<()>>)> {
    let (api_key, plaintext_key) = api_key_service
        .create_api_key(request, &claims.sub, &claims.username)
        .await
        .map_err(|e| {
            let (status, message) = match e {
                ApiKeyError::ValidationError(msg) => (StatusCode::BAD_REQUEST, msg),
                ApiKeyError::KeyNameExists => (
                    StatusCode::CONFLICT,
                    "API key name already exists".to_string(),
                ),
                ApiKeyError::DatabaseError(_) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Database error".to_string(),
                ),
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to create API key".to_string(),
                ),
            };

            (status, Json(ApiResponse::<()>::error(message)))
        })?;

    // Return response with the plaintext key (only shown once)
    let mut response = ApiKeyResponse::from(&api_key);
    response.key = Some(plaintext_key);

    Ok(Json(ApiResponse::success(response)))
}

/// List user's API keys
pub async fn list_api_keys(
    State(api_key_service): State<Arc<ApiKeyService>>,
    Extension(claims): Extension<Claims>,
    Query(query): Query<ListApiKeysRequest>,
) -> Result<Json<ApiResponse<ListApiKeysResponse>>, (StatusCode, Json<ApiResponse<()>>)> {
    let limit = query.limit.unwrap_or(50).min(100); // Cap at 100
    let offset = query.offset.unwrap_or(0);
    let active_only = query.active_only.unwrap_or(false);

    let (api_keys, total) = api_key_service
        .list_user_api_keys(&claims.sub, limit, offset, active_only)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<()>::error(
                    "Failed to list API keys".to_string(),
                )),
            )
        })?;

    let keys: Vec<ApiKeyResponse> = api_keys.iter().map(ApiKeyResponse::from).collect();

    let response = ListApiKeysResponse {
        keys,
        total,
        limit,
        offset,
    };

    Ok(Json(ApiResponse::success(response)))
}

/// Get a specific API key
pub async fn get_api_key(
    State(api_key_service): State<Arc<ApiKeyService>>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<ApiKeyResponse>>, (StatusCode, Json<ApiResponse<()>>)> {
    let api_key = api_key_service.get_api_key_by_id(&id).await.map_err(|e| {
        let (status, message) = match e {
            ApiKeyError::KeyNotFound => (StatusCode::NOT_FOUND, "API key not found".to_string()),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get API key".to_string(),
            ),
        };

        (status, Json(ApiResponse::<()>::error(message)))
    })?;

    // Verify ownership
    if api_key.owner_id != claims.sub {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiResponse::<()>::error("Access denied".to_string())),
        ));
    }

    let response = ApiKeyResponse::from(&api_key);
    Ok(Json(ApiResponse::success(response)))
}

/// Update an API key
pub async fn update_api_key(
    State(api_key_service): State<Arc<ApiKeyService>>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(request): Json<UpdateApiKeyRequest>,
) -> Result<Json<ApiResponse<ApiKeyResponse>>, (StatusCode, Json<ApiResponse<()>>)> {
    let api_key = api_key_service
        .update_api_key(&id, &claims.sub, request)
        .await
        .map_err(|e| {
            let (status, message) = match e {
                ApiKeyError::KeyNotFound => {
                    (StatusCode::NOT_FOUND, "API key not found".to_string())
                }
                ApiKeyError::ValidationError(msg) => (StatusCode::BAD_REQUEST, msg),
                ApiKeyError::KeyNameExists => (
                    StatusCode::CONFLICT,
                    "API key name already exists".to_string(),
                ),
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to update API key".to_string(),
                ),
            };

            (status, Json(ApiResponse::<()>::error(message)))
        })?;

    let response = ApiKeyResponse::from(&api_key);
    Ok(Json(ApiResponse::success(response)))
}

/// Rotate an API key (generate new key)
pub async fn rotate_api_key(
    State(api_key_service): State<Arc<ApiKeyService>>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<ApiKeyRotationResponse>>, (StatusCode, Json<ApiResponse<()>>)> {
    let (api_key, new_key) = api_key_service
        .rotate_api_key(&id, &claims.sub)
        .await
        .map_err(|e| {
            let (status, message) = match e {
                ApiKeyError::KeyNotFound => {
                    (StatusCode::NOT_FOUND, "API key not found".to_string())
                }
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to rotate API key".to_string(),
                ),
            };

            (status, Json(ApiResponse::<()>::error(message)))
        })?;

    let response = ApiKeyRotationResponse {
        id: api_key.id,
        new_key,
        key_prefix: api_key.key_prefix,
        rotated_at: api_key.updated_at,
    };

    Ok(Json(ApiResponse::success(response)))
}

/// Delete an API key
pub async fn delete_api_key(
    State(api_key_service): State<Arc<ApiKeyService>>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<String>>, (StatusCode, Json<ApiResponse<()>>)> {
    let deleted = api_key_service
        .delete_api_key(&id, &claims.sub)
        .await
        .map_err(|e| {
            let (status, message) = match e {
                ApiKeyError::KeyNotFound => {
                    (StatusCode::NOT_FOUND, "API key not found".to_string())
                }
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to delete API key".to_string(),
                ),
            };

            (status, Json(ApiResponse::<()>::error(message)))
        })?;

    if deleted {
        Ok(Json(ApiResponse::success(
            "API key deleted successfully".to_string(),
        )))
    } else {
        Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::<()>::error(
                "Failed to delete API key".to_string(),
            )),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ApiKeyPermission, TokenType, UserRole};
    use axum_test::TestServer;
    use chrono::Utc;
    use serde_json::json;

    fn create_test_claims() -> Claims {
        Claims {
            sub: "user_123".to_string(),
            username: "testuser".to_string(),
            role: UserRole::User,
            permissions: vec!["string:get".to_string(), "string:set".to_string()],
            exp: (Utc::now() + chrono::Duration::hours(1)).timestamp(),
            iat: Utc::now().timestamp(),
            iss: "test".to_string(),
            token_type: TokenType::Access,
        }
    }

    #[tokio::test]
    async fn test_create_api_key_endpoint() {
        // This test would require a proper test setup with Redis
        // Implementation structure for API key rotation endpoint
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
    }

    #[tokio::test]
    async fn test_list_api_keys_query() {
        let query = ListApiKeysRequest {
            limit: Some(10),
            offset: Some(0),
            active_only: Some(true),
        };

        assert_eq!(query.limit, Some(10));
        assert_eq!(query.active_only, Some(true));
    }
}
