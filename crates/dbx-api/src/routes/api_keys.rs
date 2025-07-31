use crate::{
    auth::ApiKeyService,
    models::{
        ApiKeyResponse, ApiResponse, Claims, CreateApiKeyRequest, ListApiKeysRequest,
        ListApiKeysResponse,
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
pub fn create_api_key_routes(api_key_service: Arc<crate::auth::ApiKeyService>) -> Router {
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
        .map_err(|_e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<()>::error(
                    "Failed to create API key".to_string(),
                )),
            )
        })?;

    // Return response with the plaintext key (only shown once)
    let mut response = ApiKeyResponse::from(&api_key);
    response.key = Some(plaintext_key);

    Ok(Json(ApiResponse::success(response)))
}

/// List user's API keys
pub async fn list_api_keys(
    State(api_key_service): State<Arc<crate::auth::ApiKeyService>>,
    Extension(claims): Extension<crate::models::Claims>,
    Query(query): Query<ListApiKeysRequest>,
) -> Result<Json<ApiResponse<ListApiKeysResponse>>, (StatusCode, Json<ApiResponse<()>>)> {
    let limit = query.limit.unwrap_or(50).min(100); // Cap at 100
    let offset = query.offset.unwrap_or(0);
    let active_only = query.active_only.unwrap_or(false);

    let (api_keys, total) = api_key_service
        .list_user_api_keys(&claims.sub, limit, offset, active_only)
        .await
        .map_err(|_e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<()>::error(
                    "Failed to list API keys".to_string(),
                )),
            )
        })?;

    let keys: Vec<crate::models::ApiKeyResponse> = api_keys
        .iter()
        .map(crate::models::ApiKeyResponse::from)
        .collect();

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
    State(api_key_service): State<Arc<crate::auth::ApiKeyService>>,
    Extension(claims): Extension<crate::models::Claims>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<crate::models::ApiKeyResponse>>, (StatusCode, Json<ApiResponse<()>>)> {
    let api_key = api_key_service.get_api_key_by_id(&id).await.map_err(|e| {
        let (status, message) = match e {
            crate::auth::ApiKeyError::KeyNotFound => {
                (StatusCode::NOT_FOUND, "API key not found".to_string())
            }
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

    let response = crate::models::ApiKeyResponse::from(&api_key);
    Ok(Json(ApiResponse::success(response)))
}

/// Update an API key
pub async fn update_api_key(
    Path(id): Path<String>,
    State(api_key_service): State<Arc<crate::auth::ApiKeyService>>,
    Extension(claims): Extension<crate::models::Claims>,
    Json(request): Json<serde_json::Value>,
) -> Result<Json<ApiResponse<crate::models::ApiKeyResponse>>, (StatusCode, Json<ApiResponse<()>>)> {
    let name = request
        .get("name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let api_key = api_key_service
        .update_api_key(&id, &claims.sub, name)
        .await
        .map_err(|e| {
            let (status, message) = match e {
                crate::auth::ApiKeyError::KeyNotFound => {
                    (StatusCode::NOT_FOUND, "API key not found".to_string())
                }
                crate::auth::ApiKeyError::ValidationError(msg) => (StatusCode::BAD_REQUEST, msg),
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                ),
            };
            (status, Json(ApiResponse::error(message)))
        })?;

    let response = crate::models::ApiKeyResponse::from(&api_key);
    Ok(Json(ApiResponse::success(response)))
}

/// Rotate an API key (generate new key)
pub async fn rotate_api_key(
    State(api_key_service): State<Arc<crate::auth::ApiKeyService>>,
    Extension(claims): Extension<crate::models::Claims>,
    Path(id): Path<String>,
) -> Result<
    Json<ApiResponse<crate::models::ApiKeyRotationResponse>>,
    (StatusCode, Json<ApiResponse<()>>),
> {
    let (api_key, new_key) = api_key_service
        .rotate_api_key(&id, &claims.sub)
        .await
        .map_err(|e| {
            let (status, message) = match e {
                crate::auth::ApiKeyError::KeyNotFound => {
                    (StatusCode::NOT_FOUND, "API key not found".to_string())
                }
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to rotate API key".to_string(),
                ),
            };

            (status, Json(ApiResponse::<()>::error(message)))
        })?;

    let response = crate::models::ApiKeyRotationResponse {
        id: api_key.id,
        new_key,
        key_prefix: api_key.key_prefix,
        rotated_at: api_key.updated_at,
    };

    Ok(Json(ApiResponse::success(response)))
}

/// Delete an API key
pub async fn delete_api_key(
    Path(id): Path<String>,
    State(api_key_service): State<Arc<crate::auth::ApiKeyService>>,
    Extension(claims): Extension<crate::models::Claims>,
) -> Result<Json<ApiResponse<()>>, (StatusCode, Json<ApiResponse<()>>)> {
    api_key_service
        .delete_api_key(&id, &claims.sub)
        .await
        .map_err(|_e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<()>::error(
                    "Failed to delete API key".to_string(),
                )),
            )
        })?;

    Ok(Json(ApiResponse::success(())))
}
