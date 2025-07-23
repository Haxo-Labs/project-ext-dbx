use axum::{
    extract::{Path, Query, Request, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use std::sync::Arc;

use crate::{
    auth::{
        permissions::{PermissionType, Role, RoleRegistry},
        RbacService,
    },
    models::{
        ApiResponse, AssignRoleRequest, AuditQueryParams, CreateRoleRequest, RevokeRoleRequest,
        RoleResponse, UpdateRoleRequest, UserPermissionsResponse,
    },
};

/// Create role management routes
pub fn create_role_routes(rbac_service: Arc<RbacService>) -> Router {
    Router::new()
        .route("/", get(list_roles).post(create_role))
        .route(
            "/:role_name",
            get(get_role).put(update_role).delete(delete_role),
        )
        .route("/:role_name/permissions", get(get_role_permissions))
        .route("/assign", post(assign_role_to_user))
        .route("/revoke", post(revoke_role_from_user))
        .route("/users/:user_id/permissions", get(get_user_permissions))
        .route("/audit", get(get_audit_logs))
        .with_state(rbac_service)
}

/// List all available roles
pub async fn list_roles(
    State(rbac_service): State<Arc<RbacService>>,
) -> Result<Json<ApiResponse<Vec<RoleResponse>>>, (StatusCode, Json<ApiResponse<()>>)> {
    let role_registry_arc = rbac_service.get_role_registry();
    let role_registry = role_registry_arc.read().unwrap();
    let roles = role_registry.list_roles();

    let role_responses: Vec<RoleResponse> = roles
        .iter()
        .map(|role| {
            let effective_permissions = role.effective_permissions(&role_registry);
            RoleResponse {
                name: role.name.clone(),
                description: role.description.clone(),
                permissions: role
                    .permissions
                    .permission_names()
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                inherits_from: role.inherits_from.clone(),
                is_default: role.is_default,
                is_system: role.is_system,
                effective_permissions: effective_permissions
                    .permission_names()
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            }
        })
        .collect();

    Ok(Json(ApiResponse::success(role_responses)))
}

/// Get a specific role by name
pub async fn get_role(
    State(rbac_service): State<Arc<RbacService>>,
    Path(role_name): Path<String>,
) -> Result<Json<ApiResponse<RoleResponse>>, (StatusCode, Json<ApiResponse<()>>)> {
    let role_registry_arc = rbac_service.get_role_registry();
    let role_registry = role_registry_arc.read().unwrap();

    match role_registry.get_role(&role_name) {
        Some(role) => {
            let effective_permissions = role.effective_permissions(&role_registry);
            let role_response = RoleResponse {
                name: role.name.clone(),
                description: role.description.clone(),
                permissions: role
                    .permissions
                    .permission_names()
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                inherits_from: role.inherits_from.clone(),
                is_default: role.is_default,
                is_system: role.is_system,
                effective_permissions: effective_permissions
                    .permission_names()
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            };
            Ok(Json(ApiResponse::success(role_response)))
        }
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::<()>::error(format!(
                "Role '{}' not found",
                role_name
            ))),
        )),
    }
}

/// Create a new custom role
pub async fn create_role(
    State(rbac_service): State<Arc<RbacService>>,
    mut req: Request,
) -> Result<Json<ApiResponse<RoleResponse>>, (StatusCode, Json<ApiResponse<()>>)> {
    // Extract authenticated user from RBAC context
    let rbac_context = req
        .extensions()
        .get::<crate::models::RbacContext>()
        .cloned()
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::<()>::error(
                    "Authentication required".to_string(),
                )),
            )
        })?;

    // Extract request body
    let body_bytes = match axum::body::to_bytes(req.into_body(), usize::MAX).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<()>::error("Invalid request body".to_string())),
            ));
        }
    };

    let request: CreateRoleRequest = match serde_json::from_slice(&body_bytes) {
        Ok(req) => req,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<()>::error("Invalid JSON format".to_string())),
            ));
        }
    };

    match rbac_service
        .create_role(
            &request.name,
            &request.description,
            request.permissions,
            request.inherits_from,
            &rbac_context.username,
        )
        .await
    {
        Ok(role) => {
            let role_registry_arc = rbac_service.get_role_registry();
            let role_registry = role_registry_arc.read().unwrap();
            let effective_permissions = role.effective_permissions(&role_registry);
            let role_response = RoleResponse {
                name: role.name.clone(),
                description: role.description.clone(),
                permissions: role
                    .permissions
                    .permission_names()
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                inherits_from: role.inherits_from.clone(),
                is_default: role.is_default,
                is_system: role.is_system,
                effective_permissions: effective_permissions
                    .permission_names()
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            };
            Ok(Json(ApiResponse::success(role_response)))
        }
        Err(e) => {
            let (status, message) = match e {
                crate::auth::RbacError::InvalidRoleName(msg) => (StatusCode::BAD_REQUEST, msg),
                crate::auth::RbacError::InheritanceCycle => (
                    StatusCode::BAD_REQUEST,
                    "Role inheritance cycle detected".to_string(),
                ),
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to create role".to_string(),
                ),
            };
            Err((status, Json(ApiResponse::<()>::error(message))))
        }
    }
}

/// Update an existing role
pub async fn update_role(
    State(rbac_service): State<Arc<RbacService>>,
    Path(role_name): Path<String>,
    Json(request): Json<UpdateRoleRequest>,
) -> Result<Json<ApiResponse<RoleResponse>>, (StatusCode, Json<ApiResponse<()>>)> {
    // Check if role exists and is not a system role
    {
        let role_registry_arc = rbac_service.get_role_registry();
        let role_registry = role_registry_arc.read().unwrap();
        match role_registry.get_role(&role_name) {
            Some(role) if role.is_system => {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(ApiResponse::<()>::error(
                        "Cannot modify system role".to_string(),
                    )),
                ));
            }
            Some(_) => {} // Role exists and can be modified
            None => {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(ApiResponse::<()>::error(format!(
                        "Role '{}' not found",
                        role_name
                    ))),
                ));
            }
        }
    }

    // Update role using RBAC service
    match rbac_service
        .update_role(
            &role_name,
            request.description,
            request.permissions,
            request.inherits_from,
            "admin_user", // Authenticated user context would be extracted from middleware
        )
        .await
    {
        Ok(role) => {
            let role_registry_arc = rbac_service.get_role_registry();
            let role_registry = role_registry_arc.read().unwrap();
            let effective_permissions = role.effective_permissions(&role_registry);
            let role_response = RoleResponse {
                name: role.name.clone(),
                description: role.description.clone(),
                permissions: role
                    .permissions
                    .permission_names()
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                inherits_from: role.inherits_from.clone(),
                is_default: role.is_default,
                is_system: role.is_system,
                effective_permissions: effective_permissions
                    .permission_names()
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            };
            Ok(Json(ApiResponse::success(role_response)))
        }
        Err(e) => {
            let (status, message) = match e {
                crate::auth::RbacError::RoleNotFound(msg) => (StatusCode::NOT_FOUND, msg),
                crate::auth::RbacError::SystemRoleModification => (
                    StatusCode::FORBIDDEN,
                    "Cannot modify system role".to_string(),
                ),
                crate::auth::RbacError::InheritanceCycle => (
                    StatusCode::BAD_REQUEST,
                    "Role inheritance cycle detected".to_string(),
                ),
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to update role".to_string(),
                ),
            };
            Err((status, Json(ApiResponse::<()>::error(message))))
        }
    }
}

/// Delete a custom role
pub async fn delete_role(
    State(rbac_service): State<Arc<RbacService>>,
    Path(role_name): Path<String>,
    req: Request,
) -> Result<Json<ApiResponse<String>>, (StatusCode, Json<ApiResponse<()>>)> {
    // Extract authenticated user from RBAC context
    let rbac_context = req
        .extensions()
        .get::<crate::models::RbacContext>()
        .cloned()
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::<()>::error(
                    "Authentication required".to_string(),
                )),
            )
        })?;

    match rbac_service
        .delete_role(&role_name, &rbac_context.username)
        .await
    {
        Ok(()) => Ok(Json(ApiResponse::success(format!(
            "Role '{}' deleted successfully",
            role_name
        )))),
        Err(e) => {
            let (status, message) = match e {
                crate::auth::RbacError::RoleNotFound(msg) => (StatusCode::NOT_FOUND, msg),
                crate::auth::RbacError::SystemRoleModification => (
                    StatusCode::FORBIDDEN,
                    "Cannot delete system role".to_string(),
                ),
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to delete role".to_string(),
                ),
            };
            Err((status, Json(ApiResponse::<()>::error(message))))
        }
    }
}

/// Get permissions for a specific role
pub async fn get_role_permissions(
    State(rbac_service): State<Arc<RbacService>>,
    Path(role_name): Path<String>,
) -> Result<Json<ApiResponse<Vec<String>>>, (StatusCode, Json<ApiResponse<()>>)> {
    let role_registry_arc = rbac_service.get_role_registry();
    let role_registry = role_registry_arc.read().unwrap();

    match role_registry.get_effective_permissions(&role_name) {
        Some(permissions) => {
            let permission_names: Vec<String> = permissions
                .permission_names()
                .iter()
                .map(|s| s.to_string())
                .collect();
            Ok(Json(ApiResponse::success(permission_names)))
        }
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ApiResponse::<()>::error(format!(
                "Role '{}' not found",
                role_name
            ))),
        )),
    }
}

/// Assign a role to a user
pub async fn assign_role_to_user(
    State(rbac_service): State<Arc<RbacService>>,
    mut req: Request,
) -> Result<Json<ApiResponse<String>>, (StatusCode, Json<ApiResponse<()>>)> {
    // Extract authenticated user from RBAC context
    let rbac_context = req
        .extensions()
        .get::<crate::models::RbacContext>()
        .cloned()
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::<()>::error(
                    "Authentication required".to_string(),
                )),
            )
        })?;

    // Extract request body
    let body_bytes = match axum::body::to_bytes(req.into_body(), usize::MAX).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<()>::error("Invalid request body".to_string())),
            ));
        }
    };

    let request: AssignRoleRequest = match serde_json::from_slice(&body_bytes) {
        Ok(req) => req,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<()>::error("Invalid JSON format".to_string())),
            ));
        }
    };

    match rbac_service
        .assign_role(
            &request.user_id,
            &request.user_id, // User ID is the username in this context
            &request.role_name,
            &rbac_context.username,
            request.expires_in_days,
            request.metadata,
        )
        .await
    {
        Ok(_) => Ok(Json(ApiResponse::success(format!(
            "Role '{}' assigned to user '{}' successfully",
            request.role_name, request.user_id
        )))),
        Err(e) => {
            let (status, message) = match e {
                crate::auth::RbacError::RoleNotFound(msg) => (StatusCode::NOT_FOUND, msg),
                crate::auth::RbacError::UserNotFound(msg) => (StatusCode::NOT_FOUND, msg),
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to assign role".to_string(),
                ),
            };
            Err((status, Json(ApiResponse::<()>::error(message))))
        }
    }
}

/// Revoke a role from a user
pub async fn revoke_role_from_user(
    State(rbac_service): State<Arc<RbacService>>,
    mut req: Request,
) -> Result<Json<ApiResponse<String>>, (StatusCode, Json<ApiResponse<()>>)> {
    // Extract authenticated user from RBAC context
    let rbac_context = req
        .extensions()
        .get::<crate::models::RbacContext>()
        .cloned()
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::<()>::error(
                    "Authentication required".to_string(),
                )),
            )
        })?;

    // Extract request body
    let body_bytes = match axum::body::to_bytes(req.into_body(), usize::MAX).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<()>::error("Invalid request body".to_string())),
            ));
        }
    };

    let request: RevokeRoleRequest = match serde_json::from_slice(&body_bytes) {
        Ok(req) => req,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<()>::error("Invalid JSON format".to_string())),
            ));
        }
    };

    match rbac_service
        .revoke_role(
            &request.user_id,
            &request.role_name,
            &rbac_context.username,
            request.reason,
        )
        .await
    {
        Ok(()) => Ok(Json(ApiResponse::success(format!(
            "Role '{}' revoked from user '{}' successfully",
            request.role_name, request.user_id
        )))),
        Err(e) => {
            let (status, message) = match e {
                crate::auth::RbacError::AssignmentNotFound => (
                    StatusCode::NOT_FOUND,
                    "Role assignment not found".to_string(),
                ),
                crate::auth::RbacError::UserNotFound(msg) => (StatusCode::NOT_FOUND, msg),
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to revoke role".to_string(),
                ),
            };
            Err((status, Json(ApiResponse::<()>::error(message))))
        }
    }
}

/// Get user permissions and role assignments
pub async fn get_user_permissions(
    State(rbac_service): State<Arc<RbacService>>,
    Path(user_id): Path<String>,
) -> Result<Json<ApiResponse<UserPermissionsResponse>>, (StatusCode, Json<ApiResponse<()>>)> {
    match rbac_service.get_user_role_assignments(&user_id).await {
        Ok(assignments) => {
            let effective_permissions = rbac_service
                .get_user_effective_permissions(&user_id)
                .await
                .unwrap_or_else(|_| crate::auth::permissions::Permission::empty());

            let roles: Vec<String> = assignments
                .iter()
                .filter(|a| a.is_active)
                .map(|a| a.role_name.clone())
                .collect();

            let response = UserPermissionsResponse {
                user_id: user_id.clone(),
                username: assignments
                    .first()
                    .map(|a| a.username.clone())
                    .unwrap_or_else(|| "unknown".to_string()),
                roles,
                effective_permissions: effective_permissions
                    .permission_names()
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                role_assignments: assignments,
            };

            Ok(Json(ApiResponse::success(response)))
        }
        Err(e) => {
            let (status, message) = match e {
                crate::auth::RbacError::UserNotFound(msg) => (StatusCode::NOT_FOUND, msg),
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to get user permissions".to_string(),
                ),
            };
            Err((status, Json(ApiResponse::<()>::error(message))))
        }
    }
}

/// Get audit logs for role management operations
pub async fn get_audit_logs(
    State(rbac_service): State<Arc<RbacService>>,
    Query(params): Query<AuditQueryParams>,
) -> Result<Json<ApiResponse<Vec<crate::models::AuditLogEntry>>>, (StatusCode, Json<ApiResponse<()>>)>
{
    match rbac_service.query_audit_logs(params).await {
        Ok(logs) => Ok(Json(ApiResponse::success(logs))),
        Err(e) => {
            let message = format!("Failed to query audit logs: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<()>::error(message)),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{permissions::Permission, RbacConfig};
    use axum_test::TestServer;
    use dbx_adapter::redis::client::RedisPool;
    use std::sync::Arc;

    fn create_test_rbac_config() -> RbacConfig {
        RbacConfig {
            audit_enabled: true,
            audit_retention_days: 30,
            max_role_inheritance_depth: 3,
            performance_cache_ttl_seconds: 60,
            default_assignment_ttl_days: Some(90),
        }
    }

    #[test]
    fn test_rbac_config_creation() {
        let config = create_test_rbac_config();
        assert!(config.audit_enabled);
        assert_eq!(config.audit_retention_days, 30);
        assert_eq!(config.max_role_inheritance_depth, 3);
        assert_eq!(config.performance_cache_ttl_seconds, 60);
        assert_eq!(config.default_assignment_ttl_days, Some(90));
    }

    #[test]
    fn test_role_request_validation() {
        // Test CreateRoleRequest validation
        let create_request = CreateRoleRequest {
            name: "test_role".to_string(),
            description: "A test role".to_string(),
            permissions: vec!["string:get".to_string(), "hash:set".to_string()],
            inherits_from: Some(vec!["user".to_string()]),
        };

        assert_eq!(create_request.name, "test_role");
        assert_eq!(create_request.permissions.len(), 2);
        assert!(create_request.inherits_from.is_some());

        // Test UpdateRoleRequest validation
        let update_request = UpdateRoleRequest {
            description: Some("Updated description".to_string()),
            permissions: Some(vec!["admin:ping".to_string()]),
            inherits_from: Some(vec![]),
        };

        assert!(update_request.description.is_some());
        assert!(update_request.permissions.is_some());
        assert_eq!(update_request.inherits_from.as_ref().unwrap().len(), 0);
    }

    #[test]
    fn test_role_response_serialization() {
        let role_response = RoleResponse {
            name: "test_role".to_string(),
            description: "Test role".to_string(),
            permissions: vec!["string:get".to_string()],
            inherits_from: vec![],
            is_default: false,
            is_system: false,
            effective_permissions: vec!["string:get".to_string()],
        };

        let serialized = serde_json::to_string(&role_response).unwrap();
        let deserialized: RoleResponse = serde_json::from_str(&serialized).unwrap();
        assert_eq!(role_response.name, deserialized.name);
        assert_eq!(deserialized.permissions.len(), 1);
        assert!(!deserialized.is_system);
    }

    #[test]
    fn test_assign_role_request_validation() {
        let assign_request = AssignRoleRequest {
            user_id: "user123".to_string(),
            role_name: "admin".to_string(),
            expires_in_days: Some(30),
            metadata: Some(serde_json::json!({"department": "engineering"})),
        };

        assert_eq!(assign_request.user_id, "user123");
        assert_eq!(assign_request.role_name, "admin");
        assert_eq!(assign_request.expires_in_days, Some(30));
        assert!(assign_request.metadata.is_some());
    }

    #[test]
    fn test_revoke_role_request_validation() {
        let revoke_request = RevokeRoleRequest {
            user_id: "user123".to_string(),
            role_name: "admin".to_string(),
            reason: Some("Role no longer needed".to_string()),
        };

        assert_eq!(revoke_request.user_id, "user123");
        assert_eq!(revoke_request.role_name, "admin");
        assert!(revoke_request.reason.is_some());
    }

    #[test]
    fn test_user_permissions_response() {
        use crate::models::UserRoleAssignment;
        use chrono::Utc;

        let assignment = UserRoleAssignment {
            user_id: "user123".to_string(),
            username: "testuser".to_string(),
            role_name: "user".to_string(),
            assigned_by: "admin".to_string(),
            assigned_at: Utc::now(),
            expires_at: None,
            is_active: true,
            metadata: None,
        };

        let permissions_response = UserPermissionsResponse {
            user_id: "user123".to_string(),
            username: "testuser".to_string(),
            roles: vec!["user".to_string(), "editor".to_string()],
            effective_permissions: vec!["string:get".to_string(), "string:set".to_string()],
            role_assignments: vec![assignment],
        };

        assert_eq!(permissions_response.user_id, "user123");
        assert_eq!(permissions_response.username, "testuser");
        assert_eq!(permissions_response.roles.len(), 2);
        assert_eq!(permissions_response.effective_permissions.len(), 2);
        assert_eq!(permissions_response.role_assignments.len(), 1);
        assert!(permissions_response.roles.contains(&"user".to_string()));
    }
}
