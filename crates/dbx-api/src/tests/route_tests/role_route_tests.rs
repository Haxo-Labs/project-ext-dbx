//! Role management route handler tests

use crate::auth::RbacConfig;
use crate::models::{
    AssignRoleRequest, CreateRoleRequest, RevokeRoleRequest, RoleResponse, UpdateRoleRequest,
    UserPermissionsResponse, UserRoleAssignment,
};
use chrono::Utc;

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
        description: Some("A test role".to_string()),
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
        expires_at: None,
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
