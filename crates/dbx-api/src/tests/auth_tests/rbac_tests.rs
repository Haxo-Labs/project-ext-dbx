//! Role-based access control tests

use crate::auth::permissions::{Permission, PermissionType};
use crate::auth::rbac::*;
use crate::auth::Role;
use crate::models::{AuditEventType, AuditQueryParams, PermissionCheckContext};
use dbx_core::UniversalBackend;
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

async fn create_test_backend() -> Arc<dyn UniversalBackend> {
    crate::test_helpers::create_mock_backend()
}

#[tokio::test]
async fn test_rbac_config_default() {
    let config = RbacConfig::default();
    assert!(config.audit_enabled);
    assert_eq!(config.audit_retention_days, 90);
    assert_eq!(config.max_role_inheritance_depth, 5);
}

#[test]
fn test_rbac_error_display() {
    let error = RbacError::RoleNotFound("test".to_string());
    assert_eq!(error.to_string(), "Role not found: test");
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
fn test_permission_context_creation() {
    let context = PermissionCheckContext {
        user_id: Some("test_user".to_string()),
        username: Some("testuser".to_string()),
        role: Some("admin".to_string()),
        resource: "test_resource".to_string(),
        action: "test_action".to_string(),
        permission_required: "string:get".to_string(),
        ip_address: Some("192.168.1.1".to_string()),
        user_agent: Some("test-browser".to_string()),
    };

    assert_eq!(context.user_id, Some("test_user".to_string()));
    assert_eq!(context.resource, "test_resource");
    assert_eq!(context.action, "test_action");
    assert_eq!(context.ip_address.unwrap(), "192.168.1.1");
    assert_eq!(context.user_agent.unwrap(), "test-browser");
}

#[test]
fn test_audit_query_params_creation() {
    let params = AuditQueryParams {
        start_date: Some(chrono::Utc::now() - chrono::Duration::days(7)),
        end_date: Some(chrono::Utc::now()),
        user_id: Some("user123".to_string()),
        event_type: Some(AuditEventType::Authorization),
        resource: Some("test_resource".to_string()),
        limit: Some(50),
        offset: Some(0),
    };

    assert!(params.start_date.is_some());
    assert!(params.end_date.is_some());
    assert_eq!(params.user_id.unwrap(), "user123");
    assert_eq!(params.limit.unwrap(), 50);
    assert_eq!(params.offset.unwrap(), 0);
}

#[tokio::test]
async fn test_validate_inheritance_chain_cycle() {
    let backend = create_test_backend().await;
    let rbac = RbacService::new(backend, create_test_rbac_config());

    // Set up roles in registry: A -> B
    {
        let role_registry = rbac.get_role_registry();
        let mut registry = role_registry.write().unwrap();

        let role_a = Role::new(
            "role_a".to_string(),
            "Role A".to_string(),
            Permission::single(PermissionType::StringGet),
        );

        let role_b = Role::new(
            "role_b".to_string(),
            "Role B".to_string(),
            Permission::single(PermissionType::StringSet),
        )
        .inherit_from("role_a".to_string());

        registry.register_role(role_a);
        registry.register_role(role_b);
    }

    // Test: Try to make A inherit from B (creates cycle A -> B -> A)
    let result = rbac.validate_inheritance_chain("role_a", &["role_b".to_string()]);

    assert!(
        matches!(result, Err(RbacError::InheritanceCycle)),
        "Expected InheritanceCycle error for A -> B -> A cycle, got: {:?}",
        result
    );
}

#[tokio::test]
async fn test_validate_inheritance_chain_self_cycle() {
    let backend = create_test_backend().await;
    let rbac = RbacService::new(backend, create_test_rbac_config());

    // Test self-inheritance: A -> A
    let result = rbac.validate_inheritance_chain("role_a", &["role_a".to_string()]);

    assert!(
        matches!(result, Err(RbacError::InheritanceCycle)),
        "Expected InheritanceCycle error for self-inheritance, got: {:?}",
        result
    );
}

#[tokio::test]
async fn test_validate_inheritance_chain_deep_cycle() {
    let backend = create_test_backend().await;
    let rbac = RbacService::new(backend, create_test_rbac_config());

    // Set up deep chain: A -> B -> C -> D
    {
        let role_registry = rbac.get_role_registry();
        let mut registry = role_registry.write().unwrap();

        let role_a = Role::new(
            "role_a".to_string(),
            "Role A".to_string(),
            Permission::single(PermissionType::StringGet),
        );

        let role_b = Role::new(
            "role_b".to_string(),
            "Role B".to_string(),
            Permission::single(PermissionType::StringSet),
        )
        .inherit_from("role_a".to_string());

        let role_c = Role::new(
            "role_c".to_string(),
            "Role C".to_string(),
            Permission::single(PermissionType::HashGet),
        )
        .inherit_from("role_b".to_string());

        let role_d = Role::new(
            "role_d".to_string(),
            "Role D".to_string(),
            Permission::single(PermissionType::HashSet),
        )
        .inherit_from("role_c".to_string());

        registry.register_role(role_a);
        registry.register_role(role_b);
        registry.register_role(role_c);
        registry.register_role(role_d);
    }

    // Test: Try to make A inherit from D (creates cycle A -> B -> C -> D -> A)
    let result = rbac.validate_inheritance_chain("role_a", &["role_d".to_string()]);

    assert!(
        matches!(result, Err(RbacError::InheritanceCycle)),
        "Expected InheritanceCycle error for deep cycle, got: {:?}",
        result
    );
}

#[tokio::test]
async fn test_validate_inheritance_chain_depth_limit() {
    let backend = create_test_backend().await;
    let mut config = create_test_rbac_config();
    config.max_role_inheritance_depth = 2; // Set low depth limit
    let rbac = RbacService::new(backend, config);

    // Set up chain that exceeds depth: A -> B -> C
    {
        let role_registry = rbac.get_role_registry();
        let mut registry = role_registry.write().unwrap();

        let role_a = Role::new(
            "role_a".to_string(),
            "Role A".to_string(),
            Permission::single(PermissionType::StringGet),
        );

        let role_b = Role::new(
            "role_b".to_string(),
            "Role B".to_string(),
            Permission::single(PermissionType::StringSet),
        )
        .inherit_from("role_a".to_string());

        let role_c = Role::new(
            "role_c".to_string(),
            "Role C".to_string(),
            Permission::single(PermissionType::HashGet),
        )
        .inherit_from("role_b".to_string());

        registry.register_role(role_a);
        registry.register_role(role_b);
        registry.register_role(role_c);
    }

    // Test: Try to make D inherit from C (would exceed depth limit of 2)
    let result = rbac.validate_inheritance_chain("role_d", &["role_c".to_string()]);

    assert!(
        matches!(result, Err(RbacError::InheritanceCycle)),
        "Expected InheritanceCycle error for depth limit violation, got: {:?}",
        result
    );
}

#[tokio::test]
async fn test_validate_inheritance_chain_multiple_parents() {
    let backend = create_test_backend().await;
    let rbac = RbacService::new(backend, create_test_rbac_config());

    // Set up: A -> B, A -> C, C -> D
    {
        let role_registry = rbac.get_role_registry();
        let mut registry = role_registry.write().unwrap();

        let role_a = Role::new(
            "role_a".to_string(),
            "Role A".to_string(),
            Permission::single(PermissionType::StringGet),
        );

        let role_b = Role::new(
            "role_b".to_string(),
            "Role B".to_string(),
            Permission::single(PermissionType::StringSet),
        )
        .inherit_from("role_a".to_string());

        let role_c = Role::new(
            "role_c".to_string(),
            "Role C".to_string(),
            Permission::single(PermissionType::HashGet),
        )
        .inherit_from("role_a".to_string());

        let role_d = Role::new(
            "role_d".to_string(),
            "Role D".to_string(),
            Permission::single(PermissionType::HashSet),
        )
        .inherit_from("role_c".to_string());

        registry.register_role(role_a);
        registry.register_role(role_b);
        registry.register_role(role_c);
        registry.register_role(role_d);
    }

    // Test: Try to make A inherit from both B and D (B creates cycle, D is valid)
    let result =
        rbac.validate_inheritance_chain("role_a", &["role_b".to_string(), "role_d".to_string()]);

    assert!(
        matches!(result, Err(RbacError::InheritanceCycle)),
        "Expected InheritanceCycle error due to B creating cycle, got: {:?}",
        result
    );
}

#[tokio::test]
async fn test_validate_inheritance_chain_valid_cases() {
    let backend = create_test_backend().await;
    let rbac = RbacService::new(backend, create_test_rbac_config());

    // Set up valid chain: A -> B -> C
    {
        let role_registry = rbac.get_role_registry();
        let mut registry = role_registry.write().unwrap();

        let role_a = Role::new(
            "role_a".to_string(),
            "Role A".to_string(),
            Permission::single(PermissionType::StringGet),
        );

        let role_b = Role::new(
            "role_b".to_string(),
            "Role B".to_string(),
            Permission::single(PermissionType::StringSet),
        )
        .inherit_from("role_a".to_string());

        let role_c = Role::new(
            "role_c".to_string(),
            "Role C".to_string(),
            Permission::single(PermissionType::HashGet),
        )
        .inherit_from("role_b".to_string());

        registry.register_role(role_a);
        registry.register_role(role_b);
        registry.register_role(role_c);
    }

    // Test: Valid inheritance - D inheriting from A (no cycle)
    let result = rbac.validate_inheritance_chain("role_d", &["role_a".to_string()]);
    assert!(
        result.is_ok(),
        "Expected valid inheritance to succeed, got: {:?}",
        result
    );

    // Test: Valid inheritance - E inheriting from B (no cycle)
    let result = rbac.validate_inheritance_chain("role_e", &["role_b".to_string()]);
    assert!(
        result.is_ok(),
        "Expected valid inheritance to succeed, got: {:?}",
        result
    );

    // Test: Valid inheritance - F inheriting from non-existent role (should be ok for validation)
    let result = rbac.validate_inheritance_chain("role_f", &["nonexistent".to_string()]);
    assert!(
        result.is_ok(),
        "Expected inheritance from non-existent role to be valid for validation, got: {:?}",
        result
    );
}
