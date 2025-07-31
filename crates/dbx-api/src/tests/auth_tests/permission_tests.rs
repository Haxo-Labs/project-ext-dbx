//! Permission system tests

use crate::auth::permissions::*;
use crate::models::UserRole;

#[test]
fn test_all_permission_types_completeness() {
    // Test that all permission types can be created and are valid
    let all_permissions = vec![
        // String operations
        PermissionType::StringGet,
        PermissionType::StringSet,
        PermissionType::StringDelete,
        PermissionType::StringExists,
        PermissionType::StringIncr,
        PermissionType::StringDecr,
        PermissionType::StringAppend,
        PermissionType::StringMget,
        PermissionType::StringMset,
        // Hash operations
        PermissionType::HashGet,
        PermissionType::HashSet,
        PermissionType::HashDelete,
        PermissionType::HashExists,
        PermissionType::HashKeys,
        PermissionType::HashValues,
        PermissionType::HashAll,
        PermissionType::HashLength,
        PermissionType::HashIncr,
        // Set operations
        PermissionType::SetAdd,
        PermissionType::SetRemove,
        PermissionType::SetMembers,
        PermissionType::SetExists,
        PermissionType::SetLength,
        PermissionType::SetUnion,
        PermissionType::SetIntersect,
        PermissionType::SetDiff,
        // Sorted Set operations
        PermissionType::ZsetAdd,
        PermissionType::ZsetRemove,
        PermissionType::ZsetScore,
        PermissionType::ZsetRank,
        PermissionType::ZsetRange,
        PermissionType::ZsetCount,
        // List operations
        PermissionType::ListPush,
        PermissionType::ListPop,
        PermissionType::ListGet,
        PermissionType::ListSet,
        PermissionType::ListLength,
        PermissionType::ListRange,
        // Bitmap operations
        PermissionType::BitmapGet,
        PermissionType::BitmapSet,
        PermissionType::BitmapCount,
        PermissionType::BitmapPos,
        // Stream operations
        PermissionType::StreamRead,
        PermissionType::StreamWrite,
        PermissionType::StreamDelete,
        PermissionType::StreamInfo,
        // Query operations
        PermissionType::QueryExecute,
        PermissionType::QueryExplain,
        // Generic operations
        PermissionType::KeyExists,
        PermissionType::KeyDelete,
        PermissionType::KeyExpire,
        PermissionType::KeyTtl,
        PermissionType::KeyScan,
        // Admin operations
        PermissionType::AdminPing,
        PermissionType::AdminInfo,
        PermissionType::AdminFlush,
        PermissionType::AdminConfig,
        PermissionType::AdminStats,
        PermissionType::AdminBackup,
        PermissionType::AdminRestore,
        // Role and audit operations
        PermissionType::RoleManage,
        PermissionType::UserManage,
        PermissionType::AuditView,
    ];

    for permission in all_permissions {
        // Test that each permission has a valid string representation
        let permission_str = permission.to_string();
        assert!(!permission_str.is_empty());

        // Test that it can be parsed back from string
        let parsed = PermissionType::from_name(permission_str);
        assert!(parsed.is_some());
        assert_eq!(parsed.unwrap(), permission);

        // Test that permission can be included in a Permission set
        let perm_set = Permission::single(permission.clone());
        assert!(perm_set.contains_type(&permission));
    }
}

#[test]
fn test_permission_groups_readonly() {
    let readonly_permissions = vec![
        PermissionType::StringGet,
        PermissionType::StringExists,
        PermissionType::HashGet,
        PermissionType::HashExists,
        PermissionType::HashKeys,
        PermissionType::HashValues,
        PermissionType::HashAll,
        PermissionType::HashLength,
        PermissionType::SetMembers,
        PermissionType::SetExists,
        PermissionType::SetLength,
        PermissionType::ZsetScore,
        PermissionType::ZsetRank,
        PermissionType::ZsetRange,
        PermissionType::ZsetCount,
        PermissionType::ListGet,
        PermissionType::ListLength,
        PermissionType::ListRange,
        PermissionType::BitmapGet,
        PermissionType::BitmapCount,
        PermissionType::StreamRead,
        PermissionType::StreamInfo,
        PermissionType::QueryExecute,
        PermissionType::QueryExplain,
        PermissionType::KeyExists,
        PermissionType::KeyTtl,
        PermissionType::KeyScan,
        PermissionType::AdminPing,
        PermissionType::AdminInfo,
        PermissionType::AdminStats,
    ];

    let readonly_group = Permission::from_types(readonly_permissions.clone());

    // Test readonly permissions
    for perm in readonly_permissions {
        assert!(readonly_group.contains_type(&perm));
    }

    // Test that write operations are not included
    assert!(!readonly_group.contains_type(&PermissionType::StringSet));
    assert!(!readonly_group.contains_type(&PermissionType::HashSet));
    assert!(!readonly_group.contains_type(&PermissionType::AdminFlush));
}

#[test]
fn test_permission_groups_readwrite() {
    let write_permissions = vec![
        PermissionType::StringSet,
        PermissionType::StringDelete,
        PermissionType::StringIncr,
        PermissionType::StringDecr,
        PermissionType::StringAppend,
        PermissionType::StringMset,
        PermissionType::HashSet,
        PermissionType::HashDelete,
        PermissionType::HashIncr,
        PermissionType::SetAdd,
        PermissionType::SetRemove,
        PermissionType::ZsetAdd,
        PermissionType::ZsetRemove,
        PermissionType::ListPush,
        PermissionType::ListPop,
        PermissionType::ListSet,
        PermissionType::BitmapSet,
        PermissionType::StreamWrite,
        PermissionType::StreamDelete,
        PermissionType::KeyDelete,
        PermissionType::KeyExpire,
    ];

    let write_group = Permission::from_types(write_permissions.clone());

    // Test write permissions
    for perm in write_permissions {
        assert!(write_group.contains_type(&perm));
    }

    // Test that admin operations are not included
    assert!(!write_group.contains_type(&PermissionType::AdminFlush));
    assert!(!write_group.contains_type(&PermissionType::AdminBackup));
    assert!(!write_group.contains_type(&PermissionType::RoleManage));
}

#[test]
fn test_permission_set_operations() {
    let string_perms =
        Permission::from_types(vec![PermissionType::StringGet, PermissionType::StringSet]);

    let hash_perms = Permission::from_types(vec![PermissionType::HashGet, PermissionType::HashSet]);

    // Test individual contains
    assert!(string_perms.contains_type(&PermissionType::StringGet));
    assert!(string_perms.contains_type(&PermissionType::StringSet));
    assert!(!string_perms.contains_type(&PermissionType::HashGet));

    // Test union operation
    let combined = string_perms.union(&hash_perms);
    assert!(combined.contains_type(&PermissionType::StringGet));
    assert!(combined.contains_type(&PermissionType::StringSet));
    assert!(combined.contains_type(&PermissionType::HashGet));
    assert!(combined.contains_type(&PermissionType::HashSet));

    // Test empty permission set
    let empty = Permission::empty();
    assert!(!empty.contains_type(&PermissionType::StringGet));
    assert_eq!(empty.permission_names().len(), 0);

    // Test converting to permission names
    let string_names = string_perms.permission_names();
    assert_eq!(string_names.len(), 2);
    assert!(string_names.contains(&"string:get"));
    assert!(string_names.contains(&"string:set"));
}

#[test]
fn test_permission_from_name_edge_cases() {
    // Test valid permission names
    assert_eq!(
        PermissionType::from_name("string:get"),
        Some(PermissionType::StringGet)
    );
    assert_eq!(
        PermissionType::from_name("hash:set"),
        Some(PermissionType::HashSet)
    );
    assert_eq!(
        PermissionType::from_name("admin:flush"),
        Some(PermissionType::AdminFlush)
    );

    // Test invalid permission names
    assert_eq!(PermissionType::from_name(""), None);
    assert_eq!(PermissionType::from_name("invalid"), None);
    assert_eq!(PermissionType::from_name("string:"), None);
    assert_eq!(PermissionType::from_name(":get"), None);
    assert_eq!(PermissionType::from_name("string:invalid"), None);
    assert_eq!(PermissionType::from_name("STRING:GET"), None); // Case sensitive

    // Test edge cases
    assert_eq!(PermissionType::from_name("string:get:extra"), None);
    assert_eq!(PermissionType::from_name(" string:get "), None); // Whitespace
}

#[test]
fn test_role_creation_and_validation() {
    // Test role creation
    let role = Role::new(
        "test_role".to_string(),
        "Test role description".to_string(),
        Permission::single(PermissionType::StringGet),
    );

    assert_eq!(role.name, "test_role");
    assert_eq!(role.description, "Test role description");
    assert!(role.permissions.contains_type(&PermissionType::StringGet));
    assert_eq!(role.inherits_from, Vec::<String>::new());
    assert!(!role.is_default);
    assert!(!role.is_system);

    // Test role with inheritance
    let inherited_role = Role::new(
        "inherited_role".to_string(),
        "Role that inherits from another".to_string(),
        Permission::single(PermissionType::HashGet),
    )
    .inherit_from("test_role".to_string());

    assert_eq!(inherited_role.inherits_from, vec!["test_role".to_string()]);

    // Test system role
    let system_role = Role::new(
        "system_role".to_string(),
        "System role".to_string(),
        Permission::single(PermissionType::AdminConfig),
    )
    .as_system();

    assert!(system_role.is_system);

    // Test default role
    let default_role = Role::new(
        "default_role".to_string(),
        "Default role".to_string(),
        Permission::single(PermissionType::StringGet),
    )
    .as_default();

    assert!(default_role.is_default);
}

#[test]
fn test_complex_role_inheritance() {
    let mut registry = RoleRegistry::new();

    // Create a hierarchy: base -> intermediate -> manager
    let base_role = Role::new(
        "base".to_string(),
        "Base role".to_string(),
        Permission::single(PermissionType::StringGet),
    );

    let mut intermediate_role = Role::new(
        "intermediate".to_string(),
        "Intermediate role".to_string(),
        Permission::single(PermissionType::StringSet),
    );
    intermediate_role.set_inheritance(vec!["base".to_string()]);

    let mut manager_role = Role::new(
        "manager".to_string(),
        "Manager role".to_string(),
        Permission::single(PermissionType::HashGet),
    );
    manager_role.set_inheritance(vec!["intermediate".to_string()]);

    registry.register_role(base_role);
    registry.register_role(intermediate_role);
    registry.register_role(manager_role);

    // Test that manager role has all permissions through inheritance chain
    let manager_perms = registry.get_effective_permissions("manager").unwrap();
    assert!(manager_perms.contains_type(&PermissionType::StringGet)); // From base
    assert!(manager_perms.contains_type(&PermissionType::StringSet)); // From intermediate
    assert!(manager_perms.contains_type(&PermissionType::HashGet)); // Own permission

    // Test that intermediate has base permissions
    let intermediate_perms = registry.get_effective_permissions("intermediate").unwrap();
    assert!(intermediate_perms.contains_type(&PermissionType::StringGet)); // From base
    assert!(intermediate_perms.contains_type(&PermissionType::StringSet)); // Own permission
    assert!(!intermediate_perms.contains_type(&PermissionType::HashGet)); // Not inherited down
}

#[test]
fn test_role_registry_operations() {
    let mut registry = RoleRegistry::new();

    // Test initial roles exist
    assert!(registry.has_role("admin"));
    assert!(registry.has_role("user"));
    assert!(registry.has_role("readonly"));

    // Test adding new role
    let custom_role = Role::new(
        "custom".to_string(),
        "Custom test role".to_string(),
        Permission::single(PermissionType::SetAdd),
    );

    registry.register_role(custom_role);
    assert!(registry.has_role("custom"));

    // Test listing roles
    let all_roles = registry.list_roles();
    assert!(all_roles.len() >= 4); // At least the 3 default + 1 custom
    assert!(all_roles.iter().any(|r| r.name == "custom"));

    // Test getting role details
    let custom_role_retrieved = registry.get_role("custom");
    assert!(custom_role_retrieved.is_some());
    let role = custom_role_retrieved.unwrap();
    assert_eq!(role.description, "Custom test role");
    assert!(role.permissions.contains_type(&PermissionType::SetAdd));

    // Test non-existent role
    assert!(!registry.has_role("nonexistent"));
    assert!(registry.get_role("nonexistent").is_none());
    assert!(registry.get_effective_permissions("nonexistent").is_none());
}

#[test]
fn test_permission_type_categorization() {
    // Test that permission types are correctly categorized
    let string_permissions = vec![
        PermissionType::StringGet,
        PermissionType::StringSet,
        PermissionType::StringDelete,
        PermissionType::StringMget,
        PermissionType::StringMset,
    ];

    let hash_permissions = vec![
        PermissionType::HashGet,
        PermissionType::HashSet,
        PermissionType::HashDelete,
        PermissionType::HashKeys,
    ];

    let admin_permissions = vec![
        PermissionType::AdminFlush,
        PermissionType::AdminInfo,
        PermissionType::AdminConfig,
        PermissionType::AdminBackup,
    ];

    // Test string permission names start with "string:"
    for perm in string_permissions {
        assert!(perm.to_string().starts_with("string:"));
    }

    // Test hash permission names start with "hash:"
    for perm in hash_permissions {
        assert!(perm.to_string().starts_with("hash:"));
    }

    // Test admin permission names start with "admin:"
    for perm in admin_permissions {
        assert!(perm.to_string().starts_with("admin:"));
    }
}

#[test]
fn test_default_role_configurations() {
    let registry = RoleRegistry::new();

    // Test readonly role permissions
    let readonly = registry.get_role("readonly").unwrap();
    assert!(readonly
        .permissions
        .contains_type(&PermissionType::StringGet));
    assert!(readonly.permissions.contains_type(&PermissionType::HashGet));
    assert!(readonly
        .permissions
        .contains_type(&PermissionType::SetMembers));
    assert!(!readonly
        .permissions
        .contains_type(&PermissionType::StringSet)); // No write
    assert!(!readonly
        .permissions
        .contains_type(&PermissionType::AdminFlush)); // No admin

    // Test user role permissions
    let user = registry.get_role("user").unwrap();
    assert!(user.permissions.contains_type(&PermissionType::StringGet)); // Read
    assert!(user.permissions.contains_type(&PermissionType::StringSet)); // Write
    assert!(user.permissions.contains_type(&PermissionType::HashSet)); // Write
    assert!(!user.permissions.contains_type(&PermissionType::AdminFlush)); // No admin

    // Test admin role permissions
    let admin = registry.get_role("admin").unwrap();
    assert!(admin.permissions.contains_type(&PermissionType::StringGet)); // Read
    assert!(admin.permissions.contains_type(&PermissionType::StringSet)); // Write
    assert!(admin.permissions.contains_type(&PermissionType::AdminFlush)); // Admin
    assert!(admin.permissions.contains_type(&PermissionType::AuditView)); // Audit

    // Test that all default roles are system roles
    assert!(readonly.is_system);
    assert!(user.is_system);
    assert!(admin.is_system);

    // Test that readonly is marked as default
    assert!(readonly.is_default);
    assert!(!user.is_default);
    assert!(!admin.is_default);
}

#[test]
fn test_role_inheritance_chain() {
    let mut registry = RoleRegistry::new();

    // Create inheritance chain: base -> intermediate -> manager
    let base_role = Role::new(
        "base".to_string(),
        "Base role".to_string(),
        Permission::single(PermissionType::StringGet),
    );

    let intermediate_role = Role::new(
        "intermediate".to_string(),
        "Intermediate role".to_string(),
        Permission::single(PermissionType::StringSet),
    )
    .inherit_from("base".to_string());

    let manager_role = Role::new(
        "manager".to_string(),
        "Manager role".to_string(),
        Permission::single(PermissionType::HashGet),
    )
    .inherit_from("intermediate".to_string());

    registry.register_role(base_role);
    registry.register_role(intermediate_role);
    registry.register_role(manager_role);

    // Test inheritance chain
    let manager = registry.get_role("manager").unwrap();
    let effective_perms = manager.effective_permissions(&registry);

    // Manager should have all permissions through inheritance chain
    assert!(effective_perms.contains_type(&PermissionType::HashGet)); // Own
    assert!(effective_perms.contains_type(&PermissionType::StringSet)); // From intermediate
    assert!(effective_perms.contains_type(&PermissionType::StringGet)); // From base

    // Test intermediate role doesn't inherit "up" the chain
    let intermediate = registry.get_role("intermediate").unwrap();
    let intermediate_perms = intermediate.effective_permissions(&registry);
    assert!(intermediate_perms.contains_type(&PermissionType::StringSet)); // Own
    assert!(intermediate_perms.contains_type(&PermissionType::StringGet)); // From base
    assert!(!intermediate_perms.contains_type(&PermissionType::HashGet)); // Not from manager
}

#[test]
fn test_multiple_inheritance() {
    let mut registry = RoleRegistry::new();

    // Create multiple parent roles
    let read_role = Role::new(
        "read_role".to_string(),
        "Read permissions".to_string(),
        Permission::from_types(vec![PermissionType::StringGet, PermissionType::HashGet]),
    );

    let write_role = Role::new(
        "write_role".to_string(),
        "Write permissions".to_string(),
        Permission::from_types(vec![PermissionType::StringSet, PermissionType::HashSet]),
    );

    // Create child role that inherits from both
    let readwrite_role = Role::new(
        "readwrite_role".to_string(),
        "Read-write permissions".to_string(),
        Permission::single(PermissionType::SetAdd),
    )
    .inherit_from("read_role".to_string())
    .inherit_from("write_role".to_string());

    registry.register_role(read_role);
    registry.register_role(write_role);
    registry.register_role(readwrite_role);

    // Test multiple inheritance
    let readwrite = registry.get_role("readwrite_role").unwrap();
    let effective_perms = readwrite.effective_permissions(&registry);

    // Should have permissions from both parents plus its own
    assert!(effective_perms.contains_type(&PermissionType::SetAdd)); // Own
    assert!(effective_perms.contains_type(&PermissionType::StringGet)); // From read_role
    assert!(effective_perms.contains_type(&PermissionType::HashGet)); // From read_role
    assert!(effective_perms.contains_type(&PermissionType::StringSet)); // From write_role
    assert!(effective_perms.contains_type(&PermissionType::HashSet)); // From write_role
}

#[test]
fn test_permission_constants() {
    // Test that permission constants are available
    assert_eq!(Permission::STRING_GET, PermissionType::StringGet);
    assert_eq!(Permission::STRING_SET, PermissionType::StringSet);
    assert_eq!(Permission::HASH_GET, PermissionType::HashGet);
    assert_eq!(Permission::HASH_SET, PermissionType::HashSet);
    assert_eq!(Permission::SET_MEMBERS, PermissionType::SetMembers);
    assert_eq!(Permission::SET_ADD, PermissionType::SetAdd);
    assert_eq!(Permission::ADMIN_PING, PermissionType::AdminPing);
    assert_eq!(Permission::ADMIN_FLUSH, PermissionType::AdminFlush);
}

#[test]
fn test_permission_serialization() {
    let original_permissions = vec![
        PermissionType::StringGet,
        PermissionType::HashSet,
        PermissionType::SetAdd,
        PermissionType::AdminInfo,
    ];

    let permission_set = Permission::from_types(original_permissions.clone());

    // Test serialization and deserialization
    let serialized = serde_json::to_string(&permission_set).unwrap();
    let deserialized: Permission = serde_json::from_str(&serialized).unwrap();

    // Should contain all original permissions
    for perm in original_permissions {
        assert!(deserialized.contains_type(&perm));
    }
}

#[test]
fn test_permission_union_operations() {
    let mut perm_set1 =
        Permission::from_types(vec![PermissionType::StringGet, PermissionType::StringSet]);

    let perm_set2 = Permission::from_types(vec![PermissionType::HashGet, PermissionType::HashSet]);

    // Test union_assign
    perm_set1.union_assign(&perm_set2);
    assert!(perm_set1.contains_type(&PermissionType::StringGet));
    assert!(perm_set1.contains_type(&PermissionType::StringSet));
    assert!(perm_set1.contains_type(&PermissionType::HashGet));
    assert!(perm_set1.contains_type(&PermissionType::HashSet));

    // Test add individual permission
    let mut single_perm = Permission::single(PermissionType::SetAdd);
    single_perm.add(PermissionType::SetRemove);
    assert!(single_perm.contains_type(&PermissionType::SetAdd));
    assert!(single_perm.contains_type(&PermissionType::SetRemove));
}
