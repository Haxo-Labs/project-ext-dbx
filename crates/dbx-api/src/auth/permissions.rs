use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Database operation permission types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PermissionType {
    // String Operations
    StringGet,
    StringSet,
    StringDelete,
    StringExists,
    StringIncr,
    StringDecr,
    StringAppend,
    StringMget,
    StringMset,

    // Hash Operations
    HashGet,
    HashSet,
    HashDelete,
    HashExists,
    HashKeys,
    HashValues,
    HashAll,
    HashLength,
    HashIncr,

    // Set Operations
    SetAdd,
    SetRemove,
    SetMembers,
    SetExists,
    SetLength,
    SetUnion,
    SetIntersect,
    SetDiff,

    // Sorted Set Operations
    ZsetAdd,
    ZsetRemove,
    ZsetScore,
    ZsetRank,
    ZsetRange,
    ZsetCount,

    // List Operations
    ListPush,
    ListPop,
    ListGet,
    ListSet,
    ListLength,
    ListRange,

    // Bitmap Operations
    BitmapGet,
    BitmapSet,
    BitmapCount,
    BitmapPos,

    // Stream Operations
    StreamRead,
    StreamWrite,
    StreamDelete,
    StreamInfo,

    // Query Operations
    QueryExecute,
    QueryExplain,

    // Admin Operations
    AdminPing,
    AdminInfo,
    AdminFlush,
    AdminConfig,
    AdminStats,
    AdminBackup,
    AdminRestore,

    // Meta Operations
    KeyExists,
    KeyDelete,
    KeyExpire,
    KeyTtl,
    KeyScan,

    // Role Management
    RoleManage,
    UserManage,
    AuditView,
}

impl PermissionType {
    pub fn to_string(&self) -> &'static str {
        match self {
            PermissionType::StringGet => "string:get",
            PermissionType::StringSet => "string:set",
            PermissionType::StringDelete => "string:delete",
            PermissionType::StringExists => "string:exists",
            PermissionType::StringIncr => "string:incr",
            PermissionType::StringDecr => "string:decr",
            PermissionType::StringAppend => "string:append",
            PermissionType::StringMget => "string:mget",
            PermissionType::StringMset => "string:mset",

            PermissionType::HashGet => "hash:get",
            PermissionType::HashSet => "hash:set",
            PermissionType::HashDelete => "hash:delete",
            PermissionType::HashExists => "hash:exists",
            PermissionType::HashKeys => "hash:keys",
            PermissionType::HashValues => "hash:values",
            PermissionType::HashAll => "hash:all",
            PermissionType::HashLength => "hash:length",
            PermissionType::HashIncr => "hash:incr",

            PermissionType::SetAdd => "set:add",
            PermissionType::SetRemove => "set:remove",
            PermissionType::SetMembers => "set:members",
            PermissionType::SetExists => "set:exists",
            PermissionType::SetLength => "set:length",
            PermissionType::SetUnion => "set:union",
            PermissionType::SetIntersect => "set:intersect",
            PermissionType::SetDiff => "set:diff",

            PermissionType::ZsetAdd => "zset:add",
            PermissionType::ZsetRemove => "zset:remove",
            PermissionType::ZsetScore => "zset:score",
            PermissionType::ZsetRank => "zset:rank",
            PermissionType::ZsetRange => "zset:range",
            PermissionType::ZsetCount => "zset:count",

            PermissionType::ListPush => "list:push",
            PermissionType::ListPop => "list:pop",
            PermissionType::ListGet => "list:get",
            PermissionType::ListSet => "list:set",
            PermissionType::ListLength => "list:length",
            PermissionType::ListRange => "list:range",

            PermissionType::BitmapGet => "bitmap:get",
            PermissionType::BitmapSet => "bitmap:set",
            PermissionType::BitmapCount => "bitmap:count",
            PermissionType::BitmapPos => "bitmap:pos",

            PermissionType::StreamRead => "stream:read",
            PermissionType::StreamWrite => "stream:write",
            PermissionType::StreamDelete => "stream:delete",
            PermissionType::StreamInfo => "stream:info",

            PermissionType::QueryExecute => "query:execute",
            PermissionType::QueryExplain => "query:explain",

            PermissionType::AdminPing => "admin:ping",
            PermissionType::AdminInfo => "admin:info",
            PermissionType::AdminFlush => "admin:flush",
            PermissionType::AdminConfig => "admin:config",
            PermissionType::AdminStats => "admin:stats",
            PermissionType::AdminBackup => "admin:backup",
            PermissionType::AdminRestore => "admin:restore",

            PermissionType::KeyExists => "key:exists",
            PermissionType::KeyDelete => "key:delete",
            PermissionType::KeyExpire => "key:expire",
            PermissionType::KeyTtl => "key:ttl",
            PermissionType::KeyScan => "key:scan",

            PermissionType::RoleManage => "role:manage",
            PermissionType::UserManage => "user:manage",
            PermissionType::AuditView => "audit:view",
        }
    }

    pub fn from_name(name: &str) -> Option<PermissionType> {
        match name {
            "string:get" => Some(PermissionType::StringGet),
            "string:set" => Some(PermissionType::StringSet),
            "string:delete" => Some(PermissionType::StringDelete),
            "string:exists" => Some(PermissionType::StringExists),
            "string:incr" => Some(PermissionType::StringIncr),
            "string:decr" => Some(PermissionType::StringDecr),
            "string:append" => Some(PermissionType::StringAppend),
            "string:mget" => Some(PermissionType::StringMget),
            "string:mset" => Some(PermissionType::StringMset),

            "hash:get" => Some(PermissionType::HashGet),
            "hash:set" => Some(PermissionType::HashSet),
            "hash:delete" => Some(PermissionType::HashDelete),
            "hash:exists" => Some(PermissionType::HashExists),
            "hash:keys" => Some(PermissionType::HashKeys),
            "hash:values" => Some(PermissionType::HashValues),
            "hash:all" => Some(PermissionType::HashAll),
            "hash:length" => Some(PermissionType::HashLength),
            "hash:incr" => Some(PermissionType::HashIncr),

            "set:add" => Some(PermissionType::SetAdd),
            "set:remove" => Some(PermissionType::SetRemove),
            "set:members" => Some(PermissionType::SetMembers),
            "set:exists" => Some(PermissionType::SetExists),
            "set:length" => Some(PermissionType::SetLength),
            "set:union" => Some(PermissionType::SetUnion),
            "set:intersect" => Some(PermissionType::SetIntersect),
            "set:diff" => Some(PermissionType::SetDiff),

            "zset:add" => Some(PermissionType::ZsetAdd),
            "zset:remove" => Some(PermissionType::ZsetRemove),
            "zset:score" => Some(PermissionType::ZsetScore),
            "zset:rank" => Some(PermissionType::ZsetRank),
            "zset:range" => Some(PermissionType::ZsetRange),
            "zset:count" => Some(PermissionType::ZsetCount),

            "list:push" => Some(PermissionType::ListPush),
            "list:pop" => Some(PermissionType::ListPop),
            "list:get" => Some(PermissionType::ListGet),
            "list:set" => Some(PermissionType::ListSet),
            "list:length" => Some(PermissionType::ListLength),
            "list:range" => Some(PermissionType::ListRange),

            "bitmap:get" => Some(PermissionType::BitmapGet),
            "bitmap:set" => Some(PermissionType::BitmapSet),
            "bitmap:count" => Some(PermissionType::BitmapCount),
            "bitmap:pos" => Some(PermissionType::BitmapPos),

            "stream:read" => Some(PermissionType::StreamRead),
            "stream:write" => Some(PermissionType::StreamWrite),
            "stream:delete" => Some(PermissionType::StreamDelete),
            "stream:info" => Some(PermissionType::StreamInfo),

            "query:execute" => Some(PermissionType::QueryExecute),
            "query:explain" => Some(PermissionType::QueryExplain),

            "admin:ping" => Some(PermissionType::AdminPing),
            "admin:info" => Some(PermissionType::AdminInfo),
            "admin:flush" => Some(PermissionType::AdminFlush),
            "admin:config" => Some(PermissionType::AdminConfig),
            "admin:stats" => Some(PermissionType::AdminStats),
            "admin:backup" => Some(PermissionType::AdminBackup),
            "admin:restore" => Some(PermissionType::AdminRestore),

            "key:exists" => Some(PermissionType::KeyExists),
            "key:delete" => Some(PermissionType::KeyDelete),
            "key:expire" => Some(PermissionType::KeyExpire),
            "key:ttl" => Some(PermissionType::KeyTtl),
            "key:scan" => Some(PermissionType::KeyScan),

            "role:manage" => Some(PermissionType::RoleManage),
            "user:manage" => Some(PermissionType::UserManage),
            "audit:view" => Some(PermissionType::AuditView),

            _ => None,
        }
    }

    pub fn permission_names(&self) -> Vec<&'static str> {
        vec![self.to_string()]
    }
}

/// Permission set using HashSet for operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    permissions: HashSet<PermissionType>,
}

impl Permission {
    /// Create empty permission set
    pub fn empty() -> Self {
        Self {
            permissions: HashSet::new(),
        }
    }

    /// Check if permission set is empty
    pub fn is_empty(&self) -> bool {
        self.permissions.is_empty()
    }

    /// Create permission with single permission type
    pub fn single(permission: PermissionType) -> Self {
        let mut permissions = HashSet::new();
        permissions.insert(permission);
        Self { permissions }
    }

    /// Create permission with multiple permissions
    pub fn from_types(types: Vec<PermissionType>) -> Self {
        Self {
            permissions: types.into_iter().collect(),
        }
    }

    /// Check if permission contains another permission
    pub fn contains(&self, other: &Permission) -> bool {
        other.permissions.is_subset(&self.permissions)
    }

    /// Check if permission contains a specific permission type
    pub fn contains_type(&self, permission_type: &PermissionType) -> bool {
        self.permissions.contains(permission_type)
    }

    /// Add a permission type
    pub fn add(&mut self, permission: PermissionType) {
        self.permissions.insert(permission);
    }

    /// Union with another permission set
    pub fn union(&self, other: &Permission) -> Permission {
        let mut result = self.clone();
        result.permissions.extend(other.permissions.iter().cloned());
        result
    }

    /// Union assignment operator
    pub fn union_assign(&mut self, other: &Permission) {
        self.permissions.extend(other.permissions.iter().cloned());
    }

    /// Get all permission names as strings
    pub fn permission_names(&self) -> Vec<&'static str> {
        self.permissions.iter().map(|p| p.to_string()).collect()
    }

    /// Parse permission from string name
    pub fn from_name(name: &str) -> Option<Permission> {
        PermissionType::from_name(name).map(|p| Self::single(p))
    }

    /// Predefined permission constants
    pub const STRING_GET: PermissionType = PermissionType::StringGet;
    pub const STRING_SET: PermissionType = PermissionType::StringSet;
    pub const HASH_GET: PermissionType = PermissionType::HashGet;
    pub const HASH_SET: PermissionType = PermissionType::HashSet;
    pub const SET_MEMBERS: PermissionType = PermissionType::SetMembers;
    pub const SET_ADD: PermissionType = PermissionType::SetAdd;
    pub const ADMIN_PING: PermissionType = PermissionType::AdminPing;
    pub const ADMIN_FLUSH: PermissionType = PermissionType::AdminFlush;
    pub const ROLE_MANAGE: PermissionType = PermissionType::RoleManage;
    pub const AUDIT_VIEW: PermissionType = PermissionType::AuditView;

    /// Predefined permission groups
    pub fn read_only() -> Self {
        Self::from_types(vec![
            PermissionType::StringGet,
            PermissionType::StringExists,
            PermissionType::StringMget,
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
            PermissionType::BitmapPos,
            PermissionType::StreamRead,
            PermissionType::StreamInfo,
            PermissionType::QueryExecute,
            PermissionType::QueryExplain,
            PermissionType::KeyExists,
            PermissionType::KeyTtl,
            PermissionType::KeyScan,
        ])
    }

    pub fn read_write() -> Self {
        let mut permission = Self::read_only();
        permission.permissions.extend(vec![
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
        ]);
        permission
    }

    pub fn admin() -> Self {
        let mut permission = Self::read_write();
        permission.permissions.extend(vec![
            PermissionType::AdminPing,
            PermissionType::AdminInfo,
            PermissionType::AdminFlush,
            PermissionType::AdminConfig,
            PermissionType::AdminStats,
            PermissionType::AdminBackup,
            PermissionType::AdminRestore,
            PermissionType::RoleManage,
            PermissionType::UserManage,
            PermissionType::AuditView,
        ]);
        permission
    }

    // Convenience constants for groups
    pub const READ_ONLY: fn() -> Permission = Permission::read_only;
    pub const READ_WRITE: fn() -> Permission = Permission::read_write;
    pub const ADMIN: fn() -> Permission = Permission::admin;
}

impl std::ops::BitOrAssign for Permission {
    fn bitor_assign(&mut self, rhs: Permission) {
        self.union_assign(&rhs);
    }
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.permission_names().join(","))
    }
}

/// Role definition with permissions and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub name: String,
    pub description: String,
    pub permissions: Permission,
    pub inherits_from: Vec<String>,
    pub is_default: bool,
    pub is_system: bool,
}

impl Role {
    /// Create a new role
    pub fn new(name: String, description: String, permissions: Permission) -> Self {
        Self {
            name,
            description,
            permissions,
            inherits_from: Vec::new(),
            is_default: false,
            is_system: false,
        }
    }

    /// Add role inheritance
    pub fn inherit_from(mut self, parent_role: String) -> Self {
        self.inherits_from.push(parent_role);
        self
    }

    /// Mark as default role
    pub fn as_default(mut self) -> Self {
        self.is_default = true;
        self
    }

    /// Mark as system role (cannot be deleted)
    pub fn as_system(mut self) -> Self {
        self.is_system = true;
        self
    }

    /// Compute effective permissions including inheritance
    pub fn effective_permissions(&self, role_registry: &RoleRegistry) -> Permission {
        let mut effective = self.permissions.clone();

        for parent_name in &self.inherits_from {
            if let Some(parent_role) = role_registry.get_role(parent_name) {
                effective = effective.union(&parent_role.effective_permissions(role_registry));
            }
        }

        effective
    }
}

/// Role registry for managing role definitions
#[derive(Debug, Clone)]
pub struct RoleRegistry {
    roles: HashMap<String, Role>,
}

impl RoleRegistry {
    /// Create a new role registry with default roles
    pub fn new() -> Self {
        let mut registry = Self {
            roles: HashMap::new(),
        };

        registry.register_default_roles();
        registry
    }

    /// Register default system roles
    pub fn register_default_roles(&mut self) {
        // ReadOnly role
        let readonly_role = Role::new(
            "readonly".to_string(),
            "Read-only access to all data operations".to_string(),
            Permission::read_only(),
        )
        .as_system()
        .as_default();

        // User role
        let user_role = Role::new(
            "user".to_string(),
            "Standard user with read-write access to data operations".to_string(),
            Permission::read_write(),
        )
        .as_system();

        // Admin role
        let admin_role = Role::new(
            "admin".to_string(),
            "Administrator with full system access".to_string(),
            Permission::admin(),
        )
        .as_system();

        self.roles.insert("readonly".to_string(), readonly_role);
        self.roles.insert("user".to_string(), user_role);
        self.roles.insert("admin".to_string(), admin_role);
    }

    /// Register a new role
    pub fn register_role(&mut self, role: Role) {
        self.roles.insert(role.name.clone(), role);
    }

    /// Get a role by name
    pub fn get_role(&self, name: &str) -> Option<&Role> {
        self.roles.get(name)
    }

    /// Remove a role (if not system role)
    pub fn remove_role(&mut self, name: &str) -> Result<(), String> {
        if let Some(role) = self.roles.get(name) {
            if role.is_system {
                return Err("Cannot remove system role".to_string());
            }
        }

        self.roles.remove(name);
        Ok(())
    }

    /// List all roles
    pub fn list_roles(&self) -> Vec<&Role> {
        self.roles.values().collect()
    }

    /// Get effective permissions for a role
    pub fn get_effective_permissions(&self, role_name: &str) -> Option<Permission> {
        self.get_role(role_name)
            .map(|role| role.effective_permissions(self))
    }

    /// Check if a role exists
    pub fn has_role(&self, name: &str) -> bool {
        self.roles.contains_key(name)
    }
}

impl Default for RoleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let hash_perms =
            Permission::from_types(vec![PermissionType::HashGet, PermissionType::HashSet]);

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
        // Test basic role creation
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

        // Create a hierarchy: base -> intermediate -> advanced
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

        let advanced_role = Role::new(
            "advanced".to_string(),
            "Advanced role".to_string(),
            Permission::single(PermissionType::HashGet),
        )
        .inherit_from("intermediate".to_string());

        registry.register_role(base_role);
        registry.register_role(intermediate_role);
        registry.register_role(advanced_role);

        // Test that advanced role has all permissions through inheritance chain
        let advanced_perms = registry.get_effective_permissions("advanced").unwrap();
        assert!(advanced_perms.contains_type(&PermissionType::StringGet)); // From base
        assert!(advanced_perms.contains_type(&PermissionType::StringSet)); // From intermediate
        assert!(advanced_perms.contains_type(&PermissionType::HashGet)); // Own permission

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

        // Create inheritance chain: base -> intermediate -> advanced
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

        let advanced_role = Role::new(
            "advanced".to_string(),
            "Advanced role".to_string(),
            Permission::single(PermissionType::HashGet),
        )
        .inherit_from("intermediate".to_string());

        registry.register_role(base_role);
        registry.register_role(intermediate_role);
        registry.register_role(advanced_role);

        // Test inheritance chain
        let advanced = registry.get_role("advanced").unwrap();
        let effective_perms = advanced.effective_permissions(&registry);

        // Advanced should have all permissions through inheritance chain
        assert!(effective_perms.contains_type(&PermissionType::HashGet)); // Own
        assert!(effective_perms.contains_type(&PermissionType::StringSet)); // From intermediate
        assert!(effective_perms.contains_type(&PermissionType::StringGet)); // From base

        // Test intermediate role doesn't inherit "up" the chain
        let intermediate = registry.get_role("intermediate").unwrap();
        let intermediate_perms = intermediate.effective_permissions(&registry);
        assert!(intermediate_perms.contains_type(&PermissionType::StringSet)); // Own
        assert!(intermediate_perms.contains_type(&PermissionType::StringGet)); // From base
        assert!(!intermediate_perms.contains_type(&PermissionType::HashGet)); // Not from advanced
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

        let perm_set2 =
            Permission::from_types(vec![PermissionType::HashGet, PermissionType::HashSet]);

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
}
