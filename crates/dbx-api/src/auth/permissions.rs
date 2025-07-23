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
    fn test_permission_operations() {
        let mut perm = Permission::empty();
        perm.add(PermissionType::StringGet);
        assert!(perm.contains_type(&PermissionType::StringGet));
        assert!(!perm.contains_type(&PermissionType::StringSet));
    }

    #[test]
    fn test_permission_groups() {
        let read_only = Permission::read_only();
        assert!(read_only.contains_type(&PermissionType::StringGet));
        assert!(!read_only.contains_type(&PermissionType::StringSet));

        let read_write = Permission::read_write();
        assert!(read_write.contains_type(&PermissionType::StringGet));
        assert!(read_write.contains_type(&PermissionType::StringSet));
        assert!(!read_write.contains_type(&PermissionType::AdminFlush));

        let admin = Permission::admin();
        assert!(admin.contains_type(&PermissionType::StringGet));
        assert!(admin.contains_type(&PermissionType::StringSet));
        assert!(admin.contains_type(&PermissionType::AdminFlush));
    }

    #[test]
    fn test_permission_names() {
        let perm = Permission::from_types(vec![PermissionType::StringGet, PermissionType::HashSet]);
        let names = perm.permission_names();
        assert!(names.contains(&"string:get"));
        assert!(names.contains(&"hash:set"));
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn test_permission_from_name() {
        assert!(Permission::from_name("string:get").is_some());
        assert!(Permission::from_name("invalid").is_none());
    }

    #[test]
    fn test_role_registry() {
        let registry = RoleRegistry::new();

        assert!(registry.get_role("readonly").is_some());
        assert!(registry.get_role("user").is_some());
        assert!(registry.get_role("admin").is_some());

        let admin_perms = registry.get_effective_permissions("admin").unwrap();
        assert!(admin_perms.contains_type(&PermissionType::StringGet));
        assert!(admin_perms.contains_type(&PermissionType::AdminFlush));
    }

    #[test]
    fn test_role_inheritance() {
        let mut registry = RoleRegistry::new();

        let custom_role = Role::new(
            "custom".to_string(),
            "Custom role inheriting from user".to_string(),
            Permission::single(PermissionType::AuditView),
        )
        .inherit_from("user".to_string());

        registry.register_role(custom_role);

        let effective_perms = registry.get_effective_permissions("custom").unwrap();
        assert!(effective_perms.contains_type(&PermissionType::StringGet)); // From user
        assert!(effective_perms.contains_type(&PermissionType::StringSet)); // From user
        assert!(effective_perms.contains_type(&PermissionType::AuditView)); // Own permission
        assert!(!effective_perms.contains_type(&PermissionType::AdminFlush)); // Not inherited
    }
}
