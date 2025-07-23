use crate::{
    auth::permissions::{Permission, PermissionType, Role, RoleRegistry},
    models::{
        AuditEventType, AuditLogEntry, AuditQueryParams, PermissionCheckContext, UserRoleAssignment,
    },
};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use dbx_adapter::redis::client::RedisPool;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use thiserror::Error;
use uuid::Uuid;

/// RBAC service errors
#[derive(Debug, Error)]
pub enum RbacError {
    #[error("Role not found: {0}")]
    RoleNotFound(String),
    #[error("User not found: {0}")]
    UserNotFound(String),
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    #[error("Role assignment not found")]
    AssignmentNotFound,
    #[error("Role is system role and cannot be modified")]
    SystemRoleModification,
    #[error("Invalid role name: {0}")]
    InvalidRoleName(String),
    #[error("Role inheritance cycle detected")]
    InheritanceCycle,
    #[error("Redis error: {0}")]
    RedisError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// RBAC service configuration
#[derive(Debug, Clone, Deserialize)]
pub struct RbacConfig {
    pub audit_enabled: bool,
    pub audit_retention_days: u32,
    pub max_role_inheritance_depth: u8,
    pub performance_cache_ttl_seconds: u64,
    pub default_assignment_ttl_days: Option<u32>,
}

impl Default for RbacConfig {
    fn default() -> Self {
        Self {
            audit_enabled: true,
            audit_retention_days: 90,
            max_role_inheritance_depth: 5,
            performance_cache_ttl_seconds: 300,
            default_assignment_ttl_days: None,
        }
    }
}

/// RBAC service for role management and permission checking
#[derive(Clone)]
pub struct RbacService {
    redis_pool: Arc<RedisPool>,
    role_registry: Arc<std::sync::RwLock<RoleRegistry>>,
    config: RbacConfig,
}

impl std::fmt::Debug for RbacService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RbacService")
            .field("role_registry", &self.role_registry)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl RbacService {
    /// Create a new RBAC service
    pub fn new(redis_pool: Arc<RedisPool>, config: RbacConfig) -> Self {
        let role_registry = Arc::new(std::sync::RwLock::new(RoleRegistry::new()));
        Self {
            redis_pool,
            role_registry,
            config,
        }
    }

    /// Check if user has specific permission
    pub async fn check_permission(
        &self,
        user_id: &str,
        permission: PermissionType,
        context: PermissionCheckContext,
    ) -> Result<bool, RbacError> {
        let user_permissions = self.get_user_effective_permissions(user_id).await?;
        let has_permission = user_permissions.contains_type(&permission);

        // Audit log the permission check
        if self.config.audit_enabled {
            self.log_audit_event(AuditLogEntry {
                id: Uuid::new_v4().to_string(),
                timestamp: Utc::now(),
                event_type: if has_permission {
                    AuditEventType::AccessGranted
                } else {
                    AuditEventType::AccessDenied
                },
                user_id: Some(user_id.to_string()),
                username: context.username.clone(),
                resource: context.resource,
                action: context.action,
                permission_required: Some(context.permission_required),
                permission_granted: has_permission,
                role: context.role,
                ip_address: context.ip_address,
                user_agent: context.user_agent,
                metadata: None,
            })
            .await?;
        }

        Ok(has_permission)
    }

    /// Get effective permissions for a user
    pub async fn get_user_effective_permissions(
        &self,
        user_id: &str,
    ) -> Result<Permission, RbacError> {
        let assignments = self.get_user_role_assignments(user_id).await?;
        let mut effective_permissions = Permission::empty();

        let role_registry = self.role_registry.read().unwrap();

        for assignment in assignments {
            if assignment.is_active {
                // Check if assignment has expired
                if let Some(expires_at) = assignment.expires_at {
                    if Utc::now() > expires_at {
                        continue;
                    }
                }

                if let Some(role_permissions) =
                    role_registry.get_effective_permissions(&assignment.role_name)
                {
                    effective_permissions = effective_permissions.union(&role_permissions);
                }
            }
        }

        Ok(effective_permissions)
    }

    /// Assign role to user
    pub async fn assign_role(
        &self,
        user_id: &str,
        username: &str,
        role_name: &str,
        assigned_by: &str,
        expires_in_days: Option<u32>,
        metadata: Option<serde_json::Value>,
    ) -> Result<UserRoleAssignment, RbacError> {
        // Verify role exists
        {
            let role_registry = self.role_registry.read().unwrap();
            if role_registry.get_role(role_name).is_none() {
                return Err(RbacError::RoleNotFound(role_name.to_string()));
            }
        }

        let expires_at = expires_in_days
            .or(self.config.default_assignment_ttl_days)
            .map(|days| Utc::now() + Duration::days(days as i64));

        let assignment = UserRoleAssignment {
            user_id: user_id.to_string(),
            username: username.to_string(),
            role_name: role_name.to_string(),
            assigned_by: assigned_by.to_string(),
            assigned_at: Utc::now(),
            expires_at,
            is_active: true,
            metadata,
        };

        self.store_user_role_assignment(&assignment).await?;

        // Audit log the assignment
        if self.config.audit_enabled {
            self.log_audit_event(AuditLogEntry {
                id: Uuid::new_v4().to_string(),
                timestamp: Utc::now(),
                event_type: AuditEventType::RoleAssignment,
                user_id: Some(user_id.to_string()),
                username: Some(username.to_string()),
                resource: format!("user:{}", user_id),
                action: "assign_role".to_string(),
                permission_required: Some("role:manage".to_string()),
                permission_granted: true,
                role: Some(role_name.to_string()),
                ip_address: None,
                user_agent: None,
                metadata: Some(serde_json::json!({
                    "assigned_by": assigned_by,
                    "expires_at": expires_at
                })),
            })
            .await?;
        }

        Ok(assignment)
    }

    /// Revoke role from user
    pub async fn revoke_role(
        &self,
        user_id: &str,
        role_name: &str,
        revoked_by: &str,
        reason: Option<String>,
    ) -> Result<(), RbacError> {
        let assignment_key = format!("rbac:assignment:{}:{}", user_id, role_name);

        // Get existing assignment
        let mut assignment: UserRoleAssignment = self
            .get_redis_value(&assignment_key)
            .await?
            .ok_or(RbacError::AssignmentNotFound)?;

        // Mark as inactive
        assignment.is_active = false;

        // Store updated assignment
        self.set_redis_value(&assignment_key, &assignment, None)
            .await?;

        // Remove from user's active roles set
        let user_roles_key = format!("rbac:user_roles:{}", user_id);
        self.remove_from_redis_set(&user_roles_key, role_name)
            .await?;

        // Audit log the revocation
        if self.config.audit_enabled {
            self.log_audit_event(AuditLogEntry {
                id: Uuid::new_v4().to_string(),
                timestamp: Utc::now(),
                event_type: AuditEventType::RoleRevocation,
                user_id: Some(user_id.to_string()),
                username: Some(assignment.username),
                resource: format!("user:{}", user_id),
                action: "revoke_role".to_string(),
                permission_required: Some("role:manage".to_string()),
                permission_granted: true,
                role: Some(role_name.to_string()),
                ip_address: None,
                user_agent: None,
                metadata: Some(serde_json::json!({
                    "revoked_by": revoked_by,
                    "reason": reason
                })),
            })
            .await?;
        }

        Ok(())
    }

    /// Create custom role
    pub async fn create_role(
        &self,
        name: &str,
        description: &str,
        permissions: Vec<String>,
        inherits_from: Option<Vec<String>>,
        created_by: &str,
    ) -> Result<Role, RbacError> {
        // Validate role name
        if name.contains(':') || name.is_empty() || name.len() > 50 {
            return Err(RbacError::InvalidRoleName(name.to_string()));
        }

        // Check if role already exists
        {
            let role_registry = self.role_registry.read().unwrap();
            if role_registry.get_role(name).is_some() {
                return Err(RbacError::InvalidRoleName(format!(
                    "Role '{}' already exists",
                    name
                )));
            }
        }

        // Parse permissions
        let mut role_permissions = Permission::empty();
        for perm_str in &permissions {
            if let Some(perm) = Permission::from_name(perm_str) {
                role_permissions = role_permissions.union(&perm);
            } else {
                return Err(RbacError::InvalidRoleName(format!(
                    "Invalid permission: {}",
                    perm_str
                )));
            }
        }

        // Validate inheritance (prevent cycles)
        if let Some(ref parents) = inherits_from {
            self.validate_inheritance_chain(name, parents)?;
        }

        let mut role = Role::new(name.to_string(), description.to_string(), role_permissions);

        if let Some(parents) = inherits_from {
            for parent in parents {
                role = role.inherit_from(parent);
            }
        }

        // Store role in registry
        {
            let mut role_registry = self.role_registry.write().unwrap();
            role_registry.register_role(role.clone());
        }

        // Store role in Redis
        let role_key = format!("rbac:role:{}", name);
        self.set_redis_value(&role_key, &role, None).await?;

        // Audit log the creation
        if self.config.audit_enabled {
            self.log_audit_event(AuditLogEntry {
                id: Uuid::new_v4().to_string(),
                timestamp: Utc::now(),
                event_type: AuditEventType::RoleCreation,
                user_id: None,
                username: Some(created_by.to_string()),
                resource: format!("role:{}", name),
                action: "create_role".to_string(),
                permission_required: Some("role:manage".to_string()),
                permission_granted: true,
                role: Some(name.to_string()),
                ip_address: None,
                user_agent: None,
                metadata: Some(serde_json::json!({
                    "permissions": permissions,
                    "inherits_from": role.inherits_from
                })),
            })
            .await?;
        }

        Ok(role)
    }

    /// Update an existing role
    pub async fn update_role(
        &self,
        role_name: &str,
        description: Option<String>,
        permissions: Option<Vec<String>>,
        inherits_from: Option<Vec<String>>,
        _updated_by: &str,
    ) -> Result<Role, RbacError> {
        let mut registry = self.role_registry.write().unwrap();

        // Get existing role
        let existing_role = registry
            .get_role(role_name)
            .cloned()
            .ok_or_else(|| RbacError::RoleNotFound(format!("Role '{}' not found", role_name)))?;

        if existing_role.is_system {
            return Err(RbacError::SystemRoleModification);
        }

        // Update role fields
        let mut updated_role = existing_role.clone();

        if let Some(desc) = description {
            updated_role.description = desc;
        }

        if let Some(inherit_roles) = inherits_from {
            // Validate no circular dependencies
            for parent in &inherit_roles {
                if parent == role_name {
                    return Err(RbacError::InheritanceCycle);
                }
            }
            updated_role.inherits_from = inherit_roles;
        }

        if let Some(perm_strs) = permissions {
            // Parse permissions
            let mut role_permissions = Permission::empty();
            for perm_str in &perm_strs {
                if let Some(perm) = Permission::from_name(perm_str) {
                    role_permissions = role_permissions.union(&perm);
                } else {
                    return Err(RbacError::InvalidRoleName(format!(
                        "Invalid permission: {}",
                        perm_str
                    )));
                }
            }
            updated_role.permissions = role_permissions;
        }

        // Store updated role in Redis
        let conn = self
            .redis_pool
            .get_connection()
            .map_err(|e| RbacError::RedisError(format!("Redis connection failed: {}", e)))?;
        let conn_arc = Arc::new(std::sync::Mutex::new(conn));

        let role_key = format!("rbac:role:{}", role_name);
        let role_data = serde_json::to_string(&updated_role)
            .map_err(|e| RbacError::SerializationError(e.to_string()))?;

        dbx_adapter::redis::primitives::string::RedisString::new(conn_arc)
            .set(&role_key, &role_data)
            .map_err(|e| RbacError::RedisError(format!("Failed to store role in Redis: {}", e)))?;

        // Update registry
        registry.register_role(updated_role.clone());

        Ok(updated_role)
    }

    /// Delete custom role
    pub async fn delete_role(&self, name: &str, deleted_by: &str) -> Result<(), RbacError> {
        // Check if role exists and is not system role
        {
            let role_registry = self.role_registry.read().unwrap();
            if let Some(role) = role_registry.get_role(name) {
                if role.is_system {
                    return Err(RbacError::SystemRoleModification);
                }
            } else {
                return Err(RbacError::RoleNotFound(name.to_string()));
            }
        }

        // Remove from registry
        {
            let mut role_registry = self.role_registry.write().unwrap();
            role_registry
                .remove_role(name)
                .map_err(|e| RbacError::InvalidRoleName(e))?;
        }

        // Remove from Redis
        let role_key = format!("rbac:role:{}", name);
        self.delete_redis_key(&role_key).await?;

        // Revoke role from all users (mark assignments as inactive)
        // Mark all existing role assignments as inactive to maintain audit trail
        let users_with_role = self.get_users_with_role(name).await?;
        for user_id in users_with_role {
            let _ = self
                .revoke_role(&user_id, name, deleted_by, Some("Role deleted".to_string()))
                .await;
        }

        // Audit log the deletion
        if self.config.audit_enabled {
            self.log_audit_event(AuditLogEntry {
                id: Uuid::new_v4().to_string(),
                timestamp: Utc::now(),
                event_type: AuditEventType::RoleDeletion,
                user_id: None,
                username: Some(deleted_by.to_string()),
                resource: format!("role:{}", name),
                action: "delete_role".to_string(),
                permission_required: Some("role:manage".to_string()),
                permission_granted: true,
                role: Some(name.to_string()),
                ip_address: None,
                user_agent: None,
                metadata: None,
            })
            .await?;
        }

        Ok(())
    }

    /// Get user's role assignments
    pub async fn get_user_role_assignments(
        &self,
        user_id: &str,
    ) -> Result<Vec<UserRoleAssignment>, RbacError> {
        let user_roles_key = format!("rbac:user_roles:{}", user_id);
        let role_names: Vec<String> = self.get_redis_set_members(&user_roles_key).await?;

        let mut assignments = Vec::new();
        for role_name in role_names {
            let assignment_key = format!("rbac:assignment:{}:{}", user_id, role_name);
            if let Some(assignment) = self.get_redis_value(&assignment_key).await? {
                assignments.push(assignment);
            }
        }

        Ok(assignments)
    }

    /// Get users with specific role
    async fn get_users_with_role(&self, role_name: &str) -> Result<Vec<String>, RbacError> {
        let role_users_key = format!("rbac:role_users:{}", role_name);
        self.get_redis_set_members(&role_users_key).await
    }

    /// Store user role assignment
    async fn store_user_role_assignment(
        &self,
        assignment: &UserRoleAssignment,
    ) -> Result<(), RbacError> {
        let assignment_key = format!(
            "rbac:assignment:{}:{}",
            assignment.user_id, assignment.role_name
        );
        let user_roles_key = format!("rbac:user_roles:{}", assignment.user_id);
        let role_users_key = format!("rbac:role_users:{}", assignment.role_name);

        // Store assignment
        self.set_redis_value(&assignment_key, assignment, assignment.expires_at)
            .await?;

        // Add to user's roles set
        self.add_to_redis_set(&user_roles_key, &assignment.role_name)
            .await?;

        // Add to role's users set
        self.add_to_redis_set(&role_users_key, &assignment.user_id)
            .await?;

        Ok(())
    }

    /// Validate role inheritance to prevent cycles
    fn validate_inheritance_chain(
        &self,
        role_name: &str,
        inherits_from: &[String],
    ) -> Result<(), RbacError> {
        let role_registry = self.role_registry.read().unwrap();

        // Cycle detection using depth-first search algorithm
        fn check_cycle(
            registry: &RoleRegistry,
            current: &str,
            target: &str,
            visited: &mut std::collections::HashSet<String>,
            depth: u8,
            max_depth: u8,
        ) -> bool {
            if depth > max_depth {
                return true; // Prevent infinite recursion
            }

            if current == target {
                return true; // Cycle detected
            }

            if visited.contains(current) {
                return false; // Already visited in this path
            }

            visited.insert(current.to_string());

            if let Some(role) = registry.get_role(current) {
                for parent in &role.inherits_from {
                    if check_cycle(registry, parent, target, visited, depth + 1, max_depth) {
                        return true;
                    }
                }
            }

            visited.remove(current);
            false
        }

        for parent in inherits_from {
            let mut visited = std::collections::HashSet::new();
            if check_cycle(
                &role_registry,
                parent,
                role_name,
                &mut visited,
                0,
                self.config.max_role_inheritance_depth,
            ) {
                return Err(RbacError::InheritanceCycle);
            }
        }

        Ok(())
    }

    /// Log audit event
    async fn log_audit_event(&self, entry: AuditLogEntry) -> Result<(), RbacError> {
        let audit_key = format!("rbac:audit:{}", entry.id);
        let audit_index_key = format!("rbac:audit_index:{}", entry.timestamp.format("%Y%m%d"));

        // Store audit entry
        self.set_redis_value(&audit_key, &entry, None).await?;

        // Add to daily index for efficient querying
        self.add_to_redis_set(&audit_index_key, &entry.id).await?;

        // Set TTL on daily index for automatic cleanup
        let ttl_seconds = self.config.audit_retention_days as i64 * 24 * 60 * 60;
        self.set_redis_ttl(&audit_index_key, ttl_seconds).await?;

        Ok(())
    }

    /// Query audit logs
    pub async fn query_audit_logs(
        &self,
        params: AuditQueryParams,
    ) -> Result<Vec<AuditLogEntry>, RbacError> {
        let start_date = params
            .start_date
            .unwrap_or_else(|| Utc::now() - Duration::days(7));
        let end_date = params.end_date.unwrap_or_else(|| Utc::now());
        let limit = params.limit.unwrap_or(100).min(1000); // Cap at 1000

        let mut entries = Vec::new();
        let mut current_date = start_date.date_naive();
        let end_date_naive = end_date.date_naive();

        while current_date <= end_date_naive && entries.len() < limit as usize {
            let audit_index_key = format!("rbac:audit_index:{}", current_date.format("%Y%m%d"));
            let entry_ids: Vec<String> = self.get_redis_set_members(&audit_index_key).await?;

            for entry_id in entry_ids {
                if entries.len() >= limit as usize {
                    break;
                }

                let audit_key = format!("rbac:audit:{}", entry_id);
                if let Some(entry) = self.get_redis_value::<AuditLogEntry>(&audit_key).await? {
                    // Apply filters
                    if entry.timestamp >= start_date && entry.timestamp <= end_date {
                        if let Some(ref user_filter) = params.user_id {
                            if entry.user_id.as_ref() != Some(user_filter) {
                                continue;
                            }
                        }

                        if let Some(ref event_type_filter) = params.event_type {
                            if std::mem::discriminant(&entry.event_type)
                                != std::mem::discriminant(event_type_filter)
                            {
                                continue;
                            }
                        }

                        if let Some(ref resource_filter) = params.resource {
                            if !entry.resource.contains(resource_filter) {
                                continue;
                            }
                        }

                        entries.push(entry);
                    }
                }
            }

            current_date = current_date.succ_opt().unwrap_or(end_date_naive);
        }

        // Sort by timestamp descending
        entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        // Apply offset
        let offset = params.offset.unwrap_or(0) as usize;
        if offset < entries.len() {
            entries = entries.into_iter().skip(offset).collect();
        } else {
            entries.clear();
        }

        Ok(entries)
    }

    // Redis helper methods
    async fn get_redis_value<T>(&self, key: &str) -> Result<Option<T>, RbacError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let conn = self
            .redis_pool
            .get_connection()
            .map_err(|e| RbacError::RedisError(e.to_string()))?;
        let conn_arc = Arc::new(std::sync::Mutex::new(conn));

        match dbx_adapter::redis::primitives::string::RedisString::new(conn_arc).get(key) {
            Ok(Some(value)) => {
                let deserialized: T = serde_json::from_str(&value)
                    .map_err(|e| RbacError::SerializationError(e.to_string()))?;
                Ok(Some(deserialized))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(RbacError::RedisError(e.to_string())),
        }
    }

    async fn set_redis_value<T>(
        &self,
        key: &str,
        value: &T,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<(), RbacError>
    where
        T: Serialize,
    {
        let conn = self
            .redis_pool
            .get_connection()
            .map_err(|e| RbacError::RedisError(e.to_string()))?;
        let conn_arc = Arc::new(std::sync::Mutex::new(conn));

        let serialized = serde_json::to_string(value)
            .map_err(|e| RbacError::SerializationError(e.to_string()))?;

        dbx_adapter::redis::primitives::string::RedisString::new(conn_arc)
            .set(key, &serialized)
            .map_err(|e| RbacError::RedisError(e.to_string()))?;

        // Set TTL if expires_at is provided
        if let Some(exp) = expires_at {
            let ttl_seconds = (exp - Utc::now()).num_seconds().max(1);
            self.set_redis_ttl(key, ttl_seconds).await?;
        }

        Ok(())
    }

    async fn delete_redis_key(&self, key: &str) -> Result<(), RbacError> {
        let conn = self
            .redis_pool
            .get_connection()
            .map_err(|e| RbacError::RedisError(e.to_string()))?;
        let conn_arc = Arc::new(std::sync::Mutex::new(conn));

        let mut conn = conn_arc.lock().unwrap();
        redis::cmd("DEL").arg(key).execute(&mut *conn);

        Ok(())
    }

    async fn add_to_redis_set(&self, key: &str, member: &str) -> Result<(), RbacError> {
        let conn = self
            .redis_pool
            .get_connection()
            .map_err(|e| RbacError::RedisError(e.to_string()))?;
        let conn_arc = Arc::new(std::sync::Mutex::new(conn));

        dbx_adapter::redis::primitives::set::RedisSet::new(conn_arc)
            .sadd(key, &[member])
            .map_err(|e| RbacError::RedisError(e.to_string()))?;

        Ok(())
    }

    async fn remove_from_redis_set(&self, key: &str, member: &str) -> Result<(), RbacError> {
        let conn = self
            .redis_pool
            .get_connection()
            .map_err(|e| RbacError::RedisError(e.to_string()))?;
        let conn_arc = Arc::new(std::sync::Mutex::new(conn));

        dbx_adapter::redis::primitives::set::RedisSet::new(conn_arc)
            .srem(key, &[member])
            .map_err(|e| RbacError::RedisError(e.to_string()))?;

        Ok(())
    }

    async fn get_redis_set_members(&self, key: &str) -> Result<Vec<String>, RbacError> {
        let conn = self
            .redis_pool
            .get_connection()
            .map_err(|e| RbacError::RedisError(e.to_string()))?;
        let conn_arc = Arc::new(std::sync::Mutex::new(conn));

        dbx_adapter::redis::primitives::set::RedisSet::new(conn_arc)
            .smembers(key)
            .map_err(|e| RbacError::RedisError(e.to_string()))
    }

    async fn set_redis_ttl(&self, key: &str, ttl_seconds: i64) -> Result<(), RbacError> {
        let conn = self
            .redis_pool
            .get_connection()
            .map_err(|e| RbacError::RedisError(e.to_string()))?;
        let conn_arc = Arc::new(std::sync::Mutex::new(conn));

        let mut conn = conn_arc.lock().unwrap();
        redis::cmd("EXPIRE")
            .arg(key)
            .arg(ttl_seconds)
            .execute(&mut *conn);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::permissions::Permission;

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
}
