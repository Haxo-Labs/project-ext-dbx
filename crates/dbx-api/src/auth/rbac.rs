use crate::{
    auth::permissions::{Permission, PermissionType, Role, RoleRegistry},
    models::{AuditEventType, AuditLogEntry, AuditQueryParams, RbacContext, UserRoleAssignment},
};
use chrono::{Duration, Utc};
use dbx_core::UniversalBackend;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
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
    #[error("Backend error: {0}")]
    BackendError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Role already exists: {0}")]
    RoleAlreadyExists(String),
    #[error("Database error: {0}")]
    DatabaseError(String),
    #[error("System error: {0}")]
    SystemError(String),
    #[error("Validation error: {0}")]
    ValidationError(String),
}

/// RBAC service configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    backend: Arc<dyn UniversalBackend>,
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
    pub fn new(backend: Arc<dyn UniversalBackend>, config: RbacConfig) -> Self {
        let role_registry = Arc::new(std::sync::RwLock::new(RoleRegistry::new()));
        Self {
            backend,
            role_registry,
            config,
        }
    }

    /// Get a reference to the role registry for read operations
    pub fn get_role_registry(&self) -> Arc<std::sync::RwLock<RoleRegistry>> {
        self.role_registry.clone()
    }

    /// Check if user has specific permission
    pub async fn check_user_permission(
        &self,
        user_id: &str,
        permission: PermissionType,
        context: RbacContext,
    ) -> Result<bool, RbacError> {
        let user_permissions = self.get_user_effective_permissions(user_id).await?;

        let permission_to_check = Permission::single(permission.clone());
        let has_permission = user_permissions.contains(&permission_to_check);

        // Audit log the permission check
        if self.config.audit_enabled {
            self.log_audit_event(AuditLogEntry {
                id: Uuid::new_v4().to_string(),
                timestamp: Utc::now(),
                event_type: if has_permission {
                    AuditEventType::Authorization
                } else {
                    AuditEventType::Authorization
                },
                user_id: Some(user_id.to_string()),
                username: Some(context.username.clone()),
                resource: format!("{:?}", permission),
                action: "check".to_string(),
                permission_required: Some(format!("{:?}", permission)),
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

        let role_registry = match self.role_registry.read() {
            Ok(registry) => registry,
            Err(_) => {
                return Err(RbacError::SystemError(
                    "Failed to access role registry".to_string(),
                ))
            }
        };

        for assignment in &assignments {
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

    /// Assign a role to a user
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
            let role_registry = self.role_registry.read().map_err(|_| {
                RbacError::BackendError("Failed to acquire read lock on role registry".to_string())
            })?;
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
            .get_backend_value(&assignment_key)
            .await?
            .ok_or(RbacError::AssignmentNotFound)?;

        // Mark as inactive
        assignment.is_active = false;

        // Store updated assignment
        self.set_backend_value(&assignment_key, &assignment).await?;

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
            let role_registry = match self.role_registry.read() {
                Ok(registry) => registry,
                Err(_) => {
                    return Err(RbacError::SystemError(
                        "Failed to access role registry".to_string(),
                    ))
                }
            };
            if role_registry.get_role(name).is_some() {
                return Err(RbacError::InvalidRoleName(format!(
                    "Role '{}' already exists",
                    name
                )));
            }
        }

        // Parse permissions
        let mut role_permissions = Permission::empty();
        for perm_str in permissions {
            match perm_str.parse::<PermissionType>() {
                Ok(perm_type) => {
                    role_permissions = role_permissions.union(&Permission::single(perm_type));
                }
                Err(_) => {
                    return Err(RbacError::InvalidRoleName(format!(
                        "Invalid permission: {}",
                        perm_str
                    )));
                }
            }
        }

        let mut role = Role::new(name.to_string(), description.to_string(), role_permissions);

        if let Some(ref parents) = inherits_from {
            // Validate inheritance chain for cycles and depth
            self.validate_inheritance_chain(name, parents)?;

            for parent in parents {
                role = role.inherit_from(parent.clone());
            }
        }

        // Store role in registry
        {
            let mut role_registry = match self.role_registry.write() {
                Ok(registry) => registry,
                Err(_) => {
                    return Err(RbacError::SystemError(
                        "Failed to access role registry".to_string(),
                    ))
                }
            };
            role_registry.register_role(role.clone());
        }

        // Store role
        let role_key = format!("rbac:role:{}", name);
        self.set_backend_value(&role_key, &role).await?;

        // Audit log the creation
        if self.config.audit_enabled {
            self.log_audit_event(AuditLogEntry {
                id: Uuid::new_v4().to_string(),
                timestamp: Utc::now(),
                event_type: AuditEventType::RoleManagement,
                user_id: None,
                username: Some(created_by.to_string()),
                resource: format!("role:{}", name),
                action: "create_role".to_string(),
                permission_required: Some("role:manage".to_string()),
                permission_granted: true,
                role: Some(name.to_string()),
                ip_address: None,
                user_agent: None,
                metadata: None,
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
        let mut registry = self.role_registry.write().map_err(|_| {
            RbacError::BackendError("Failed to acquire write lock on role registry".to_string())
        })?;

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
            // Validate inheritance chain for cycles and depth
            self.validate_inheritance_chain(role_name, &inherit_roles)?;
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

        // Store updated role
        let _conn = self
            .backend
            .execute_data(dbx_core::DataOperation::Set {
                key: format!("rbac:role:{}", role_name),
                value: dbx_core::DataValue::String(
                    serde_json::to_string(&updated_role)
                        .map_err(|e| RbacError::SerializationError(e.to_string()))?,
                ),
                ttl: None,
            })
            .await
            .map_err(|e| RbacError::BackendError(format!("Failed to store role: {}", e)))?;

        // Update registry
        registry.register_role(updated_role.clone());

        Ok(updated_role)
    }

    /// Delete custom role
    pub async fn delete_role(&self, name: &str, deleted_by: &str) -> Result<(), RbacError> {
        // Check if role exists and is not system role
        {
            let role_registry = match self.role_registry.read() {
                Ok(registry) => registry,
                Err(_) => {
                    return Err(RbacError::SystemError(
                        "Failed to access role registry".to_string(),
                    ))
                }
            };
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
            let mut role_registry = match self.role_registry.write() {
                Ok(registry) => registry,
                Err(_) => {
                    return Err(RbacError::SystemError(
                        "Failed to access role registry".to_string(),
                    ))
                }
            };
            role_registry
                .remove_role(name)
                .map_err(|e| RbacError::InvalidRoleName(e))?;
        }

        // Remove from storage
        let role_key = format!("rbac:role:{}", name);
        self.delete_backend_key(&role_key).await?;

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
                event_type: AuditEventType::RoleManagement,
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
        // Query all assignments for this user using pattern matching
        let pattern = format!("rbac:assignment:{}:*", user_id);
        let assignment_keys = self.query_keys(&pattern).await?;

        let mut assignments = Vec::new();
        for key in assignment_keys {
            if let Some(assignment) = self.get_backend_value(&key).await? {
                assignments.push(assignment);
            }
        }

        Ok(assignments)
    }

    /// Get users with specific role
    async fn get_users_with_role(&self, role_name: &str) -> Result<Vec<String>, RbacError> {
        // Query all assignments for this role using pattern matching
        let pattern = format!("rbac:assignment:*:{}", role_name);
        let assignment_keys = self.query_keys(&pattern).await?;

        let mut user_ids = Vec::new();
        for key in assignment_keys {
            if let Some(assignment) = self.get_backend_value::<UserRoleAssignment>(&key).await? {
                if assignment.is_active {
                    user_ids.push(assignment.user_id);
                }
            }
        }

        Ok(user_ids)
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

        // Store assignment record
        self.set_backend_value(&assignment_key, assignment).await?;

        Ok(())
    }

    /// Validate role inheritance to prevent cycles
    fn validate_inheritance_chain(
        &self,
        role_name: &str,
        inherits_from: &[String],
    ) -> Result<(), RbacError> {
        let role_registry = self.role_registry.read().map_err(|_| {
            RbacError::BackendError("Failed to acquire read lock on role registry".to_string())
        })?;

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
                return true; // Prevent infinite recursion or depth limit exceeded
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

        // Function to calculate the maximum depth of inheritance from a role
        fn calculate_max_depth(
            registry: &RoleRegistry,
            role_name: &str,
            visited: &mut std::collections::HashSet<String>,
            max_depth: u8,
        ) -> u8 {
            if visited.contains(role_name) {
                return 0; // Avoid cycles
            }

            if let Some(role) = registry.get_role(role_name) {
                if role.inherits_from.is_empty() {
                    return 0; // Leaf role
                }

                visited.insert(role_name.to_string());
                let mut max_child_depth = 0;

                for parent in &role.inherits_from {
                    let child_depth = calculate_max_depth(registry, parent, visited, max_depth);
                    max_child_depth = max_child_depth.max(child_depth);
                }

                visited.remove(role_name);
                return max_child_depth + 1;
            }

            0 // Role doesn't exist
        }

        // Check for cycles
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

        // Check depth limit for each parent
        for parent in inherits_from {
            let mut visited = std::collections::HashSet::new();
            let depth = calculate_max_depth(
                &role_registry,
                parent,
                &mut visited,
                self.config.max_role_inheritance_depth,
            );
            if depth >= self.config.max_role_inheritance_depth {
                return Err(RbacError::InheritanceCycle);
            }
        }

        Ok(())
    }

    /// Log audit event
    async fn log_audit_event(&self, entry: AuditLogEntry) -> Result<(), RbacError> {
        if !self.config.audit_enabled {
            return Ok(());
        }

        let audit_key = format!("rbac:audit:{}", entry.id);

        // Store audit entry
        self.set_backend_value(&audit_key, &entry).await?;

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

        // Query all audit entries using pattern matching
        let pattern = "rbac:audit:*";
        let audit_keys = self.query_keys(&pattern).await?;

        let mut entries = Vec::new();
        for audit_key in audit_keys {
            if entries.len() >= limit as usize {
                break;
            }

            if let Some(entry) = self.get_backend_value::<AuditLogEntry>(&audit_key).await? {
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

    // Backend helper methods
    async fn query_keys(&self, pattern: &str) -> Result<Vec<String>, RbacError> {
        use dbx_core::{QueryFilter, QueryOperation};
        use uuid::Uuid;

        let operation = QueryOperation {
            id: Uuid::new_v4(),
            filter: QueryFilter::KeyPattern {
                pattern: pattern.to_string(),
            },
            projection: None,
            limit: None,
            offset: None,
            sort: None,
        };

        match self.backend.execute_query(operation).await {
            Ok(result) => {
                if result.success {
                    let keys = result.results.into_iter().map(|item| item.key).collect();
                    Ok(keys)
                } else {
                    Ok(Vec::new())
                }
            }
            Err(e) => Err(RbacError::BackendError(e.to_string())),
        }
    }

    async fn get_backend_value<T>(&self, key: &str) -> Result<Option<T>, RbacError>
    where
        T: for<'de> Deserialize<'de>,
    {
        use dbx_core::{DataOperation, DataValue};

        match self
            .backend
            .execute_data(DataOperation::Get {
                key: key.to_string(),
                fields: None,
            })
            .await
        {
            Ok(result) => {
                if result.success {
                    if let Some(DataValue::String(value)) = result.data {
                        let deserialized: T = serde_json::from_str(&value)
                            .map_err(|e| RbacError::SerializationError(e.to_string()))?;
                        Ok(Some(deserialized))
                    } else {
                        Ok(None)
                    }
                } else {
                    Ok(None)
                }
            }
            Err(e) => Err(RbacError::BackendError(e.to_string())),
        }
    }

    async fn set_backend_value<T>(&self, key: &str, value: &T) -> Result<(), RbacError>
    where
        T: Serialize,
    {
        use dbx_core::{DataOperation, DataValue};

        let serialized = serde_json::to_string(value)
            .map_err(|e| RbacError::SerializationError(e.to_string()))?;

        self.backend
            .execute_data(DataOperation::Set {
                key: key.to_string(),
                value: DataValue::String(serialized),
                ttl: None,
            })
            .await
            .map_err(|e| RbacError::BackendError(e.to_string()))?;

        Ok(())
    }

    async fn delete_backend_key(&self, key: &str) -> Result<(), RbacError> {
        use dbx_core::DataOperation;

        self.backend
            .execute_data(DataOperation::Delete {
                key: key.to_string(),
                fields: None,
            })
            .await
            .map_err(|e| RbacError::BackendError(e.to_string()))?;

        Ok(())
    }
}
