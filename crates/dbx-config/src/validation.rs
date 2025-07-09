use std::collections::{HashMap, HashSet};
use validator::Validate;

use crate::error::ConfigError;
use crate::{BackendConfig, DbxConfig};

/// Configuration validator
pub struct ConfigValidator;

impl ConfigValidator {
    /// Validate the entire configuration
    pub fn validate_config(config: &DbxConfig) -> Result<(), ConfigError> {
        // First run basic validation
        config.validate()?;

        // Then run custom validation
        Self::validate_backend_references(config)?;
        Self::validate_routing_consistency(config)?;
        Self::validate_load_balancing(config)?;
        Self::validate_security_consistency(config)?;

        Ok(())
    }

    /// Validate that all backend references in routing exist
    fn validate_backend_references(config: &DbxConfig) -> Result<(), ConfigError> {
        let backend_names: HashSet<_> = config.backends.keys().collect();

        // Check default backend
        if !backend_names.contains(&config.routing.default_backend) {
            return Err(ConfigError::InvalidBackendReference {
                backend: config.routing.default_backend.clone(),
                context: "default backend".to_string(),
            });
        }

        // Check operation routing
        for (operation, backend) in &config.routing.operation_routing {
            if !backend_names.contains(backend) {
                return Err(ConfigError::InvalidBackendReference {
                    backend: backend.clone(),
                    context: format!("operation routing for '{}'", operation),
                });
            }
        }

        // Check key routing
        for rule in &config.routing.key_routing {
            if !backend_names.contains(&rule.backend) {
                return Err(ConfigError::InvalidBackendReference {
                    backend: rule.backend.clone(),
                    context: format!("key routing rule '{}'", rule.pattern),
                });
            }
        }

        // Check load balancing
        if let Some(lb_config) = &config.routing.load_balancing {
            for backend in &lb_config.backends {
                if !backend_names.contains(backend) {
                    return Err(ConfigError::InvalidBackendReference {
                        backend: backend.clone(),
                        context: "load balancing configuration".to_string(),
                    });
                }
            }
        }

        Ok(())
    }

    /// Validate routing configuration consistency
    fn validate_routing_consistency(config: &DbxConfig) -> Result<(), ConfigError> {
        // Check for duplicate key routing patterns with same priority
        let mut pattern_priorities: HashMap<String, u32> = HashMap::new();

        for rule in &config.routing.key_routing {
            if let Some(existing_priority) = pattern_priorities.get(&rule.pattern) {
                if *existing_priority == rule.priority {
                    return Err(ConfigError::DuplicateRoutingRule {
                        pattern: rule.pattern.clone(),
                        priority: rule.priority,
                    });
                }
            } else {
                pattern_priorities.insert(rule.pattern.clone(), rule.priority);
            }
        }

        Ok(())
    }

    /// Validate load balancing configuration
    fn validate_load_balancing(config: &DbxConfig) -> Result<(), ConfigError> {
        if let Some(lb_config) = &config.routing.load_balancing {
            // Check for duplicate backends
            let mut seen_backends = HashSet::new();
            for backend in &lb_config.backends {
                if !seen_backends.insert(backend) {
                    return Err(ConfigError::DuplicateLoadBalancingBackend {
                        backend: backend.clone(),
                    });
                }
            }

            // Validate weights if using weighted round-robin
            if let Some(weights) = &lb_config.weights {
                // Check that all backends have weights
                for backend in &lb_config.backends {
                    if !weights.contains_key(backend) {
                        return Err(ConfigError::MissingLoadBalancingWeight {
                            backend: backend.clone(),
                        });
                    }
                }

                // Check that weights are positive
                for (backend, weight) in weights {
                    if *weight <= 0.0 {
                        return Err(ConfigError::InvalidLoadBalancingWeight {
                            backend: backend.clone(),
                            weight: *weight,
                        });
                    }
                }
            }
        }

        Ok(())
    }

    /// Validate security configuration consistency
    fn validate_security_consistency(config: &DbxConfig) -> Result<(), ConfigError> {
        // If authentication is required, JWT config must be provided
        if config.security.authentication_required && config.security.jwt.is_none() {
            return Err(ConfigError::MissingSecurityConfig {
                config_type: "JWT configuration".to_string(),
                reason: "Authentication is enabled but JWT config is missing".to_string(),
            });
        }

        // If TLS is enabled, cert and key paths must be provided
        if config.security.encryption_in_transit {
            if config.security.tls.is_none() {
                return Err(ConfigError::MissingSecurityConfig {
                    config_type: "TLS configuration".to_string(),
                    reason: "Encryption in transit is enabled but TLS config is missing"
                        .to_string(),
                });
            }
        }

        Ok(())
    }

    /// Validate a backend configuration
    pub fn validate_backend_config(config: &BackendConfig) -> Result<(), ConfigError> {
        config.validate()?;

        // Validate URL format based on provider
        Self::validate_provider_url(&config.provider, &config.url)?;

        Ok(())
    }

    /// Validate URL format for specific providers
    fn validate_provider_url(provider: &str, url: &str) -> Result<(), ConfigError> {
        let parsed_url = url::Url::parse(url).map_err(|e| ConfigError::InvalidUrl {
            url: url.to_string(),
            error: e.to_string(),
        })?;

        match provider.to_lowercase().as_str() {
            "redis" => {
                if !["redis", "rediss"].contains(&parsed_url.scheme()) {
                    return Err(ConfigError::InvalidProviderUrl {
                        provider: provider.to_string(),
                        url: url.to_string(),
                        expected_scheme: "redis or rediss".to_string(),
                    });
                }
            }
            "postgresql" | "postgres" => {
                if !["postgres", "postgresql"].contains(&parsed_url.scheme()) {
                    return Err(ConfigError::InvalidProviderUrl {
                        provider: provider.to_string(),
                        url: url.to_string(),
                        expected_scheme: "postgres or postgresql".to_string(),
                    });
                }
            }
            "mongodb" | "mongo" => {
                if !["mongodb", "mongodb+srv"].contains(&parsed_url.scheme()) {
                    return Err(ConfigError::InvalidProviderUrl {
                        provider: provider.to_string(),
                        url: url.to_string(),
                        expected_scheme: "mongodb or mongodb+srv".to_string(),
                    });
                }
            }
            "mysql" => {
                if parsed_url.scheme() != "mysql" {
                    return Err(ConfigError::InvalidProviderUrl {
                        provider: provider.to_string(),
                        url: url.to_string(),
                        expected_scheme: "mysql".to_string(),
                    });
                }
            }
            _ => {
                // Validate URL format for unknown providers
                // The specific provider implementation will handle validation
            }
        }

        Ok(())
    }
}

/// Health checker for configuration
pub struct ConfigHealthChecker;

impl ConfigHealthChecker {
    /// Check if configuration is healthy and complete
    pub fn check_health(config: &DbxConfig) -> ConfigHealth {
        let mut warnings = Vec::new();
        let mut errors = Vec::new();

        // Check for common configuration issues
        Self::check_backend_health(config, &mut warnings, &mut errors);
        Self::check_performance_health(config, &mut warnings);
        Self::check_security_health(config, &mut warnings);

        let status = if !errors.is_empty() {
            ConfigHealthStatus::Error
        } else if !warnings.is_empty() {
            ConfigHealthStatus::Warning
        } else {
            ConfigHealthStatus::Healthy
        };

        ConfigHealth {
            status,
            warnings,
            errors,
        }
    }

    fn check_backend_health(
        config: &DbxConfig,
        warnings: &mut Vec<String>,
        errors: &mut Vec<String>,
    ) {
        // Check if any backends are configured
        if config.backends.is_empty() {
            errors.push("No backends configured".to_string());
            return;
        }

        // Check for single points of failure
        if config.backends.len() == 1 && config.routing.load_balancing.is_none() {
            warnings.push(
                "Single backend configured without load balancing - consider adding redundancy"
                    .to_string(),
            );
        }

        // Check backend configurations
        for (name, backend_config) in &config.backends {
            // Check pool size
            if let Some(pool_size) = backend_config.pool_size {
                if pool_size < 2 {
                    warnings.push(format!(
                        "Backend '{}' has very small pool size ({})",
                        name, pool_size
                    ));
                } else if pool_size > 100 {
                    warnings.push(format!(
                        "Backend '{}' has very large pool size ({})",
                        name, pool_size
                    ));
                }
            }

            // Check timeout configuration
            if let Some(timeout) = backend_config.timeout_ms {
                if timeout < 1000 {
                    warnings.push(format!(
                        "Backend '{}' has very short timeout ({}ms)",
                        name, timeout
                    ));
                } else if timeout > 30000 {
                    warnings.push(format!(
                        "Backend '{}' has very long timeout ({}ms)",
                        name, timeout
                    ));
                }
            }
        }
    }

    fn check_performance_health(config: &DbxConfig, warnings: &mut Vec<String>) {
        // Check query timeout
        if config.performance.query_timeout_ms > 60000 {
            warnings
                .push("Query timeout is very high (>60s) - may impact user experience".to_string());
        }

        // Check concurrent operations
        if config.performance.max_concurrent_operations > 5000 {
            warnings
                .push("High max concurrent operations - ensure sufficient resources".to_string());
        }

        // Check cache configuration
        if !config.performance.cache_enabled {
            warnings
                .push("Caching is disabled - consider enabling for better performance".to_string());
        }

        // Check if metrics are disabled
        if !config.performance.metrics_enabled {
            warnings
                .push("Metrics collection is disabled - monitoring will be limited".to_string());
        }
    }

    fn check_security_health(config: &DbxConfig, warnings: &mut Vec<String>) {
        // Check authentication
        if !config.security.authentication_required {
            warnings
                .push("Authentication is disabled - consider enabling for production".to_string());
        }

        // Check encryption
        if !config.security.encryption_in_transit {
            warnings.push(
                "TLS encryption is disabled - data will be transmitted in plain text".to_string(),
            );
        }

        if !config.security.encryption_at_rest {
            warnings.push(
                "Encryption at rest is disabled - consider enabling for sensitive data".to_string(),
            );
        }

        // Check audit logging
        if !config.security.audit_logging {
            warnings
                .push("Audit logging is disabled - consider enabling for compliance".to_string());
        }

        // Check rate limiting
        if config.security.rate_limiting.is_none() {
            warnings
                .push("Rate limiting is disabled - consider enabling to prevent abuse".to_string());
        }
    }
}

/// Configuration health status
#[derive(Debug, Clone)]
pub struct ConfigHealth {
    pub status: ConfigHealthStatus,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

/// Configuration health status levels
#[derive(Debug, Clone, PartialEq)]
pub enum ConfigHealthStatus {
    Healthy,
    Warning,
    Error,
}

impl ConfigHealth {
    /// Check if configuration is healthy (no errors)
    pub fn is_healthy(&self) -> bool {
        self.status != ConfigHealthStatus::Error
    }

    /// Get a summary of the health check
    pub fn summary(&self) -> String {
        match self.status {
            ConfigHealthStatus::Healthy => "Configuration is healthy".to_string(),
            ConfigHealthStatus::Warning => {
                format!("Configuration has {} warnings", self.warnings.len())
            }
            ConfigHealthStatus::Error => format!("Configuration has {} errors", self.errors.len()),
        }
    }
}
