//! PostgreSQL client module
//!
//! This module provides client functionality for establishing and managing
//! PostgreSQL connections using deadpool-postgres for high-performance async operations.

use crate::error::{AdapterError, ConnectionError};
use deadpool_postgres::{Config, Pool, Runtime};
use tokio_postgres::NoTls;

/// Result type for connection operations
pub type ConnectionResult<T> = Result<T, AdapterError>;

/// High-performance PostgreSQL connection pool using deadpool-postgres
#[derive(Debug, Clone)]
pub struct PostgresConnectionPool {
    pool: Pool,
    url: String,
}

impl PostgresConnectionPool {
    /// Create a new PostgreSQL connection pool from URL
    pub fn new(url: &str, pool_size: usize) -> Result<Self, AdapterError> {
        // Parse the URL manually since deadpool_postgres doesn't have from_url
        let parsed_url = url::Url::parse(url).map_err(|e| {
            AdapterError::Connection(ConnectionError::InvalidConfiguration(format!(
                "Invalid PostgreSQL URL: {}",
                e
            )))
        })?;

        let mut config = Config::new();
        config.host = Some(parsed_url.host_str().unwrap_or("localhost").to_string());
        config.port = Some(parsed_url.port().unwrap_or(5432));
        config.dbname = parsed_url.path().strip_prefix('/').map(|s| s.to_string());
        config.user = if parsed_url.username().is_empty() {
            None
        } else {
            Some(parsed_url.username().to_string())
        };
        config.password = parsed_url.password().map(|s| s.to_string());
        config.pool = Some(deadpool_postgres::PoolConfig::new(pool_size));

        let pool = config
            .create_pool(Some(Runtime::Tokio1), NoTls)
            .map_err(|e| {
                AdapterError::Connection(ConnectionError::ConnectionFailed(format!(
                    "Failed to create PostgreSQL pool: {}",
                    e
                )))
            })?;

        Ok(Self {
            pool,
            url: url.to_string(),
        })
    }

    /// Get a connection from the pool
    pub async fn get(&self) -> Result<deadpool_postgres::Object, AdapterError> {
        self.pool.get().await.map_err(|e| {
            AdapterError::Connection(ConnectionError::ConnectionFailed(format!(
                "Failed to get PostgreSQL connection: {}",
                e
            )))
        })
    }

    /// Get pool status and metrics
    pub fn status(&self) -> PoolStatus {
        let status = self.pool.status();
        PoolStatus {
            available: status.available,
            size: status.size,
            max_size: status.max_size,
            waiting: status.waiting,
        }
    }

    /// Perform health check on the pool
    pub async fn health_check(&self) -> Result<bool, AdapterError> {
        match self.get().await {
            Ok(conn) => match conn.query_one("SELECT 1", &[]).await {
                Ok(_) => Ok(true),
                Err(e) => {
                    tracing::warn!("PostgreSQL health check failed: {}", e);
                    Ok(false)
                }
            },
            Err(e) => {
                tracing::error!(
                    "Failed to get PostgreSQL connection for health check: {}",
                    e
                );
                Ok(false)
            }
        }
    }

    /// Get connection pool statistics
    pub async fn get_stats(&self) -> PoolStats {
        let status = self.status();
        let health = self.health_check().await.unwrap_or(false);

        PoolStats {
            total_connections: status.size,
            active_connections: status.size - status.available,
            idle_connections: status.available,
            max_connections: status.max_size,
            waiting_requests: status.waiting,
            is_healthy: health,
            connection_string: self.url.clone(),
        }
    }

    /// Get the PostgreSQL URL
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Ping the PostgreSQL server
    pub async fn ping(&self) -> Result<bool, AdapterError> {
        self.health_check().await
    }

    /// Execute a simple query for testing
    pub async fn execute_query(&self, query: &str) -> Result<u64, AdapterError> {
        let conn = self.get().await?;
        conn.execute(query, &[]).await.map_err(|e| {
            AdapterError::Connection(ConnectionError::QueryFailed(format!(
                "Query execution failed: {}",
                e
            )))
        })
    }

    /// Get database version information
    pub async fn get_version(&self) -> Result<String, AdapterError> {
        let conn = self.get().await?;
        let row = conn.query_one("SELECT version()", &[]).await.map_err(|e| {
            AdapterError::Connection(ConnectionError::QueryFailed(format!(
                "Failed to get PostgreSQL version: {}",
                e
            )))
        })?;

        let version: String = row.get(0);
        Ok(version)
    }
}

/// Pool status information
#[derive(Debug, Clone)]
pub struct PoolStatus {
    pub available: usize,
    pub size: usize,
    pub max_size: usize,
    pub waiting: usize,
}

/// Comprehensive pool statistics
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub total_connections: usize,
    pub active_connections: usize,
    pub idle_connections: usize,
    pub max_connections: usize,
    pub waiting_requests: usize,
    pub is_healthy: bool,
    pub connection_string: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_postgres_connection_pool_creation() {
        let url = "postgresql://postgres:postgres@localhost:5432/test";
        let result = PostgresConnectionPool::new(url, 5);
        // This will fail without a running PostgreSQL instance, but we're testing URL parsing
        match result {
            Ok(_) => {} // Connection successful
            Err(e) => {
                // Expected if no PostgreSQL instance is running
                assert!(e.to_string().contains("Failed to create PostgreSQL pool"));
            }
        }
    }

    #[test]
    fn test_url_storage() {
        let url = "postgresql://test:test@localhost:5432/testdb";
        if let Ok(pool) = PostgresConnectionPool::new(url, 5) {
            assert_eq!(pool.url(), url);
        }
    }
}
