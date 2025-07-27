//! Redis client module
//!
//! This module provides client functionality for establishing and managing
//! Redis connections using deadpool-redis for high-performance async operations.

use crate::error::{AdapterError, ConnectionError};
use deadpool_redis::{Config, Pool, Runtime};
use redis::RedisResult;

/// Result type for connection operations
pub type ConnectionResult<T> = Result<T, AdapterError>;

/// High-performance Redis connection pool using deadpool-redis
#[derive(Clone)]
pub struct RedisConnectionPool {
    pool: Pool,
    url: String,
}

impl RedisConnectionPool {
    /// Create a new Redis connection pool
    pub fn new(redis_url: &str, max_connections: usize) -> Result<Self, AdapterError> {
        let config = Config::from_url(redis_url);
        let pool = config.create_pool(Some(Runtime::Tokio1)).map_err(|e| {
            AdapterError::Connection(ConnectionError::ConnectionFailed(format!(
                "Failed to create pool: {}",
                e
            )))
        })?;

        Ok(Self {
            pool,
            url: redis_url.to_string(),
        })
    }

    /// Get a connection from the pool
    pub async fn get(&self) -> Result<deadpool_redis::Connection, AdapterError> {
        self.pool.get().await.map_err(|e| {
            AdapterError::Connection(ConnectionError::ConnectionFailed(format!(
                "Failed to get connection: {}",
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
            Ok(mut conn) => {
                match redis::cmd("PING")
                    .query_async::<_, String>(&mut *conn)
                    .await
                {
                    Ok(response) => Ok(response == "PONG"),
                    Err(e) => {
                        tracing::warn!("Health check failed: {}", e);
                        Ok(false)
                    }
                }
            }
            Err(e) => {
                tracing::error!("Failed to get connection for health check: {}", e);
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
            url: self.url.clone(),
        }
    }

    /// Get the Redis URL
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Ping the Redis server
    pub async fn ping(&self) -> Result<bool, AdapterError> {
        match self.get().await {
            Ok(mut conn) => {
                match redis::cmd("PING")
                    .query_async::<_, String>(&mut *conn)
                    .await
                {
                    Ok(response) => Ok(response == "PONG"),
                    Err(e) => {
                        tracing::warn!("Ping failed: {}", e);
                        Ok(false)
                    }
                }
            }
            Err(e) => {
                tracing::error!("Failed to get connection for ping: {}", e);
                Ok(false)
            }
        }
    }

    /// Get a string value from Redis
    pub async fn get_string(&self, key: &str) -> Result<String, AdapterError> {
        let mut conn = self.get().await?;
        redis::cmd("GET")
            .arg(key)
            .query_async(&mut *conn)
            .await
            .map_err(|e| {
                AdapterError::Connection(ConnectionError::ConnectionFailed(format!(
                    "GET failed: {}",
                    e
                )))
            })
    }

    /// Get keys matching a pattern
    pub async fn keys(&self, pattern: &str) -> Result<Vec<String>, AdapterError> {
        let mut conn = self.get().await?;
        redis::cmd("KEYS")
            .arg(pattern)
            .query_async(&mut *conn)
            .await
            .map_err(|e| {
                AdapterError::Connection(ConnectionError::ConnectionFailed(format!(
                    "KEYS failed: {}",
                    e
                )))
            })
    }

    /// Get a raw connection for manual operations
    pub async fn acquire_connection(&self) -> Result<deadpool_redis::Connection, AdapterError> {
        self.get().await
    }
}

#[derive(Debug, Clone)]
pub struct PoolStatus {
    pub available: usize,
    pub size: usize,
    pub max_size: usize,
    pub waiting: usize,
}

#[derive(Debug, Clone)]
pub struct PoolStats {
    pub total_connections: usize,
    pub active_connections: usize,
    pub idle_connections: usize,
    pub max_connections: usize,
    pub waiting_requests: usize,
    pub is_healthy: bool,
    pub url: String,
}

/// Create a Redis connection pool from a connection string
pub fn create_pool(url: &str, pool_size: usize) -> Result<RedisConnectionPool, AdapterError> {
    RedisConnectionPool::new(url, pool_size)
}
