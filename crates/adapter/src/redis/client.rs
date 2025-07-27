//! Redis client module
//!
//! This module provides client functionality for establishing and managing
//! Redis connections, including support for connection pooling and different
//! connection types.

use crate::error::AdapterError;
use deadpool_redis::{Config, Pool, Runtime};
use redis::{aio::Connection, Client, RedisResult};
use std::sync::{Arc, Mutex, PoisonError};
use tracing::{debug, error, warn};

use super::primitives::hash::RedisHash;
use super::primitives::set::RedisSet;
use super::primitives::string::RedisString;

/// Result type for connection operations
pub type ConnectionResult<T> = Result<T, AdapterError>;

/// Redis connection handler trait for safe connection acquisition
pub trait RedisConnectionHandler {
    fn acquire_connection(&self) -> ConnectionResult<std::sync::MutexGuard<Connection>>;
}

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
        let pool = config
            .create_pool(Some(Runtime::Tokio1))
            .map_err(|e| AdapterError::ConnectionError(format!("Failed to create pool: {}", e)))?;

        Ok(Self {
            pool,
            url: redis_url.to_string(),
        })
    }

    /// Get a connection from the pool
    pub async fn get(&self) -> Result<deadpool_redis::Connection, AdapterError> {
        self.pool
            .get()
            .await
            .map_err(|e| AdapterError::ConnectionError(format!("Failed to get connection: {}", e)))
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
                        warn!("Health check failed: {}", e);
                        Ok(false)
                    }
                }
            }
            Err(e) => {
                error!("Failed to get connection for health check: {}", e);
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

/// Legacy Redis client implementation (kept for compatibility)
pub struct RedisClient {
    client: Client,
    connection: Arc<Mutex<Connection>>,
}

impl RedisClient {
    pub fn from_url(url: &str) -> RedisResult<Self> {
        let client = Client::open(url)?;
        let connection = Arc::new(Mutex::new(
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(client.get_async_connection())?,
        ));

        Ok(Self { client, connection })
    }

    pub async fn ping(&self) -> ConnectionResult<bool> {
        let mut conn = self.acquire_connection()?;
        match redis::cmd("PING").query::<String>(&mut *conn) {
            Ok(response) => Ok(response == "PONG"),
            Err(e) => {
                warn!("Ping failed: {}", e);
                Ok(false)
            }
        }
    }

    pub async fn test_connection(&self) -> ConnectionResult<bool> {
        self.ping().await
    }
}

impl RedisConnectionHandler for RedisClient {
    fn acquire_connection(&self) -> ConnectionResult<std::sync::MutexGuard<Connection>> {
        match self.connection.lock() {
            Ok(guard) => Ok(guard),
            Err(poisoned) => {
                warn!("Mutex was poisoned, recovering connection");
                Ok(poisoned.into_inner())
            }
        }
    }
}

/// Legacy Redis pool implementation (kept for compatibility)
pub struct RedisPool {
    clients: Vec<Arc<RedisClient>>,
    current_index: std::sync::atomic::AtomicUsize,
}

impl RedisPool {
    pub fn new(redis_url: &str, pool_size: usize) -> RedisResult<Self> {
        let mut clients = Vec::new();

        for _ in 0..pool_size {
            clients.push(Arc::new(RedisClient::from_url(redis_url)?));
        }

        Ok(Self {
            clients,
            current_index: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    pub fn get_client(&self) -> Arc<RedisClient> {
        let index = self
            .current_index
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % self.clients.len();
        self.clients[index].clone()
    }

    pub async fn health_check(&self) -> ConnectionResult<bool> {
        let client = self.get_client();
        client.ping().await
    }
}

/// A trait for Redis clients that provides common functionality
pub trait RedisClientTrait {
    /// Get a connection from the client
    fn get_connection(&self) -> RedisResult<Connection>;

    /// Check if the connection is valid
    fn ping(&self) -> RedisResult<bool>;
}

impl RedisClientTrait for RedisClient {
    fn get_connection(&self) -> RedisResult<Connection> {
        self.get_new_connection()
    }

    fn ping(&self) -> RedisResult<bool> {
        self.ping()
    }
}

#[cfg(feature = "connection-pool")]
impl RedisClientTrait for RedisPool {
    fn get_connection(&self) -> RedisResult<Connection> {
        self.get_connection()
    }

    fn ping(&self) -> RedisResult<bool> {
        let mut conn = self.get_connection()?;
        let pong: String = redis::cmd("PING").query(&mut conn)?;
        Ok(pong == "PONG")
    }
}

/// Create a Redis client from a connection string
pub fn create_client(url: &str) -> RedisResult<RedisClient> {
    RedisClient::from_url(url)
}

/// Create a Redis pool from a connection string with the specified pool size
#[cfg(feature = "connection-pool")]
pub fn create_pool(url: &str, pool_size: u32) -> RedisResult<RedisPool> {
    RedisPool::new(url, pool_size)
}

/// Convert a Redis error to a standard error message
pub fn format_redis_error(error: &RedisError) -> String {
    format!("Redis error: {error}")
}
