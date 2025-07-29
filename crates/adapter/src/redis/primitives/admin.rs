use redis::{Connection, RedisResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use tracing::error;

use crate::redis::RedisConnectionHandler;

/// Administrative operations for Redis server management
#[derive(Clone)]
pub struct AdminOperations {
    conn: Arc<Mutex<Connection>>,
}

impl RedisConnectionHandler for AdminOperations {
    fn acquire_connection(&self) -> Result<MutexGuard<'_, Connection>, redis::RedisError> {
        match self.conn.lock() {
            Ok(guard) => Ok(guard),
            Err(poisoned) => {
                error!("Redis connection mutex poisoned, recovering");
                Ok(poisoned.into_inner())
            }
        }
    }
}

impl AdminOperations {
    /// Creates a new AdminOperations instance
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }

    /// Gets the connection reference for direct usage
    pub fn connection(&self) -> &Arc<Mutex<Connection>> {
        &self.conn
    }

    /// Tests connectivity to the Redis server
    pub fn ping(&self) -> RedisResult<bool> {
        let mut conn = self.acquire_connection()?;
        let response: String = redis::cmd("PING").query(&mut *conn)?;
        Ok(response == "PONG")
    }

    /// Sends a ping with a custom message
    pub fn ping_with_message(&self, message: &str) -> RedisResult<String> {
        let mut conn = self.acquire_connection()?;
        redis::cmd("PING").arg(message).query(&mut *conn)
    }

    /// Gets server information and statistics
    pub fn info(&self, section: Option<&str>) -> RedisResult<String> {
        let mut conn = self.acquire_connection()?;
        match section {
            Some(s) => redis::cmd("INFO").arg(s).query(&mut *conn),
            None => redis::cmd("INFO").query(&mut *conn),
        }
    }

    /// Retrieves specific sections of Redis server information.
    ///
    /// # Arguments
    ///
    /// * `section` - The specific section to retrieve (e.g., "server", "clients", "memory").
    ///
    /// # Returns
    ///
    /// A string containing the specified section's information.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dbx_adapter::redis::RedisConnectionPool;
    /// let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    /// let redis = RedisConnectionPool::new(&redis_url, 10).unwrap();
    /// let admin = redis.admin();
    /// let server_info = admin.info_section("server").unwrap();
    /// assert!(server_info.contains("redis_version"));
    /// ```
    pub fn info_section(&self, section: &str) -> RedisResult<String> {
        let mut conn = self.acquire_connection()?;
        redis::cmd("INFO").arg(section).query(&mut *conn)
    }

    /// Gets server configuration parameters
    pub fn config_get(&self, parameter: &str) -> RedisResult<Vec<String>> {
        let mut conn = self.acquire_connection()?;
        redis::cmd("CONFIG")
            .arg("GET")
            .arg(parameter)
            .query(&mut *conn)
    }

    /// Sets a server configuration parameter
    pub fn config_set(&self, parameter: &str, value: &str) -> RedisResult<String> {
        let mut conn = self.acquire_connection()?;
        redis::cmd("CONFIG")
            .arg("SET")
            .arg(parameter)
            .arg(value)
            .query(&mut *conn)
    }

    /// Resets server statistics
    pub fn config_resetstat(&self) -> RedisResult<String> {
        let mut conn = self.acquire_connection()?;
        redis::cmd("CONFIG").arg("RESETSTAT").query(&mut *conn)
    }

    /// Rewrites the configuration file
    pub fn config_rewrite(&self) -> RedisResult<String> {
        let mut conn = self.acquire_connection()?;
        redis::cmd("CONFIG").arg("REWRITE").query(&mut *conn)
    }

    /// Retrieves all Redis server configuration parameters.
    ///
    /// # Returns
    ///
    /// A HashMap containing all configuration parameters and their values.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dbx_adapter::redis::RedisConnectionPool;
    /// let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    /// let redis = RedisConnectionPool::new(&redis_url, 10).unwrap();
    /// let admin = redis.admin();
    /// let config = admin.config_get_all().unwrap();
    /// assert!(config.contains_key("timeout"));
    /// ```
    pub fn config_get_all(&self) -> RedisResult<HashMap<String, String>> {
        let mut conn = self.acquire_connection()?;
        let result: Vec<String> = redis::cmd("CONFIG").arg("GET").arg("*").query(&mut *conn)?;

        let mut config = HashMap::new();
        for chunk in result.chunks(2) {
            if chunk.len() == 2 {
                config.insert(chunk[0].clone(), chunk[1].clone());
            }
        }
        Ok(config)
    }

    /// Returns the number of keys in the current database
    pub fn dbsize(&self) -> RedisResult<usize> {
        let mut conn = self.acquire_connection()?;
        redis::cmd("DBSIZE").query(&mut *conn)
    }

    /// Removes all keys from the current database
    pub fn flushdb(&self) -> RedisResult<String> {
        let mut conn = self.acquire_connection()?;
        redis::cmd("FLUSHDB").query(&mut *conn)
    }

    /// Removes all keys from all databases
    pub fn flushall(&self) -> RedisResult<String> {
        let mut conn = self.acquire_connection()?;
        redis::cmd("FLUSHALL").query(&mut *conn)
    }

    /// Returns the current server time.
    ///
    /// # Returns
    ///
    /// A tuple containing (unix_time, microseconds).
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dbx_adapter::redis::RedisConnectionPool;
    /// let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    /// let redis = RedisConnectionPool::new(&redis_url, 10).unwrap();
    /// let admin = redis.admin();
    /// let (time, microseconds) = admin.time().unwrap();
    /// println!("Server time: {} (microseconds: {})", time, microseconds);
    /// ```
    pub fn time(&self) -> RedisResult<(i64, i64)> {
        let mut conn = self.acquire_connection()?;
        redis::cmd("TIME").query(&mut *conn)
    }

    /// Returns the Redis server version.
    ///
    /// # Returns
    ///
    /// A string containing the Redis version.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dbx_adapter::redis::RedisConnectionPool;
    /// let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    /// let redis = RedisConnectionPool::new(&redis_url, 10).unwrap();
    /// let admin = redis.admin();
    /// let version = admin.version().unwrap();
    /// println!("Redis version: {}", version);
    /// ```
    pub fn version(&self) -> RedisResult<String> {
        let info = self.info_section("server")?;
        for line in info.lines() {
            if line.starts_with("redis_version:") {
                return Ok(line.split(':').nth(1).unwrap_or("unknown").to_string());
            }
        }
        // If we can't find the version, return a default
        Ok("unknown".to_string())
    }

    /// Returns memory usage statistics.
    ///
    /// # Returns
    ///
    /// A HashMap containing memory usage information.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dbx_adapter::redis::RedisConnectionPool;
    /// let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    /// let redis = RedisConnectionPool::new(&redis_url, 10).unwrap();
    /// let admin = redis.admin();
    /// let memory = admin.memory_stats().unwrap();
    /// println!("Used memory: {} bytes", memory.get("used_memory").unwrap_or(&"unknown".to_string()));
    /// ```
    pub fn memory_stats(&self) -> RedisResult<HashMap<String, String>> {
        let info = self.info_section("memory")?;
        let mut stats = HashMap::new();

        for line in info.lines() {
            if let Some((key, value)) = line.split_once(':') {
                stats.insert(key.to_string(), value.to_string());
            }
        }
        Ok(stats)
    }

    /// Returns client connection statistics.
    ///
    /// # Returns
    ///
    /// A HashMap containing client connection information.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dbx_adapter::redis::RedisConnectionPool;
    /// let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    /// let redis = RedisConnectionPool::new(&redis_url, 10).unwrap();
    /// let admin = redis.admin();
    /// let clients = admin.client_stats().unwrap();
    /// println!("Connected clients: {}", clients.get("connected_clients").unwrap_or(&"unknown".to_string()));
    /// ```
    pub fn client_stats(&self) -> RedisResult<HashMap<String, String>> {
        let info = self.info_section("clients")?;
        let mut stats = HashMap::new();

        for line in info.lines() {
            if let Some((key, value)) = line.split_once(':') {
                stats.insert(key.to_string(), value.to_string());
            }
        }
        Ok(stats)
    }

    /// Returns server statistics.
    ///
    /// # Returns
    ///
    /// A HashMap containing server statistics.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dbx_adapter::redis::RedisConnectionPool;
    /// let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    /// let redis = RedisConnectionPool::new(&redis_url, 10).unwrap();
    /// let admin = redis.admin();
    /// let stats = admin.server_stats().unwrap();
    /// println!("Total commands processed: {}", stats.get("total_commands_processed").unwrap_or(&"unknown".to_string()));
    /// ```
    pub fn server_stats(&self) -> RedisResult<HashMap<String, String>> {
        let info = self.info_section("stats")?;
        let mut stats = HashMap::new();

        for line in info.lines() {
            if let Some((key, value)) = line.split_once(':') {
                stats.insert(key.to_string(), value.to_string());
            }
        }
        Ok(stats)
    }

    /// Returns a health check of the Redis server.
    ///
    /// Performs multiple checks including ping, database size,
    /// and server information to ensure the Redis server is healthy.
    ///
    /// # Returns
    ///
    /// A result containing health check information.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dbx_adapter::redis::RedisConnectionPool;
    /// let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    /// let redis = RedisConnectionPool::new(&redis_url, 10).unwrap();
    /// let admin = redis.admin();
    /// let health = admin.health_check().unwrap();
    /// println!("Redis server is healthy: {}", health.is_healthy);
    /// ```
    pub fn health_check(&self) -> RedisResult<HealthCheck> {
        let ping_result = self.ping();
        let dbsize_result = self.dbsize();
        let version_result = self.version();
        let memory_result = self.memory_stats();

        let is_healthy = ping_result.is_ok() && dbsize_result.is_ok() && version_result.is_ok();

        Ok(HealthCheck {
            is_healthy,
            ping_response: ping_result
                .map(|success| {
                    if success {
                        "PONG".to_string()
                    } else {
                        "FAILED".to_string()
                    }
                })
                .unwrap_or_else(|_| "FAILED".to_string()),
            database_size: dbsize_result.map(|size| size as i64).unwrap_or(-1),
            version: version_result.unwrap_or_else(|_| "unknown".to_string()),
            memory_usage: memory_result.unwrap_or_default(),
        })
    }

    /// Returns a server status report.
    ///
    /// Collects various statistics and information about the Redis server
    /// and returns them in a structured format.
    ///
    /// # Returns
    ///
    /// A result containing the server status report.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dbx_adapter::redis::RedisConnectionPool;
    /// let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    /// let redis = RedisConnectionPool::new(&redis_url, 10).unwrap();
    /// let admin = redis.admin();
    /// let status = admin.server_status().unwrap();
    /// println!("Server uptime: {} seconds", status.uptime_seconds);
    /// ```
    pub fn server_status(&self) -> RedisResult<ServerStatus> {
        let info = self.info(None)?;
        let (time, _) = self.time()?;

        let mut status = ServerStatus {
            timestamp: time,
            uptime_seconds: 0,
            connected_clients: 0,
            used_memory: 0,
            total_commands_processed: 0,
            keyspace_hits: 0,
            keyspace_misses: 0,
            version: "unknown".to_string(),
            role: "unknown".to_string(),
        };

        for line in info.lines() {
            if let Some((key, value)) = line.split_once(':') {
                match key {
                    "uptime_in_seconds" => {
                        status.uptime_seconds = value.parse().unwrap_or(0);
                    }
                    "connected_clients" => {
                        status.connected_clients = value.parse().unwrap_or(0);
                    }
                    "used_memory" => {
                        status.used_memory = value.parse().unwrap_or(0);
                    }
                    "total_commands_processed" => {
                        status.total_commands_processed = value.parse().unwrap_or(0);
                    }
                    "keyspace_hits" => {
                        status.keyspace_hits = value.parse().unwrap_or(0);
                    }
                    "keyspace_misses" => {
                        status.keyspace_misses = value.parse().unwrap_or(0);
                    }
                    "redis_version" => {
                        status.version = value.to_string();
                    }
                    "role" => {
                        status.role = value.to_string();
                    }
                    _ => {}
                }
            }
        }

        Ok(status)
    }
}

/// Health check information for the Redis server.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HealthCheck {
    /// Whether the server is responding to commands
    pub is_healthy: bool,
    /// Response from the PING command
    pub ping_response: String,
    /// Number of keys in the current database
    pub database_size: i64,
    /// Redis server version
    pub version: String,
    /// Memory usage statistics
    pub memory_usage: HashMap<String, String>,
}

/// Server status information.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServerStatus {
    /// Unix timestamp of the status check
    pub timestamp: i64,
    /// Server uptime in seconds
    pub uptime_seconds: i64,
    /// Number of connected clients
    pub connected_clients: i64,
    /// Memory usage in bytes
    pub used_memory: i64,
    /// Total commands processed
    pub total_commands_processed: i64,
    /// Number of keyspace hits
    pub keyspace_hits: i64,
    /// Number of keyspace misses
    pub keyspace_misses: i64,
    /// Redis server version
    pub version: String,
    /// Server role (master/slave)
    pub role: String,
}

impl ServerStatus {
    /// Returns the hit rate as a percentage.
    ///
    /// # Returns
    ///
    /// Hit rate percentage, or 0.0 if no commands have been processed.
    pub fn hit_rate(&self) -> f64 {
        let total = self.keyspace_hits + self.keyspace_misses;
        if total == 0 {
            0.0
        } else {
            ((self.keyspace_hits as f64) / (total as f64)) * 100.0
        }
    }

    /// Returns the memory usage in megabytes.
    ///
    /// # Returns
    ///
    /// Memory usage in MB.
    pub fn memory_usage_mb(&self) -> f64 {
        (self.used_memory as f64) / 1024.0 / 1024.0
    }

    /// Returns the commands per second rate.
    ///
    /// # Returns
    ///
    /// Commands per second, or 0.0 if uptime is 0.
    pub fn commands_per_second(&self) -> f64 {
        if self.uptime_seconds == 0 {
            0.0
        } else {
            (self.total_commands_processed as f64) / (self.uptime_seconds as f64)
        }
    }
}

#[cfg(test)]
mod tests {

    fn _get_redis_url() -> String {
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string())
    }
}
