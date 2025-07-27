//! Redis adapter module
//!
//! This module provides Redis database adapter implementation using deadpool-redis
//! for high-performance async operations and connection pooling.

pub mod backend;
pub mod client;
pub mod factory;
pub mod primitives;

// Re-export key types
pub use backend::RedisBackend;
pub use client::RedisConnectionPool as RedisPool; // Alias for compatibility
pub use client::RedisConnectionPool;

use redis::{Connection, RedisError, RedisResult, Script};
use std::sync::MutexGuard;

use primitives::admin::AdminOperations;
use primitives::bitmap::RedisBitmap;
use primitives::hash::RedisHash;
use primitives::set::RedisSet;
use primitives::string::RedisString;

/// Connection handling for Redis primitives
pub trait RedisConnectionHandler {
    /// Acquire connection with poison recovery
    fn acquire_connection(&self) -> Result<MutexGuard<'_, Connection>, RedisError>;
}

/// Redis data type adapters providing type-specific operations
pub mod types {
    pub use super::primitives::bitmap::RedisBitmap;
    pub use super::primitives::hash::RedisHash;
    pub use super::primitives::set::RedisSet;
    pub use super::primitives::string::RedisString;
    // Other Redis types will be added here as they're implemented:
    // pub use super::primitives::list::RedisList;
    pub use super::primitives::sorted_set::RedisSortedSet;
}

/// Commonly used Redis Lua scripts
pub mod scripts {
    use redis::Script;

    /// Get and set a key atomically
    pub fn get_set() -> Script {
        super::primitives::string::RedisString::get_set_script()
    }

    /// Set a key only if it doesn't exist
    pub fn set_if_not_exists() -> Script {
        super::primitives::string::RedisString::set_if_not_exists_script()
    }

    /// Update a key only if current value matches expected value
    pub fn compare_and_set_with_ttl() -> Script {
        super::primitives::string::RedisString::compare_and_set_with_ttl_script()
    }

    /// Increment multiple counters atomically
    pub fn multi_counter() -> Script {
        super::primitives::string::RedisString::multi_counter_script()
    }

    /// Set multiple keys with TTL atomically
    pub fn multi_set_with_ttl() -> Script {
        super::primitives::string::RedisString::multi_set_with_ttl_script()
    }

    /// Implement a rate limiter pattern
    pub fn rate_limiter() -> Script {
        super::primitives::string::RedisString::rate_limiter_script()
    }

    /// Hash operations
    pub fn hash_get_set() -> Script {
        super::primitives::hash::RedisHash::get_set_script()
    }

    pub fn hash_set_if_not_exists() -> Script {
        super::primitives::hash::RedisHash::set_if_not_exists_script()
    }

    pub fn hash_multi_set() -> Script {
        super::primitives::hash::RedisHash::multi_set_script()
    }

    pub fn hash_multi_delete() -> Script {
        super::primitives::hash::RedisHash::multi_delete_script()
    }
}


/// Error types for Redis operations
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Redis error: {0}")]
    Redis(#[from] RedisError),

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Serialization error: {0}")]
    Serialization(String),
}
