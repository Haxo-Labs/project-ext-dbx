//! Redis string primitive tests

use crate::redis::primitives::string::RedisString;
use redis::pipe;
use std::sync::{Arc, Mutex};

fn create_test_connection() -> Arc<Mutex<redis::Connection>> {
    // Use test configuration instead of hardcoded environment variable
    let redis_url = "redis://localhost:6379";
    let client = redis::Client::open(redis_url).unwrap_or_else(|_| {
        redis::Client::open("redis://localhost:6379").expect("Creating test client")
    });

    // Connection object for compilation
    match client.get_connection() {
        Ok(conn) => Arc::new(Mutex::new(conn)),
        Err(_) => {
            // Connection unavailable in test environment
            let client =
                redis::Client::open("redis://localhost:6379").expect("Creating test client");
            let conn = client.get_connection().unwrap_or_else(|_| {
                panic!("This test is only for compilation and is marked as ignored")
            });
            Arc::new(Mutex::new(conn))
        }
    }
}

#[test]
#[ignore = "Compilation test only"]
fn test_compile_operations() {
    // Compilation verification test
    let conn = create_test_connection();
    let redis_string = RedisString::new(conn);

    // Verify compilation
    let _set_cmd = redis_string.set("test_key", "test_value");
    let _get_cmd = redis_string.get("test_key");
    let _append_cmd = redis_string.append("test_key", "_suffix");
    let _incr_cmd = redis_string.incr("counter");
    let _set_ex_cmd = redis_string.setex("session", "token123", 60);
    let _decr_cmd = redis_string.decr("counter");
    let _incr_by_cmd = redis_string.incrby("score", 5);
    let _decr_by_cmd = redis_string.decrby("balance", 25);
}

#[test]
#[ignore = "Compilation test only"]
fn test_pipeline_methods() {
    // Test that pipelines can be used directly with cmd()
    let mut pipeline = pipe();

    let _pipe_ref1 = pipeline.cmd("SET").arg("key1").arg("value1");
    let _pipe_ref2 = pipeline.cmd("GET").arg("key2");
    let _pipe_ref3 = pipeline.cmd("INCRBY").arg("counter").arg(1);
}

#[test]
#[ignore = "Compilation test only"]
fn test_batch_operations() {
    let conn = create_test_connection();
    let redis_string = RedisString::new(conn);

    // Test data for batch operations
    let user_data = vec![
        ("user:1:name", "Alice"),
        ("user:1:email", "alice@example.com"),
        ("user:1:status", "active"),
    ];

    // Verify method compilation
    let _ = redis_string.set_many(user_data);

    // Test batch get
    let keys = vec!["user:1:name", "user:1:email", "user:2:name"];
    let _ = redis_string.get_many(keys);

    // Test batch set with expiry
    let ttl_data = vec![
        ("session:1", "token123", 3600),
        ("session:2", "token456", 1800),
    ];
    let _ = redis_string.set_many_with_expiry(ttl_data);

    // Test batch increment
    let counters = vec!["visits:page1", "visits:page2"];
    let _ = redis_string.incr_many(counters);

    // Test batch increment by amount
    let score_updates = vec![("user:1:score", 10), ("user:2:score", 5)];
    let _ = redis_string.incr_many_by(score_updates);

    // Test batch delete
    let expired_keys = vec!["session:old1", "session:old2"];
    let _ = redis_string.del_many(expired_keys);
}

#[test]
#[ignore = "Compilation test only"]
fn test_lua_scripts() {
    let conn = create_test_connection();
    let _redis_string = RedisString::new(conn);

    // Create some example scripts - compilation test only
    let _script = RedisString::create_script("return redis.call('GET', KEYS[1])");
}

#[test]
#[ignore = "Compilation test only"]
fn test_transaction() {
    let conn = create_test_connection();
    let _redis_string = RedisString::new(conn);

    // Compilation verification only
}

// Integration tests require Redis instance setup.

/// Examples of how to use RedisString with various features
///
/// These examples demonstrate how to use RedisString's features.
#[cfg(test)]
mod examples {
    use super::*;

    #[test]
    #[ignore = "Demonstration only"]
    fn example_patterns() {
        // Example connection setup
        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        let client = redis::Client::open(redis_url).unwrap_or_else(|_| {
            redis::Client::open("redis://localhost:6379").expect("Creating example client")
        });

        // Example connection object
        let conn =
            Arc::new(Mutex::new(client.get_connection().unwrap_or_else(|_| {
                panic!("Demonstration example - ignored test")
            })));

        let redis_string = RedisString::new(conn);

        // Create a script for demonstration
        let _set_and_get_script =
            RedisString::create_script("return redis.call('SET', KEYS[1], ARGV[1])");

        // Example 1: Pipeline with multiple string operations
        let _: Result<(String, String), redis::RedisError> = redis_string.with_pipeline(|pipe| {
            pipe.cmd("SET")
                .arg("key1")
                .arg("value1")
                .cmd("GET")
                .arg("some_key")
        });

        // Example 2: Transaction with multiple string operations
        let _: Result<(String, String), redis::RedisError> = redis_string.transaction(|pipe| {
            pipe.cmd("SET")
                .arg("tx:key1")
                .arg("value1")
                .cmd("SET")
                .arg("tx:key2")
                .arg("value2")
                .cmd("EXPIRE")
                .arg("tx:key1")
                .arg(3600)
        });

        // Example 3: Basic operations
        let _ = redis_string.set_many(vec![("batch:key1", "value1"), ("batch:key2", "value2")]);
    }
}
