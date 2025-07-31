//! Redis sorted set primitive tests

use crate::redis::primitives::sorted_set::RedisSortedSet;
use redis::pipe;
use std::sync::{Arc, Mutex};

// Create test connection for compilation validation
fn create_test_connection() -> Arc<Mutex<redis::Connection>> {
    // Test client without Redis server dependency
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
    let redis_sorted_set = RedisSortedSet::new(conn);

    // Verify basic compilation only
    let _zadd_cmd = redis_sorted_set.zadd("test_zset", &[(1.0, "member1")]);
    let _zrange_cmd = redis_sorted_set.zrange("test_zset", 0, -1);
    let _zcard_cmd = redis_sorted_set.zcard("test_zset");
}

#[test]
#[ignore = "Compilation test only"]
fn test_pipeline_methods() {
    // Test that pipelines can be used directly with cmd()
    let mut pipeline = pipe();

    let _pipe_ref1 = pipeline.cmd("ZADD").arg("zset1").arg(1.0).arg("member1");
    let _pipe_ref2 = pipeline.cmd("ZCARD").arg("zset1");
    let _pipe_ref3 = pipeline.cmd("ZSCORE").arg("zset1").arg("member1");
}

#[test]
#[ignore = "Compilation test only"]
fn test_batch_operations() {
    let conn = create_test_connection();
    let redis_sorted_set = RedisSortedSet::new(conn);

    // Basic compilation test only
    let _zcard_cmd = redis_sorted_set.zcard("test_zset");
}

#[test]
#[ignore = "Compilation test only"]
fn test_lua_scripts() {
    let conn = create_test_connection();
    let _redis_sorted_set = RedisSortedSet::new(conn);

    // Create some example scripts
    let _script = RedisSortedSet::create_script("return redis.call('ZCARD', KEYS[1])");
}

#[test]
#[ignore = "Compilation test only"]
fn test_transaction() {
    let conn = create_test_connection();
    let _redis_sorted_set = RedisSortedSet::new(conn);

    // Compilation verification only
}

/// Examples of how to use RedisSortedSet with various features
#[cfg(test)]
mod examples {
    use super::*;

    #[test]
    #[ignore = "Demonstration only"]
    fn example_patterns() {
        // Example connection setup
        let redis_url = "redis://localhost:6379";
        let client = redis::Client::open(redis_url).unwrap_or_else(|_| {
            redis::Client::open("redis://localhost:6379").expect("Creating example client")
        });

        // Example connection object
        let conn =
            Arc::new(Mutex::new(client.get_connection().unwrap_or_else(|_| {
                panic!("Demonstration example - ignored test")
            })));

        let redis_sorted_set = RedisSortedSet::new(conn);

        // Create a script for demonstration
        let _zadd_script =
            RedisSortedSet::create_script("return redis.call('ZADD', KEYS[1], ARGV[1], ARGV[2])");

        // Example 1: Pipeline with multiple sorted set operations
        let _: Result<(i64, i64), redis::RedisError> = redis_sorted_set.with_pipeline(|pipe| {
            pipe.cmd("ZADD")
                .arg("zset1")
                .arg(1.0)
                .arg("member1")
                .cmd("ZCARD")
                .arg("zset1")
        });

        // Example 2: Transaction with multiple sorted set operations
        let _: Result<(i64, i64), redis::RedisError> = redis_sorted_set.transaction(|pipe| {
            pipe.cmd("ZADD")
                .arg("tx:zset1")
                .arg(1.0)
                .arg("member1")
                .cmd("ZADD")
                .arg("tx:zset2")
                .arg(2.0)
                .arg("member2")
                .cmd("EXPIRE")
                .arg("tx:zset1")
                .arg(3600)
        });

        // Example 3: Basic operations
        let _ = redis_sorted_set.zadd("batch:zset", &[(1.0, "member1"), (2.0, "member2")]);
        let _ = redis_sorted_set.zrange("batch:zset", 0, -1);
    }
}
