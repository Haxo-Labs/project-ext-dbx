//! Redis string primitive tests

use crate::redis::primitives::string::*;


        // Connection object for compilation
        match client.get_connection() {
            Ok(conn) => Arc::new(Mutex::new(conn)),
            Err(_) => {
                // Connection unavailable in test environment
                let client =
                    redis::Client::open("redis://localhost:6379").expect("Creating test client");
                let conn = client
                    .get_connection()
                    .unwrap_or_else(|_| panic!("Test compilation only"));
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

        // Create some example scripts
        let _script = RedisString::create_script("return redis.call('GET', KEYS[1])");
        let _get_set_script = RedisString::get_set_script();

        // Test pipeline integration with scripts
        let mut pipe = redis::pipe();
        _redis_string.add_script_to_pipeline(
            &mut pipe,
            script_constants::PING_SCRIPT,
            vec!["key1"],
            vec!["new_value"],
        );
    }

    #[test]
    #[ignore = "Compilation test only"]
    fn test_transaction() {
        let conn = create_test_connection();
        let _redis_string = RedisString::new(conn);

        // Compilation verification only
    }

    // Integration tests require Redis instance setup.
}

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
        let _increment_script =
            RedisString::create_script("return redis.call('INCRBY', KEYS[1], ARGV[1])");

        // Example 1: Pipeline with multiple commands
        let _: Result<(String, String, i64), redis::RedisError> =
            redis_string.with_pipeline(|pipe| {
                pipe.cmd("SET")
                    .arg("key1")
                    .arg("value1")
                    .cmd("GET")
                    .arg("key2")
                    .cmd("INCR")
                    .arg("counter")
            });

        // Example 2: Transaction with multiple commands
        let _: Result<(String, i64, i64), redis::RedisError> = redis_string.transaction(|pipe| {
            pipe.cmd("SET")
                .arg("tx:key")
                .arg("value")
                .cmd("EXPIRE")
                .arg("tx:key")
                .arg(3600)
                .cmd("INCR")
                .arg("tx:counter")
        });

        // Example 3: Using scripts in pipelines
        let _: Result<(i64, String), redis::RedisError> = redis_string.with_pipeline(|pipe| {
            redis_string.add_script_to_pipeline(
                pipe,
                script_constants::PING_SCRIPT,
                vec!["counter"],
                vec![5],
            );

            pipe.cmd("GET").arg("some_key")
        });

        // Example 4: Batch operations
        let _ = redis_string.set_many(vec![("batch:key1", "value1"), ("batch:key2", "value2")]);
    }

