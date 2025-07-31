
    use redis::pipe;
    use std::sync::{Arc, Mutex};

    // Create test connection for compilation validation
    fn create_test_connection() -> Arc<Mutex<redis::Connection>> {
        // Test client without Redis server dependency
        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
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

        // Verify compilation
        let _zadd_cmd = redis_sorted_set.zadd("test_zset", &[(1.0, "member1"), (2.0, "member2")]);
        let _zrange_cmd = redis_sorted_set.zrange("test_zset", 0, -1);
        let _zrem_cmd = redis_sorted_set.zrem("test_zset", &["member1"]);
        let _zcard_cmd = redis_sorted_set.zcard("test_zset");
        let _zscore_cmd = redis_sorted_set.zscore("test_zset", "member1");
        let _zrank_cmd = redis_sorted_set.zrank("test_zset", "member1");
        let _zrevrank_cmd = redis_sorted_set.zrevrank("test_zset", "member1");
        let _zincrby_cmd = redis_sorted_set.zincrby("test_zset", 1.5, "member1");
        let _zcount_cmd = redis_sorted_set.zcount("test_zset", 0.0, 10.0);
        let _zrangebyscore_cmd = redis_sorted_set.zrangebyscore("test_zset", 0.0, 10.0);
        let _zrevrangebyscore_cmd = redis_sorted_set.zrevrangebyscore("test_zset", 10.0, 0.0);
        let _zremrangebyrank_cmd = redis_sorted_set.zremrangebyrank("test_zset", 0, 1);
        let _zremrangebyscore_cmd = redis_sorted_set.zremrangebyscore("test_zset", 0.0, 5.0);
        let _zinterstore_cmd = redis_sorted_set.zinterstore("dest", &["zset1", "zset2"]);
        let _zunionstore_cmd = redis_sorted_set.zunionstore("dest", &["zset1", "zset2"]);
    }

    #[test]
    #[ignore = "Compilation test only"]
    fn test_pipeline_methods() {
        // Test that pipelines can be used directly with cmd()
        let mut pipeline = pipe();

        let _pipe_ref1 = pipeline
            .cmd("ZADD")
            .arg("zset1")
            .arg(1.0)
            .arg("member1")
            .arg(2.0)
            .arg("member2");
        let _pipe_ref2 = pipeline.cmd("ZRANGE").arg("zset1").arg(0).arg(-1);
        let _pipe_ref3 = pipeline.cmd("ZCARD").arg("zset1");
    }

    #[test]
    #[ignore = "Compilation test only"]
    fn test_batch_operations() {
        let conn = create_test_connection();
        let redis_sorted_set = RedisSortedSet::new(conn);

        // Test data for batch operations
        let zset_data = vec![
            (
                "zset1",
                vec![(1.0, "member1"), (2.0, "member2"), (3.0, "member3")],
            ),
            (
                "zset2",
                vec![(2.0, "member2"), (3.0, "member3"), (4.0, "member4")],
            ),
            (
                "zset3",
                vec![(1.0, "member1"), (4.0, "member4"), (5.0, "member5")],
            ),
        ];

        // Verify method compilation
        let _ = redis_sorted_set.zadd_many(zset_data);

        // Test batch remove
        let remove_data = vec![("zset1", vec!["member1"]), ("zset2", vec!["member2"])];
        let _ = redis_sorted_set.zrem_many(remove_data);

        // Test batch get ranges
        let range_data = vec![("zset1", 0, -1), ("zset2", 0, 2), ("zset3", -2, -1)];
        let _ = redis_sorted_set.zrange_many(range_data);

        // Test batch get scores
        let score_checks = vec![("zset1", "member1"), ("zset2", "member2")];
        let _ = redis_sorted_set.zscore_many(score_checks);

        // Test batch get ranks
        let rank_checks = vec![("zset1", "member1"), ("zset2", "member2")];
        let _ = redis_sorted_set.zrank_many(rank_checks);

        // Test batch get cardinalities
        let zset_keys = vec!["zset1", "zset2", "zset3"];
        let _ = redis_sorted_set.zcard_many(zset_keys);

        // Test batch delete
        let expired_keys = vec!["old_zset1", "old_zset2"];
        let _ = redis_sorted_set.del_many(expired_keys);
    }

    #[test]
    #[ignore = "Compilation test only"]
    fn test_lua_scripts() {
        let conn = create_test_connection();
        let _redis_sorted_set = RedisSortedSet::new(conn);

        // Create some example scripts
        let _script = RedisSortedSet::create_script("return redis.call('ZCARD', KEYS[1])");
        let add_script = RedisSortedSet::add_and_get_rank_script();

        // Test pipeline integration with scripts
        let mut pipe = redis::pipe();
        RedisSortedSet::add_script_to_pipeline(
            &mut pipe,
            &add_script,
            &["zset1"],
            &["member1", "10.0"],
        );
    }

    #[test]
    #[ignore = "Compilation test only"]
    fn test_transaction() {
        let conn = create_test_connection();
        let _redis_sorted_set = RedisSortedSet::new(conn);

        // Compilation verification only
    }

    // Integration tests require Redis instance setup.
}

/// Examples of how to use RedisSortedSet with various features
///
/// These examples demonstrate how to use RedisSortedSet's features
/// in real-world scenarios.
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

        let redis_sorted_set = RedisSortedSet::new(conn);

        // Create a script for demonstration
        let incr_script = RedisSortedSet::create_script(
            "return redis.call('ZINCRBY', KEYS[1], ARGV[1], ARGV[2])",
        );

        // Example 1: Pipeline with multiple sorted set operations
        let _: Result<(usize, Vec<String>), redis::RedisError> =
            redis_sorted_set.with_pipeline(|pipe| {
                pipe.cmd("ZADD")
                    .arg("zset1")
                    .arg(1.0)
                    .arg("member1")
                    .arg(2.0)
                    .arg("member2")
                    .cmd("ZRANGE")
                    .arg("zset1")
                    .arg(0)
                    .arg(-1)
                    .cmd("ZCARD")
                    .arg("zset1")
            });

        // Example 2: Transaction with multiple sorted set operations
        let _: Result<(usize, usize), redis::RedisError> = redis_sorted_set.transaction(|pipe| {
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

        // Example 3: Using scripts in pipelines
        let _: Result<(f64, Vec<String>), redis::RedisError> =
            redis_sorted_set.with_pipeline(|pipe| {
                RedisSortedSet::add_script_to_pipeline(
                    pipe,
                    &incr_script,
                    &["zset1"],
                    &["1.5", "member1"],
                );

                pipe.cmd("ZRANGE").arg("zset1").arg(0).arg(-1)
            });

        // Example 4: Batch operations
        let _ = redis_sorted_set.zadd_many(vec![
            ("batch:zset1", vec![(1.0, "member1"), (2.0, "member2")]),
            ("batch:zset2", vec![(2.0, "member2"), (3.0, "member3")]),
        ]);

        // Example 5: Sorted set operations
        let _ = redis_sorted_set.zrange("zset1", 0, -1);
        let _ = redis_sorted_set.zrangebyscore("zset1", 0.0, 10.0);
        let _ = redis_sorted_set.zrevrange("zset1", 0, 2);
        let _ = redis_sorted_set.zinterstore("result", &["zset1", "zset2"]);
        let _ = redis_sorted_set.zunionstore("result", &["zset1", "zset2"]);
    }

