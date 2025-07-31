//! Redis bitmap primitive tests

use crate::redis::primitives::bitmap::RedisBitmap;
use redis::pipe;
use std::sync::{Arc, Mutex};

fn create_test_connection() -> Arc<Mutex<redis::Connection>> {
    let redis_url = "redis://localhost:6379";
    let client = redis::Client::open(redis_url).unwrap_or_else(|_| {
        redis::Client::open("redis://localhost:6379").expect("Creating test client")
    });

    match client.get_connection() {
        Ok(conn) => Arc::new(Mutex::new(conn)),
        Err(_) => {
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
#[ignore = "requires redis server"]
fn test_compile_operations() {
    let conn = create_test_connection();
    let redis_bitmap = RedisBitmap::new(conn);

    let _setbit_cmd = redis_bitmap.setbit("test_bitmap", 0, true);
    let _getbit_cmd = redis_bitmap.getbit("test_bitmap", 0);
    let _bitcount_cmd = redis_bitmap.bitcount("test_bitmap", None, None);
    let _bitcount_range_cmd = redis_bitmap.bitcount_range("test_bitmap", 0, 10);
    let _bitop_and_cmd = redis_bitmap.bitop_and("dest", &["bitmap1", "bitmap2"]);
    let _bitop_or_cmd = redis_bitmap.bitop_or("dest", &["bitmap1", "bitmap2"]);
    let _bitop_xor_cmd = redis_bitmap.bitop_xor("dest", &["bitmap1", "bitmap2"]);
    let _bitop_not_cmd = redis_bitmap.bitop_not("dest", "source");
    let _bitpos_cmd = redis_bitmap.bitpos("test_bitmap", true);
    let _bitpos_range_cmd = redis_bitmap.bitpos_range("test_bitmap", true, 0, 10);
    let _get_cmd = redis_bitmap.get("test_bitmap");
    let _set_cmd = redis_bitmap.set("test_bitmap", &[0x01, 0x02, 0x03]);
    let _strlen_cmd = redis_bitmap.strlen("test_bitmap");
    let _del_cmd = redis_bitmap.del("test_bitmap");
    let _exists_cmd = redis_bitmap.exists("test_bitmap");
    let _ttl_cmd = redis_bitmap.ttl("test_bitmap");
    let _expire_cmd = redis_bitmap.expire("test_bitmap", 3600);
    let _keys_cmd = redis_bitmap.keys("test_bitmap*");
}

#[test]
#[ignore = "requires redis server"]
fn test_pipeline_methods() {
    let mut pipeline = pipe();

    let _pipe_ref1 = pipeline.cmd("SETBIT").arg("bitmap1").arg(0).arg(1);
    let _pipe_ref2 = pipeline.cmd("BITCOUNT").arg("bitmap1");
    let _pipe_ref3 = pipeline.cmd("GETBIT").arg("bitmap1").arg(0);
}

#[test]
#[ignore = "requires redis server"]
fn test_batch_operations() {
    let conn = create_test_connection();
    let redis_bitmap = RedisBitmap::new(conn);

    let bit_offsets = vec![(0, true), (1, false), (2, true), (3, false)];
    let offsets = vec![0, 1, 2, 3];
    let keys = vec!["bitmap1", "bitmap2", "bitmap3"];

    let _ = redis_bitmap.setbit_many("test_bitmap", bit_offsets);
    let _ = redis_bitmap.getbit_many("test_bitmap", offsets);
    let _ = redis_bitmap.bitcount_many(keys.clone());
    let _ = redis_bitmap.del_many(keys.clone());
    let _ = redis_bitmap.exists_many(keys);
}

#[test]
#[ignore = "requires redis server"]
fn test_lua_scripts() {
    let conn = create_test_connection();
    let _redis_bitmap = RedisBitmap::new(conn);

    let _script = RedisBitmap::create_script("return redis.call('BITCOUNT', KEYS[1])");
    let _setbit_script = RedisBitmap::setbit_and_get_previous_script();
}

#[test]
#[ignore = "requires redis server"]
fn test_transaction() {
    let conn = create_test_connection();
    let _redis_bitmap = RedisBitmap::new(conn);
}

#[cfg(test)]
mod examples {
    use super::*;

    #[test]
    #[ignore = "example code"]
    fn example_patterns() {
        let redis_url = "redis://localhost:6379";
        let client = redis::Client::open(redis_url).unwrap_or_else(|_| {
            redis::Client::open("redis://localhost:6379").expect("Creating example client")
        });

        let conn = Arc::new(Mutex::new(
            client
                .get_connection()
                .unwrap_or_else(|_| panic!("Example test - ignored")),
        ));

        let redis_bitmap = RedisBitmap::new(conn);

        let _setbit_script =
            RedisBitmap::create_script("return redis.call('SETBIT', KEYS[1], ARGV[1], ARGV[2])");

        let _: Result<(bool, u64), redis::RedisError> = redis_bitmap.with_pipeline(|pipe| {
            pipe.cmd("SETBIT")
                .arg("bitmap1")
                .arg(0)
                .arg(1)
                .cmd("BITCOUNT")
                .arg("bitmap1")
                .cmd("GETBIT")
                .arg("bitmap1")
                .arg(0)
        });

        let _: Result<(bool, bool), redis::RedisError> = redis_bitmap.transaction(|pipe| {
            pipe.cmd("SETBIT")
                .arg("tx:bitmap1")
                .arg(0)
                .arg(1)
                .cmd("SETBIT")
                .arg("tx:bitmap2")
                .arg(1)
                .arg(1)
                .cmd("EXPIRE")
                .arg("tx:bitmap1")
                .arg(3600)
        });

        let _ = redis_bitmap.setbit_many("batch:bitmap", vec![(0, true), (1, false), (2, true)]);
        let _ = redis_bitmap.getbit_many("batch:bitmap", vec![0, 1, 2]);
    }
}
