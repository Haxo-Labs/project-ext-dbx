use redis::{Commands, Connection, FromRedisValue, Pipeline, RedisResult, Script, ToRedisArgs};
use std::sync::{Arc, Mutex, MutexGuard};
use tracing::error;

/// Internal script storage for debugging and testing purposes.
///
/// The Redis crate doesn't expose script content after creation,
/// so we store commonly used scripts as constants for reference.
mod script_constants {
    /// Ping script for testing script execution
    #[allow(dead_code)]
    pub const PING_SCRIPT: &str = "return redis.call('PING')";
}

use crate::redis::RedisConnectionHandler;

/// Redis set operations with pipeline and transaction support.
///
/// Operations include:
/// - Individual commands (sadd, srem, etc.)
/// - Pipelined operations (for efficiency)
/// - Transactions (for atomicity)
/// - Lua script execution (for complex operations)
#[derive(Clone)]
pub struct RedisSet {
    conn: Arc<Mutex<Connection>>,
}

impl RedisConnectionHandler for RedisSet {
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

/// Core implementation with set operations
impl RedisSet {
    /// Creates a new RedisSet instance with the provided connection
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }

    /// Gets the connection reference for direct usage
    pub fn connection(&self) -> &Arc<Mutex<Connection>> {
        &self.conn
    }

    /// Adds one or more members to a set
    pub fn sadd(&self, key: &str, members: &[&str]) -> RedisResult<usize> {
        let mut conn = self.acquire_connection()?;
        conn.sadd(key, members)
    }

    /// Removes one or more members from a set
    pub fn srem(&self, key: &str, members: &[&str]) -> RedisResult<usize> {
        let mut conn = self.acquire_connection()?;
        conn.srem(key, members)
    }

    /// Gets all members of a set
    pub fn smembers(&self, key: &str) -> RedisResult<Vec<String>> {
        let mut conn = self.acquire_connection()?;
        conn.smembers(key)
    }

    /// Checks if a member exists in a set
    pub fn sismember(&self, key: &str, member: &str) -> RedisResult<bool> {
        let mut conn = self.acquire_connection()?;
        let result: i32 = conn.sismember(key, member)?;
        Ok(result == 1)
    }

    /// Gets the number of members in a set
    pub fn scard(&self, key: &str) -> RedisResult<usize> {
        let mut conn = self.acquire_connection()?;
        conn.scard(key)
    }

    /// Gets a random member from a set
    pub fn srandmember(&self, key: &str) -> RedisResult<Option<String>> {
        let mut conn = self.acquire_connection()?;
        conn.srandmember(key)
    }

    /// Gets multiple random members from a set
    pub fn srandmember_multiple(&self, key: &str, count: isize) -> RedisResult<Vec<String>> {
        let mut conn = self.acquire_connection()?;
        redis::cmd("SRANDMEMBER")
            .arg(key)
            .arg(count)
            .query(&mut *conn)
    }

    /// Removes and returns a random member from a set
    pub fn spop(&self, key: &str) -> RedisResult<Option<String>> {
        let mut conn = self.acquire_connection()?;
        conn.spop(key)
    }

    /// Removes and returns multiple random members from a set
    pub fn spop_multiple(&self, key: &str, count: usize) -> RedisResult<Vec<String>> {
        let mut conn = self.acquire_connection()?;
        redis::cmd("SPOP").arg(key).arg(count).query(&mut *conn)
    }

    /// Moves a member from one set to another
    pub fn smove(&self, source: &str, destination: &str, member: &str) -> RedisResult<bool> {
        let mut conn = self.acquire_connection()?;
        let result: i32 = conn.smove(source, destination, member)?;
        Ok(result == 1)
    }

    /// Gets the union of multiple sets
    pub fn sunion(&self, keys: &[&str]) -> RedisResult<Vec<String>> {
        let mut conn = self.acquire_connection()?;
        conn.sunion(keys)
    }

    /// Gets the intersection of multiple sets
    pub fn sinter(&self, keys: &[&str]) -> RedisResult<Vec<String>> {
        let mut conn = self.acquire_connection()?;
        conn.sinter(keys)
    }

    /// Gets the difference between sets
    pub fn sdiff(&self, keys: &[&str]) -> RedisResult<Vec<String>> {
        let mut conn = self.acquire_connection()?;
        conn.sdiff(keys)
    }

    /// Stores the union of multiple sets in a destination key
    pub fn sunionstore(&self, destination: &str, keys: &[&str]) -> RedisResult<usize> {
        let mut conn = self.acquire_connection()?;
        conn.sunionstore(destination, keys)
    }

    /// Stores the intersection of multiple sets in a destination key
    pub fn sinterstore(&self, destination: &str, keys: &[&str]) -> RedisResult<usize> {
        let mut conn = self.acquire_connection()?;
        conn.sinterstore(destination, keys)
    }

    /// Stores the difference between sets in a destination key
    pub fn sdiffstore(&self, destination: &str, keys: &[&str]) -> RedisResult<usize> {
        let mut conn = self.acquire_connection()?;
        conn.sdiffstore(destination, keys)
    }

    /// Returns a random member from a set without removing it
    pub fn srandmember_one(&self, key: &str) -> RedisResult<Option<String>> {
        let mut conn = self.acquire_connection()?;
        conn.srandmember(key)
    }

    /// Returns all members of a set as a HashSet
    pub fn smembers_as_set(&self, key: &str) -> RedisResult<std::collections::HashSet<String>> {
        let mut conn = self.acquire_connection()?;
        conn.smembers(key)
    }

    /// Deletes a set
    pub fn del(&self, key: &str) -> RedisResult<()> {
        let mut conn = self.acquire_connection()?;
        conn.del(key)
    }

    /// Checks if a set exists
    pub fn exists(&self, key: &str) -> RedisResult<bool> {
        let mut conn = self.acquire_connection()?;
        let result: i32 = conn.exists(key)?;
        Ok(result == 1)
    }

    /// Gets the TTL of a set in seconds
    pub fn ttl(&self, key: &str) -> RedisResult<i64> {
        let mut conn = self.acquire_connection()?;
        conn.ttl(key)
    }

    /// Sets the TTL of a set in seconds
    pub fn expire(&self, key: &str, seconds: u64) -> RedisResult<bool> {
        let mut conn = self.acquire_connection()?;
        let result: i32 = conn.expire(key, seconds as i64)?;
        Ok(result == 1)
    }

    /// Gets keys matching a pattern
    pub fn keys(&self, pattern: &str) -> RedisResult<Vec<String>> {
        let mut conn = self.acquire_connection()?;
        conn.keys(pattern)
    }
}

/// Pipeline operations
impl RedisSet {
    /// Executes a function with a pipeline
    ///
    /// # Example
    /// ```ignore
    /// # use redis::{Connection, RedisResult};
    /// # use std::sync::{Arc, Mutex};
    /// # use dbx_adapter::redis::primitives::set::RedisSet;
    /// # fn example(conn: Connection) -> RedisResult<()> {
    /// let redis_set = RedisSet::new(Arc::new(Mutex::new(conn)));
    /// let results: (usize, Vec<String>) = redis_set.with_pipeline(|pipe| {
    ///     pipe.cmd("SADD").arg("set1").arg("member1").arg("member2")
    ///        .cmd("SMEMBERS").arg("set1")
    /// })?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_pipeline<F, T>(&self, f: F) -> RedisResult<T>
    where
        F: FnOnce(&mut Pipeline) -> &mut Pipeline,
        T: FromRedisValue,
    {
        let mut conn = self.acquire_connection()?;
        let mut pipe = redis::pipe();
        let result = f(&mut pipe).query(&mut *conn)?;
        Ok(result)
    }

    /// Helper: batch add multiple members to multiple sets using pipeline
    pub fn sadd_many(&self, set_members: Vec<(&str, Vec<&str>)>) -> RedisResult<Vec<usize>> {
        self.with_pipeline(|pipe| {
            for (set_key, members) in set_members {
                let mut cmd = pipe.cmd("SADD").arg(set_key);
                for member in members {
                    cmd = cmd.arg(member);
                }
            }
            pipe
        })
    }

    /// Helper: batch remove multiple members from multiple sets using pipeline
    pub fn srem_many(&self, set_members: Vec<(&str, Vec<&str>)>) -> RedisResult<Vec<usize>> {
        self.with_pipeline(|pipe| {
            for (set_key, members) in set_members {
                let mut cmd = pipe.cmd("SREM").arg(set_key);
                for member in members {
                    cmd = cmd.arg(member);
                }
            }
            pipe
        })
    }

    /// Helper: batch get members from multiple sets using pipeline
    pub fn smembers_many(&self, keys: Vec<&str>) -> RedisResult<Vec<Vec<String>>> {
        self.with_pipeline(|pipe| {
            for key in keys {
                pipe.cmd("SMEMBERS").arg(key);
            }
            pipe
        })
    }

    /// Helper: batch check if members exist in sets using pipeline
    pub fn sismember_many(&self, key_members: Vec<(&str, &str)>) -> RedisResult<Vec<bool>> {
        self.with_pipeline(|pipe| {
            for (key, member) in key_members {
                pipe.cmd("SISMEMBER").arg(key).arg(member);
            }
            pipe
        })
    }

    /// Helper: batch get set cardinalities using pipeline
    pub fn scard_many(&self, keys: Vec<&str>) -> RedisResult<Vec<usize>> {
        self.with_pipeline(|pipe| {
            for key in keys {
                pipe.cmd("SCARD").arg(key);
            }
            pipe
        })
    }

    /// Helper: batch delete multiple sets using pipeline
    pub fn del_many(&self, keys: Vec<&str>) -> RedisResult<()> {
        self.with_pipeline(|pipe| {
            for key in keys {
                pipe.cmd("DEL").arg(key);
            }
            pipe
        })
    }
}

/// Transaction operations (MULTI/EXEC)
///
/// Transactions in Redis are atomic command blocks executed with MULTI/EXEC.
/// Unlike pipelines, transactions guarantee atomicity - either all commands
/// execute or none do.
impl RedisSet {
    /// Executes a transaction using MULTI/EXEC
    ///
    /// All commands execute atomically.
    /// If any command fails, the entire transaction is aborted.
    ///
    /// # Example
    /// ```ignore
    /// # use redis::{Connection, RedisResult};
    /// # use std::sync::{Arc, Mutex};
    /// # use dbx_adapter::redis::primitives::set::RedisSet;
    /// # fn example(conn: Connection) -> RedisResult<()> {
    /// let redis_set = RedisSet::new(Arc::new(Mutex::new(conn)));
    /// let _: () = redis_set.transaction(|pipe| {
    ///     pipe.cmd("SADD").arg("set1").arg("member1")
    ///        .cmd("SADD").arg("set2").arg("member2")
    /// })?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn transaction<F, T>(&self, f: F) -> RedisResult<T>
    where
        F: FnOnce(&mut Pipeline) -> &mut Pipeline,
        T: FromRedisValue,
    {
        let mut conn = self.acquire_connection()?;
        let mut pipe = redis::pipe();
        // Add MULTI command at the beginning
        pipe.cmd("MULTI");
        // Apply the user's commands
        f(&mut pipe);
        // Add EXEC command at the end
        pipe.cmd("EXEC");
        // Execute the transaction
        let result = pipe.query(&mut *conn)?;
        Ok(result)
    }
}

/// Lua script operations
///
/// Lua scripts in Redis provide a way to execute complex operations atomically.
/// Scripts are executed atomically and can access keys, allowing for custom
/// atomic operations that aren't possible with standard Redis commands.
impl RedisSet {
    /// Creates a new Lua script
    ///
    /// # Example
    /// ```ignore
    /// use redis::Script;
    /// use dbx_adapter::redis::primitives::set::RedisSet;
    ///
    /// let script = RedisSet::create_script(r#"
    ///     local members = redis.call('SMEMBERS', KEYS[1])
    ///     redis.call('SADD', KEYS[1], ARGV[1])
    ///     return #members
    /// "#);
    /// ```
    pub fn create_script(script_source: &str) -> Script {
        Script::new(script_source)
    }

    /// Executes a Lua script with the given keys and arguments
    ///
    /// # Example
    /// ```ignore
    /// # use redis::{Connection, RedisResult, Script};
    /// # use std::sync::{Arc, Mutex};
    /// # use dbx_adapter::redis::primitives::set::RedisSet;
    /// # fn example(conn: Connection) -> RedisResult<()> {
    /// let redis_set = RedisSet::new(Arc::new(Mutex::new(conn)));
    /// let script = RedisSet::create_script("return redis.call('SCARD', KEYS[1])");
    ///
    /// // Execute the script with "myset" as the key and no arguments
    /// let result: usize = redis_set.eval_script::<usize, _, _>(&script, &["myset"], &[""])?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn eval_script<T, K, A>(&self, script: &Script, keys: K, args: A) -> RedisResult<T>
    where
        T: FromRedisValue,
        K: ToRedisArgs,
        A: ToRedisArgs,
    {
        let mut conn = self.acquire_connection()?;
        script.key(keys).arg(args).invoke(&mut *conn)
    }

    /// Add a Lua script to a pipeline
    /// Add a script execution to the pipeline
    ///
    /// This integrates script execution with Redis pipelines. Since the Redis
    /// Testing utility for script internals.
    pub fn add_script_to_pipeline<'a, K, A>(
        &self,
        pipe: &'a mut Pipeline,
        script: &str,
        keys: Vec<K>,
        args: Vec<A>,
    ) -> &'a mut Pipeline
    where
        K: ToRedisArgs,
        A: ToRedisArgs,
    {
        pipe.cmd("EVAL")
            .arg(script)
            .arg(keys.len())
            .arg(keys)
            .arg(args)
    }
}

/// Utility functions for common set operations with Lua scripts
///
/// These predefined scripts provide common atomic operations that can be reused
/// across your application.
impl RedisSet {
    /// Gets a script that atomically adds a member and returns the previous cardinality
    ///
    /// # Example
    /// ```ignore
    /// # use redis::{Connection, RedisResult};
    /// # use std::sync::{Arc, Mutex};
    /// # use dbx_adapter::redis::primitives::set::RedisSet;
    /// # fn example(conn: Connection) -> RedisResult<()> {
    /// let redis_set = RedisSet::new(Arc::new(Mutex::new(conn)));
    /// let script = RedisSet::add_and_get_cardinality_script();
    ///
    /// // Atomically add a member and get the previous cardinality
    /// let previous_count: usize = redis_set.eval_script(
    ///     &script,
    ///     &["my_set"],  // KEYS[1]
    ///     &["new_member"] // ARGV[1]
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_and_get_cardinality_script() -> Script {
        Script::new(
            r#"
            local cardinality = redis.call('SCARD', KEYS[1])
            redis.call('SADD', KEYS[1], ARGV[1])
            return cardinality
            "#,
        )
    }

    /// Gets a script that conditionally adds a member if it doesn't exist
    pub fn add_if_not_exists_script() -> Script {
        Script::new(
            r#"
            local exists = redis.call('SISMEMBER', KEYS[1], ARGV[1])
            if exists == 0 then
                redis.call('SADD', KEYS[1], ARGV[1])
                return 1
            else
                return 0
            end
            "#,
        )
    }

    /// Gets a script that removes a member and returns whether it existed
    pub fn remove_and_check_script() -> Script {
        Script::new(
            r#"
            local removed = redis.call('SREM', KEYS[1], ARGV[1])
            return removed
            "#,
        )
    }

    /// Gets a script that moves a member between sets atomically
    pub fn move_member_script() -> Script {
        Script::new(
            r#"
            local exists = redis.call('SISMEMBER', KEYS[1], ARGV[1])
            if exists == 1 then
                redis.call('SREM', KEYS[1], ARGV[1])
                redis.call('SADD', KEYS[2], ARGV[1])
                return 1
            else
                return 0
            end
            "#,
        )
    }

    /// Gets a script that finds the intersection of multiple sets
    pub fn multi_intersection_script() -> Script {
        Script::new(
            r#"
            local result = {}
            for i=1, #KEYS do
                local members = redis.call('SMEMBERS', KEYS[i])
                for j=1, #members do
                    result[members[j]] = (result[members[j]] or 0) + 1
                end
            end
            
            local intersection = {}
            local set_count = #KEYS
            for member, count in pairs(result) do
                if count == set_count then
                    table.insert(intersection, member)
                end
            end
            return intersection
            "#,
        )
    }

    /// Gets a script that implements a unique visitor counter pattern
    pub fn unique_visitor_script() -> Script {
        Script::new(
            r#"
            local key = KEYS[1]
            local visitor = ARGV[1]
            local window = tonumber(ARGV[2])

            local added = redis.call('SADD', key, visitor)
            if added == 1 then
                redis.call('EXPIRE', key, window)
            end

            return redis.call('SCARD', key)
            "#,
        )
    }

    /// Gets a script that implements a rate limiter with unique tokens
    pub fn unique_rate_limiter_script() -> Script {
        Script::new(
            r#"
            local key = KEYS[1]
            local token = ARGV[1]
            local limit = tonumber(ARGV[2])
            local window = tonumber(ARGV[3])

            local added = redis.call('SADD', key, token)
            if added == 1 then
                redis.call('EXPIRE', key, window)
            end

            local current = redis.call('SCARD', key)
            if current > limit then
                return 0
            else
                return 1
            end
            "#,
        )
    }
}
