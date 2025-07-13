use dbx_adapter::redis::primitives::set::RedisSet;
use redis::Connection;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SetOperation {
    pub key: String,
    pub members: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SetResponse {
    pub success: bool,
    pub data: Option<Vec<String>>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SetInfo {
    pub key: String,
    pub members: Vec<String>,
    pub cardinality: usize,
    pub ttl: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SetOperationRequest {
    pub keys: Vec<String>,
    pub members: Option<Vec<String>>,
}

fn redis_set(conn: Arc<Mutex<Connection>>) -> RedisSet {
    RedisSet::new(conn)
}

// =========================
// Single Set Operations
// =========================

pub fn add_to_set(
    conn: Arc<Mutex<Connection>>,
    key: &str,
    members: &[&str],
) -> redis::RedisResult<usize> {
    redis_set(conn).sadd(key, members)
}

pub fn remove_from_set(
    conn: Arc<Mutex<Connection>>,
    key: &str,
    members: &[&str],
) -> redis::RedisResult<usize> {
    redis_set(conn).srem(key, members)
}

pub fn get_set_members(conn: Arc<Mutex<Connection>>, key: &str) -> redis::RedisResult<Vec<String>> {
    redis_set(conn).smembers(key)
}

pub fn set_exists(
    conn: Arc<Mutex<Connection>>,
    key: &str,
    member: &str,
) -> redis::RedisResult<bool> {
    redis_set(conn).sismember(key, member)
}

pub fn get_set_cardinality(conn: Arc<Mutex<Connection>>, key: &str) -> redis::RedisResult<usize> {
    redis_set(conn).scard(key)
}

pub fn get_random_set_member(
    conn: Arc<Mutex<Connection>>,
    key: &str,
) -> redis::RedisResult<Option<String>> {
    redis_set(conn).srandmember(key)
}

pub fn get_random_set_members(
    conn: Arc<Mutex<Connection>>,
    key: &str,
    count: usize,
) -> redis::RedisResult<Vec<String>> {
    redis_set(conn).srandmember_count(key, count)
}

pub fn pop_set_member(
    conn: Arc<Mutex<Connection>>,
    key: &str,
) -> redis::RedisResult<Option<String>> {
    redis_set(conn).spop(key)
}

pub fn pop_set_members(
    conn: Arc<Mutex<Connection>>,
    key: &str,
    count: usize,
) -> redis::RedisResult<Vec<String>> {
    redis_set(conn).spop_count(key, count)
}

pub fn move_set_member(
    conn: Arc<Mutex<Connection>>,
    source: &str,
    destination: &str,
    member: &str,
) -> redis::RedisResult<bool> {
    redis_set(conn).smove(source, destination, member)
}

// =========================
// Set Operations
// =========================

pub fn intersect_sets(
    conn: Arc<Mutex<Connection>>,
    keys: &[&str],
) -> redis::RedisResult<Vec<String>> {
    redis_set(conn).sinter(keys)
}

pub fn union_sets(conn: Arc<Mutex<Connection>>, keys: &[&str]) -> redis::RedisResult<Vec<String>> {
    redis_set(conn).sunion(keys)
}

pub fn difference_sets(
    conn: Arc<Mutex<Connection>>,
    keys: &[&str],
) -> redis::RedisResult<Vec<String>> {
    redis_set(conn).sdiff(keys)
}

pub fn intersect_sets_store(
    conn: Arc<Mutex<Connection>>,
    destination: &str,
    keys: &[&str],
) -> redis::RedisResult<usize> {
    redis_set(conn).sinterstore(destination, keys)
}

pub fn union_sets_store(
    conn: Arc<Mutex<Connection>>,
    destination: &str,
    keys: &[&str],
) -> redis::RedisResult<usize> {
    redis_set(conn).sunionstore(destination, keys)
}

pub fn difference_sets_store(
    conn: Arc<Mutex<Connection>>,
    destination: &str,
    keys: &[&str],
) -> redis::RedisResult<usize> {
    redis_set(conn).sdiffstore(destination, keys)
}

// =========================
// Set Management
// =========================

pub fn delete_set(conn: Arc<Mutex<Connection>>, key: &str) -> redis::RedisResult<bool> {
    let exists = redis_set(conn.clone()).exists(key)?;
    if exists {
        redis_set(conn).del(key)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

pub fn set_exists_key(conn: Arc<Mutex<Connection>>, key: &str) -> redis::RedisResult<bool> {
    redis_set(conn).exists(key)
}

pub fn get_set_ttl(conn: Arc<Mutex<Connection>>, key: &str) -> redis::RedisResult<i64> {
    redis_set(conn).ttl(key)
}

pub fn set_set_ttl(conn: Arc<Mutex<Connection>>, key: &str, ttl: u64) -> redis::RedisResult<bool> {
    redis_set(conn).expire(key, ttl)
}

// =========================
// Batch Operations
// =========================

pub fn add_to_multiple_sets(
    conn: Arc<Mutex<Connection>>,
    set_members: Vec<(&str, Vec<&str>)>,
) -> redis::RedisResult<Vec<usize>> {
    redis_set(conn).sadd_many(set_members)
}

pub fn remove_from_multiple_sets(
    conn: Arc<Mutex<Connection>>,
    set_members: Vec<(&str, Vec<&str>)>,
) -> redis::RedisResult<Vec<usize>> {
    redis_set(conn).srem_many(set_members)
}

pub fn get_multiple_set_members(
    conn: Arc<Mutex<Connection>>,
    keys: Vec<&str>,
) -> redis::RedisResult<Vec<Vec<String>>> {
    redis_set(conn).smembers_many(keys)
}

pub fn check_multiple_set_members(
    conn: Arc<Mutex<Connection>>,
    key_members: Vec<(&str, &str)>,
) -> redis::RedisResult<Vec<bool>> {
    redis_set(conn).sismember_many(key_members)
}

pub fn get_multiple_set_cardinalities(
    conn: Arc<Mutex<Connection>>,
    keys: Vec<&str>,
) -> redis::RedisResult<Vec<usize>> {
    redis_set(conn).scard_many(keys)
}

pub fn delete_multiple_sets(
    conn: Arc<Mutex<Connection>>,
    keys: Vec<&str>,
) -> redis::RedisResult<()> {
    redis_set(conn).del_many(keys)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_operation_structure() {
        let operation = SetOperation {
            key: "users".to_string(),
            members: vec![
                "alice".to_string(),
                "bob".to_string(),
                "charlie".to_string(),
            ],
        };
        assert_eq!(operation.key, "users");
        assert_eq!(operation.members.len(), 3);
        assert!(operation.members.contains(&"alice".to_string()));
        assert!(operation.members.contains(&"bob".to_string()));
        assert!(operation.members.contains(&"charlie".to_string()));

        // Test serialization
        let json = serde_json::to_string(&operation).unwrap();
        assert!(json.contains("users"));
        assert!(json.contains("alice"));
        assert!(json.contains("bob"));
        assert!(json.contains("charlie"));

        // Test deserialization
        let deserialized: SetOperation = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.key, "users");
        assert_eq!(deserialized.members, operation.members);
    }

    #[test]
    fn test_set_operation_empty_members() {
        let operation = SetOperation {
            key: "empty_set".to_string(),
            members: vec![],
        };
        assert!(operation.members.is_empty());

        let json = serde_json::to_string(&operation).unwrap();
        let deserialized: SetOperation = serde_json::from_str(&json).unwrap();
        assert!(deserialized.members.is_empty());
    }

    #[test]
    fn test_set_response_structure() {
        // Test success response
        let success_response = SetResponse {
            success: true,
            data: Some(vec!["member1".to_string(), "member2".to_string()]),
            error: None,
        };
        assert!(success_response.success);
        assert!(success_response.data.is_some());
        assert!(success_response.error.is_none());
        assert_eq!(success_response.data.as_ref().unwrap().len(), 2);

        // Test error response
        let error_response = SetResponse {
            success: false,
            data: None,
            error: Some("Set not found".to_string()),
        };
        assert!(!error_response.success);
        assert!(error_response.data.is_none());
        assert!(error_response.error.is_some());

        // Test empty data response
        let empty_response = SetResponse {
            success: true,
            data: Some(vec![]),
            error: None,
        };
        assert!(empty_response.success);
        assert!(empty_response.data.as_ref().unwrap().is_empty());

        // Test serialization
        let json = serde_json::to_string(&success_response).unwrap();
        let deserialized: SetResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.success, true);
        assert_eq!(
            deserialized.data,
            Some(vec!["member1".to_string(), "member2".to_string()])
        );
    }

    #[test]
    fn test_set_info_structure() {
        let info = SetInfo {
            key: "active_users".to_string(),
            members: vec![
                "user1".to_string(),
                "user2".to_string(),
                "user3".to_string(),
            ],
            cardinality: 3,
            ttl: Some(7200),
        };
        assert_eq!(info.key, "active_users");
        assert_eq!(info.members.len(), 3);
        assert_eq!(info.cardinality, 3);
        assert_eq!(info.ttl, Some(7200));

        // Test with no TTL
        let info_no_ttl = SetInfo {
            key: "persistent_set".to_string(),
            members: vec!["member".to_string()],
            cardinality: 1,
            ttl: None,
        };
        assert!(info_no_ttl.ttl.is_none());

        // Test serialization
        let json = serde_json::to_string(&info).unwrap();
        let deserialized: SetInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.key, "active_users");
        assert_eq!(deserialized.members.len(), 3);
        assert_eq!(deserialized.cardinality, 3);
        assert_eq!(deserialized.ttl, Some(7200));
    }

    #[test]
    fn test_set_operation_request_structure() {
        // Test with members
        let request_with_members = SetOperationRequest {
            keys: vec!["set1".to_string(), "set2".to_string()],
            members: Some(vec!["member1".to_string(), "member2".to_string()]),
        };
        assert_eq!(request_with_members.keys.len(), 2);
        assert!(request_with_members.members.is_some());
        assert_eq!(request_with_members.members.as_ref().unwrap().len(), 2);

        // Test without members
        let request_without_members = SetOperationRequest {
            keys: vec!["set1".to_string()],
            members: None,
        };
        assert_eq!(request_without_members.keys.len(), 1);
        assert!(request_without_members.members.is_none());

        // Test serialization
        let json = serde_json::to_string(&request_with_members).unwrap();
        let deserialized: SetOperationRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(
            deserialized.keys,
            vec!["set1".to_string(), "set2".to_string()]
        );
        assert_eq!(
            deserialized.members,
            Some(vec!["member1".to_string(), "member2".to_string()])
        );
    }

    #[test]
    fn test_debug_implementations() {
        let operation = SetOperation {
            key: "test_set".to_string(),
            members: vec!["member".to_string()],
        };
        let debug_str = format!("{:?}", operation);
        assert!(debug_str.contains("SetOperation"));
        assert!(debug_str.contains("test_set"));
        assert!(debug_str.contains("member"));

        let response = SetResponse {
            success: true,
            data: Some(vec!["data".to_string()]),
            error: None,
        };
        let debug_str = format!("{:?}", response);
        assert!(debug_str.contains("SetResponse"));
        assert!(debug_str.contains("true"));
        assert!(debug_str.contains("data"));

        let info = SetInfo {
            key: "info_set".to_string(),
            members: vec![],
            cardinality: 0,
            ttl: Some(300),
        };
        let debug_str = format!("{:?}", info);
        assert!(debug_str.contains("SetInfo"));
        assert!(debug_str.contains("info_set"));
        assert!(debug_str.contains("300"));

        let request = SetOperationRequest {
            keys: vec!["key".to_string()],
            members: None,
        };
        let debug_str = format!("{:?}", request);
        assert!(debug_str.contains("SetOperationRequest"));
        assert!(debug_str.contains("key"));
    }

    #[test]
    fn test_clone_implementations() {
        let original_operation = SetOperation {
            key: "original".to_string(),
            members: vec!["member1".to_string(), "member2".to_string()],
        };
        let cloned_operation = original_operation.clone();
        assert_eq!(original_operation.key, cloned_operation.key);
        assert_eq!(original_operation.members, cloned_operation.members);

        let original_response = SetResponse {
            success: false,
            data: Some(vec!["test".to_string()]),
            error: Some("error".to_string()),
        };
        let cloned_response = original_response.clone();
        assert_eq!(original_response.success, cloned_response.success);
        assert_eq!(original_response.data, cloned_response.data);
        assert_eq!(original_response.error, cloned_response.error);

        let original_info = SetInfo {
            key: "clone_test".to_string(),
            members: vec!["a".to_string(), "b".to_string()],
            cardinality: 2,
            ttl: Some(1800),
        };
        let cloned_info = original_info.clone();
        assert_eq!(original_info.key, cloned_info.key);
        assert_eq!(original_info.members, cloned_info.members);
        assert_eq!(original_info.cardinality, cloned_info.cardinality);
        assert_eq!(original_info.ttl, cloned_info.ttl);

        let original_request = SetOperationRequest {
            keys: vec!["key1".to_string(), "key2".to_string()],
            members: Some(vec!["mem".to_string()]),
        };
        let cloned_request = original_request.clone();
        assert_eq!(original_request.keys, cloned_request.keys);
        assert_eq!(original_request.members, cloned_request.members);
    }

    #[test]
    fn test_edge_case_values() {
        // Test empty strings
        let empty_operation = SetOperation {
            key: "".to_string(),
            members: vec!["".to_string()],
        };
        let json = serde_json::to_string(&empty_operation).unwrap();
        let deserialized: SetOperation = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.key, "");
        assert_eq!(deserialized.members, vec![""]);

        // Test unicode values
        let unicode_operation = SetOperation {
            key: "test_set".to_string(),
            members: vec!["member1_test".to_string(), "member2_test".to_string()],
        };
        let json = serde_json::to_string(&unicode_operation).unwrap();
        let deserialized: SetOperation = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.key, "test_set");
        assert_eq!(
            deserialized.members,
            vec!["member1_test".to_string(), "member2_test".to_string()]
        );

        // Test very long strings
        let long_key = "k".repeat(1000);
        let long_member = "m".repeat(1000);
        let long_operation = SetOperation {
            key: long_key.clone(),
            members: vec![long_member.clone()],
        };
        let json = serde_json::to_string(&long_operation).unwrap();
        let deserialized: SetOperation = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.key.len(), 1000);
        assert_eq!(deserialized.members[0].len(), 1000);
    }

    #[test]
    fn test_large_member_collections() {
        // Test with large number of members
        let large_members: Vec<String> = (0..1000).map(|i| format!("member_{}", i)).collect();
        let large_operation = SetOperation {
            key: "large_set".to_string(),
            members: large_members.clone(),
        };
        assert_eq!(large_operation.members.len(), 1000);

        let json = serde_json::to_string(&large_operation).unwrap();
        let deserialized: SetOperation = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.members.len(), 1000);
        assert_eq!(deserialized.members[0], "member_0");
        assert_eq!(deserialized.members[999], "member_999");
    }

    #[test]
    fn test_set_info_edge_cases() {
        // Test with zero cardinality
        let zero_cardinality = SetInfo {
            key: "empty".to_string(),
            members: vec![],
            cardinality: 0,
            ttl: Some(0),
        };
        assert_eq!(zero_cardinality.cardinality, 0);
        assert_eq!(zero_cardinality.ttl, Some(0));

        // Test with mismatched cardinality and members count
        let mismatched = SetInfo {
            key: "mismatched".to_string(),
            members: vec!["a".to_string(), "b".to_string()],
            cardinality: 5, // Intentionally different from members.len()
            ttl: None,
        };
        assert_eq!(mismatched.members.len(), 2);
        assert_eq!(mismatched.cardinality, 5);

        // Test with negative TTL
        let negative_ttl = SetInfo {
            key: "expiring".to_string(),
            members: vec!["member".to_string()],
            cardinality: 1,
            ttl: Some(-1),
        };
        assert_eq!(negative_ttl.ttl, Some(-1));

        // Test with very large cardinality
        let large_cardinality = SetInfo {
            key: "huge".to_string(),
            members: vec!["member".to_string()],
            cardinality: usize::MAX,
            ttl: Some(i64::MAX),
        };
        assert_eq!(large_cardinality.cardinality, usize::MAX);
        assert_eq!(large_cardinality.ttl, Some(i64::MAX));
    }

    #[test]
    fn test_set_operation_request_edge_cases() {
        // Test with empty keys
        let empty_keys = SetOperationRequest {
            keys: vec![],
            members: Some(vec!["member".to_string()]),
        };
        assert!(empty_keys.keys.is_empty());
        assert!(empty_keys.members.is_some());

        // Test with empty members option
        let empty_members = SetOperationRequest {
            keys: vec!["key".to_string()],
            members: Some(vec![]),
        };
        assert!(empty_members.members.as_ref().unwrap().is_empty());

        // Test serialization consistency
        let request = SetOperationRequest {
            keys: vec!["test".to_string()],
            members: None,
        };
        let json1 = serde_json::to_string(&request).unwrap();
        let deserialized: SetOperationRequest = serde_json::from_str(&json1).unwrap();
        let json2 = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(json1, json2);
    }

    #[test]
    fn test_special_characters_in_members() {
        let special_operation = SetOperation {
            key: "special:key@test".to_string(),
            members: vec![
                "member:with:colons".to_string(),
                "member@with@symbols".to_string(),
                "member with spaces".to_string(),
                "member\twith\ttabs".to_string(),
                "member\nwith\nnewlines".to_string(),
            ],
        };

        let json = serde_json::to_string(&special_operation).unwrap();
        let deserialized: SetOperation = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.key, "special:key@test");
        assert_eq!(deserialized.members.len(), 5);
        assert!(deserialized
            .members
            .contains(&"member:with:colons".to_string()));
        assert!(deserialized
            .members
            .contains(&"member@with@symbols".to_string()));
        assert!(deserialized
            .members
            .contains(&"member with spaces".to_string()));
        assert!(deserialized
            .members
            .contains(&"member\twith\ttabs".to_string()));
        assert!(deserialized
            .members
            .contains(&"member\nwith\nnewlines".to_string()));
    }
}
