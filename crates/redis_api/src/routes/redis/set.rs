use crate::routes::common::set::{
    add_to_set, delete_set, difference_sets, get_set_cardinality, get_set_members, intersect_sets,
    remove_from_set, set_exists, union_sets,
};
use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
    routing::{delete, get, post},
    Router,
};
use dbx_adapter::redis::client::RedisPool;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Deserialize, Serialize)]
struct SetMemberRequest {
    member: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct SetMembersRequest {
    members: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct SetKeysRequest {
    keys: Vec<String>,
}

// Add member to set
async fn add_to_set_handler(
    State(pool): State<Arc<RedisPool>>,
    Path(key): Path<String>,
    Json(payload): Json<SetMemberRequest>,
) -> Result<Json<usize>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let added = add_to_set(conn_arc, &key, &[&payload.member])
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(added))
}

// Add multiple members to set
async fn add_many_to_set_handler(
    State(pool): State<Arc<RedisPool>>,
    Path(key): Path<String>,
    Json(payload): Json<SetMembersRequest>,
) -> Result<Json<usize>, StatusCode> {
    // If members array is empty, return 0 (no members added)
    if payload.members.is_empty() {
        return Ok(Json(0));
    }

    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let member_refs: Vec<&str> = payload.members.iter().map(|s| s.as_str()).collect();
    let added =
        add_to_set(conn_arc, &key, &member_refs).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(added))
}

// Remove member from set
async fn remove_from_set_handler(
    State(pool): State<Arc<RedisPool>>,
    Path((key, member)): Path<(String, String)>,
) -> Result<Json<usize>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let removed = remove_from_set(conn_arc, &key, &[&member])
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(removed))
}

// Get all set members
async fn get_set_members_handler(
    State(pool): State<Arc<RedisPool>>,
    Path(key): Path<String>,
) -> Result<Json<Vec<String>>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let members = get_set_members(conn_arc, &key).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(members))
}

// Get set cardinality
async fn get_set_cardinality_handler(
    State(pool): State<Arc<RedisPool>>,
    Path(key): Path<String>,
) -> Result<Json<usize>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let cardinality =
        get_set_cardinality(conn_arc, &key).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(cardinality))
}

// Check if member exists in set
async fn set_exists_handler(
    State(pool): State<Arc<RedisPool>>,
    Path((key, member)): Path<(String, String)>,
) -> Result<Json<bool>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let exists =
        set_exists(conn_arc, &key, &member).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(exists))
}

// Intersect sets
async fn intersect_sets_handler(
    State(pool): State<Arc<RedisPool>>,
    Json(payload): Json<SetKeysRequest>,
) -> Result<Json<Vec<String>>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let key_refs: Vec<&str> = payload.keys.iter().map(|k| k.as_str()).collect();
    let result =
        intersect_sets(conn_arc, &key_refs).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(result))
}

// Union sets
async fn union_sets_handler(
    State(pool): State<Arc<RedisPool>>,
    Json(payload): Json<SetKeysRequest>,
) -> Result<Json<Vec<String>>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let key_refs: Vec<&str> = payload.keys.iter().map(|k| k.as_str()).collect();
    let result = union_sets(conn_arc, &key_refs).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(result))
}

// Difference of sets
async fn difference_sets_handler(
    State(pool): State<Arc<RedisPool>>,
    Json(payload): Json<SetKeysRequest>,
) -> Result<Json<Vec<String>>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let key_refs: Vec<&str> = payload.keys.iter().map(|k| k.as_str()).collect();
    let result =
        difference_sets(conn_arc, &key_refs).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(result))
}

// Delete entire set
async fn delete_set_handler(
    State(pool): State<Arc<RedisPool>>,
    Path(key): Path<String>,
) -> Result<Json<bool>, StatusCode> {
    let conn = pool
        .get_connection()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let conn_arc = Arc::new(std::sync::Mutex::new(conn));
    let deleted = delete_set(conn_arc, &key).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(deleted))
}

pub fn create_redis_set_routes(pool: Arc<RedisPool>) -> Router {
    Router::new()
        .route("/set/:key", post(add_to_set_handler))
        .route("/set/:key", delete(delete_set_handler))
        .route("/set/:key/many", post(add_many_to_set_handler))
        .route("/set/:key/members", get(get_set_members_handler))
        .route("/set/:key/cardinality", get(get_set_cardinality_handler))
        .route("/set/:key/:member/exists", get(set_exists_handler))
        .route("/set/:key/:member", delete(remove_from_set_handler))
        .route("/set/intersect", post(intersect_sets_handler))
        .route("/set/union", post(union_sets_handler))
        .route("/set/difference", post(difference_sets_handler))
        .with_state(pool)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use dbx_adapter::redis::client::RedisPool;
    use std::sync::Arc;

    // Helper function to create a test app with routes
    fn create_test_app() -> Router {
        let pool = Arc::new(RedisPool::new("redis://localhost:6379", 1).unwrap());
        create_redis_set_routes(pool)
    }

    #[test]
    fn test_set_member_request_structure() {
        let request = SetMemberRequest {
            member: "test_member".to_string(),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("test_member"));

        let deserialized: SetMemberRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.member, "test_member");
    }

    #[test]
    fn test_set_members_request_structure() {
        let request = SetMembersRequest {
            members: vec![
                "member1".to_string(),
                "member2".to_string(),
                "member3".to_string(),
            ],
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: SetMembersRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.members, vec!["member1", "member2", "member3"]);
    }

    #[test]
    fn test_set_keys_request_structure() {
        let request = SetKeysRequest {
            keys: vec!["set1".to_string(), "set2".to_string()],
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: SetKeysRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.keys, vec!["set1", "set2"]);
    }

    #[test]
    fn test_request_deserialization_errors() {
        // Test invalid JSON for SetMemberRequest
        let invalid_json = r#"{"member": 123}"#;
        let result = serde_json::from_str::<SetMemberRequest>(invalid_json);
        assert!(result.is_err());

        // Test missing required fields
        let incomplete_json = r#"{}"#;
        let result = serde_json::from_str::<SetMemberRequest>(incomplete_json);
        assert!(result.is_err());

        // Test invalid array type
        let invalid_array = r#"{"members": "not_an_array"}"#;
        let result = serde_json::from_str::<SetMembersRequest>(invalid_array);
        assert!(result.is_err());
    }

    #[test]
    fn test_debug_implementations() {
        let member_request = SetMemberRequest {
            member: "debug_member".to_string(),
        };
        let debug_str = format!("{:?}", member_request);
        assert!(debug_str.contains("SetMemberRequest"));
        assert!(debug_str.contains("debug_member"));

        let members_request = SetMembersRequest {
            members: vec!["member1".to_string(), "member2".to_string()],
        };
        let debug_str = format!("{:?}", members_request);
        assert!(debug_str.contains("SetMembersRequest"));
        assert!(debug_str.contains("member1"));

        let keys_request = SetKeysRequest {
            keys: vec!["key1".to_string()],
        };
        let debug_str = format!("{:?}", keys_request);
        assert!(debug_str.contains("SetKeysRequest"));
        assert!(debug_str.contains("key1"));
    }

    #[test]
    fn test_edge_case_values() {
        // Test empty member
        let request = SetMemberRequest {
            member: "".to_string(),
        };
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: SetMemberRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.member, "");

        // Test empty members array
        let request = SetMembersRequest { members: vec![] };
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: SetMembersRequest = serde_json::from_str(&json).unwrap();
        assert!(deserialized.members.is_empty());

        // Test empty keys array
        let request = SetKeysRequest { keys: vec![] };
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: SetKeysRequest = serde_json::from_str(&json).unwrap();
        assert!(deserialized.keys.is_empty());
    }

    #[test]
    fn test_special_characters_in_members() {
        let request = SetMembersRequest {
            members: vec![
                "member:with:colons".to_string(),
                "member-with-dashes".to_string(),
                "member_with_underscores".to_string(),
                "member.with.dots".to_string(),
                "member/with/slashes".to_string(),
                "member with spaces".to_string(),
            ],
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: SetMembersRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.members.len(), 6);
        assert!(deserialized
            .members
            .contains(&"member:with:colons".to_string()));
        assert!(deserialized
            .members
            .contains(&"member with spaces".to_string()));
    }

    #[test]
    fn test_unicode_members() {
        let request = SetMemberRequest {
            member: "Hello 世界 🌍 Здравствуй мир".to_string(),
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: SetMemberRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.member, "Hello 世界 🌍 Здравствуй мир");
    }

    #[test]
    fn test_large_members_array() {
        // Test large number of members
        let mut members = Vec::new();
        for i in 0..1000 {
            members.push(format!("member_{}", i));
        }

        let request = SetMembersRequest {
            members: members.clone(),
        };
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: SetMembersRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.members.len(), 1000);
        assert_eq!(deserialized.members[999], "member_999");
    }

    #[test]
    fn test_large_keys_array() {
        // Test large number of keys for set operations
        let mut keys = Vec::new();
        for i in 0..100 {
            keys.push(format!("set_{}", i));
        }

        let request = SetKeysRequest { keys: keys.clone() };
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: SetKeysRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.keys.len(), 100);
        assert_eq!(deserialized.keys[99], "set_99");
    }

    #[test]
    fn test_duplicate_members() {
        let request = SetMembersRequest {
            members: vec![
                "member1".to_string(),
                "member2".to_string(),
                "member1".to_string(), // Duplicate
                "member3".to_string(),
                "member2".to_string(), // Another duplicate
            ],
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: SetMembersRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.members.len(), 5); // All members preserved, including duplicates
        assert_eq!(deserialized.members[0], "member1");
        assert_eq!(deserialized.members[2], "member1"); // Duplicate preserved
    }

    #[test]
    fn test_duplicate_keys() {
        let request = SetKeysRequest {
            keys: vec![
                "set1".to_string(),
                "set2".to_string(),
                "set1".to_string(), // Duplicate
                "set3".to_string(),
            ],
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: SetKeysRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.keys.len(), 4); // All keys preserved, including duplicates
        assert!(deserialized.keys.contains(&"set1".to_string()));
        assert!(deserialized.keys.contains(&"set2".to_string()));
        assert!(deserialized.keys.contains(&"set3".to_string()));
    }

    #[test]
    fn test_mixed_data_types_as_strings() {
        let request = SetMembersRequest {
            members: vec![
                "42".to_string(),
                "true".to_string(),
                "3.14".to_string(),
                "null".to_string(),
                r#"{"key": "value"}"#.to_string(),
                "[1,2,3]".to_string(),
            ],
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: SetMembersRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.members.len(), 6);
        assert!(deserialized.members.contains(&"42".to_string()));
        assert!(deserialized
            .members
            .contains(&r#"{"key": "value"}"#.to_string()));
    }

    #[test]
    fn test_very_long_member_names() {
        // Test very long member names
        let long_member = "a".repeat(10000);
        let request = SetMemberRequest {
            member: long_member.clone(),
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: SetMemberRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.member, long_member);
        assert_eq!(deserialized.member.len(), 10000);
    }

    #[test]
    fn test_very_long_key_names() {
        let long_key = "k".repeat(5000);
        let request = SetKeysRequest {
            keys: vec![long_key.clone()],
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: SetKeysRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.keys[0], long_key);
        assert_eq!(deserialized.keys[0].len(), 5000);
    }

    #[test]
    fn test_serialization_roundtrip_consistency() {
        // Test that serialization and deserialization are consistent
        let original_member = SetMemberRequest {
            member: "test_member_roundtrip".to_string(),
        };

        let json = serde_json::to_string(&original_member).unwrap();
        let deserialized: SetMemberRequest = serde_json::from_str(&json).unwrap();
        let json2 = serde_json::to_string(&deserialized).unwrap();

        // Both JSON strings should be equivalent
        assert_eq!(json, json2);
        assert_eq!(original_member.member, deserialized.member);
    }

    #[test]
    fn test_case_sensitive_members() {
        let request = SetMembersRequest {
            members: vec![
                "Member".to_string(),
                "member".to_string(),
                "MEMBER".to_string(),
                "MeMbEr".to_string(),
            ],
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: SetMembersRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.members.len(), 4);
        // All variations should be preserved as distinct members
        assert!(deserialized.members.contains(&"Member".to_string()));
        assert!(deserialized.members.contains(&"member".to_string()));
        assert!(deserialized.members.contains(&"MEMBER".to_string()));
        assert!(deserialized.members.contains(&"MeMbEr".to_string()));
    }

    #[test]
    fn test_whitespace_members() {
        let request = SetMembersRequest {
            members: vec![
                " ".to_string(),
                "  ".to_string(),
                "\t".to_string(),
                "\n".to_string(),
                "\r\n".to_string(),
                " leading".to_string(),
                "trailing ".to_string(),
                " both ".to_string(),
            ],
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: SetMembersRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.members.len(), 8);
        assert!(deserialized.members.contains(&" ".to_string()));
        assert!(deserialized.members.contains(&" leading".to_string()));
        assert!(deserialized.members.contains(&"trailing ".to_string()));
    }

    #[test]
    fn test_numeric_string_members() {
        let request = SetMembersRequest {
            members: vec![
                "0".to_string(),
                "42".to_string(),
                "-1".to_string(),
                "3.14159".to_string(),
                "-2.718".to_string(),
                "1e10".to_string(),
                "0xFF".to_string(),
                "NaN".to_string(),
                "infinity".to_string(),
            ],
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: SetMembersRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.members.len(), 9);
        assert!(deserialized.members.contains(&"3.14159".to_string()));
        assert!(deserialized.members.contains(&"0xFF".to_string()));
    }
}
