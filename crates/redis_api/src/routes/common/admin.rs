use dbx_adapter::redis::primitives::admin::{AdminOperations, HealthCheck, ServerStatus};
use redis::Connection;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfigSetRequest {
    pub parameter: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfigGetRequest {
    pub parameter: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AdminResponse {
    pub success: bool,
    pub data: Option<serde_json::Value>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServerInfo {
    pub info: String,
    pub section: Option<String>,
}

fn redis_admin(conn: Arc<Mutex<Connection>>) -> AdminOperations {
    AdminOperations::new(conn)
}

// =========================
// Basic Health & Status Operations
// =========================

pub fn ping_server(conn: Arc<Mutex<Connection>>) -> redis::RedisResult<String> {
    redis_admin(conn).ping()
}

pub fn get_server_info(conn: Arc<Mutex<Connection>>) -> redis::RedisResult<String> {
    redis_admin(conn).info()
}

pub fn get_server_info_section(
    conn: Arc<Mutex<Connection>>,
    section: &str,
) -> redis::RedisResult<String> {
    redis_admin(conn).info_section(section)
}

pub fn get_database_size(conn: Arc<Mutex<Connection>>) -> redis::RedisResult<i64> {
    redis_admin(conn).dbsize()
}

pub fn get_server_time(conn: Arc<Mutex<Connection>>) -> redis::RedisResult<(i64, i64)> {
    redis_admin(conn).time()
}

pub fn get_server_version(conn: Arc<Mutex<Connection>>) -> redis::RedisResult<String> {
    redis_admin(conn).version()
}

// =========================
// Health Check Operations
// =========================

pub fn health_check(conn: Arc<Mutex<Connection>>) -> redis::RedisResult<HealthCheck> {
    redis_admin(conn).health_check()
}

pub fn server_status(conn: Arc<Mutex<Connection>>) -> redis::RedisResult<ServerStatus> {
    redis_admin(conn).server_status()
}

// =========================
// Statistics Operations
// =========================

pub fn get_memory_stats(
    conn: Arc<Mutex<Connection>>,
) -> redis::RedisResult<HashMap<String, String>> {
    redis_admin(conn).memory_stats()
}

pub fn get_client_stats(
    conn: Arc<Mutex<Connection>>,
) -> redis::RedisResult<HashMap<String, String>> {
    redis_admin(conn).client_stats()
}

pub fn get_server_stats(
    conn: Arc<Mutex<Connection>>,
) -> redis::RedisResult<HashMap<String, String>> {
    redis_admin(conn).server_stats()
}

// =========================
// Configuration Operations
// =========================

pub fn config_set(
    conn: Arc<Mutex<Connection>>,
    parameter: &str,
    value: &str,
) -> redis::RedisResult<()> {
    redis_admin(conn).config_set(parameter, value)
}

pub fn config_get(conn: Arc<Mutex<Connection>>, parameter: &str) -> redis::RedisResult<String> {
    redis_admin(conn).config_get(parameter)
}

pub fn config_get_all(conn: Arc<Mutex<Connection>>) -> redis::RedisResult<HashMap<String, String>> {
    redis_admin(conn).config_get_all()
}

pub fn config_reset_statistics(conn: Arc<Mutex<Connection>>) -> redis::RedisResult<()> {
    redis_admin(conn).config_resetstat()
}

pub fn config_rewrite(conn: Arc<Mutex<Connection>>) -> redis::RedisResult<()> {
    redis_admin(conn).config_rewrite()
}

// =========================
// Database Management Operations
// =========================

pub fn flush_current_database(conn: Arc<Mutex<Connection>>) -> redis::RedisResult<()> {
    redis_admin(conn).flushdb()
}

pub fn flush_all_databases(conn: Arc<Mutex<Connection>>) -> redis::RedisResult<()> {
    redis_admin(conn).flushall()
}

#[cfg(test)]
mod tests {
    use super::*;
    use redis::{Connection, RedisResult};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    // Mock connection for testing
    fn create_mock_connection() -> Arc<Mutex<Connection>> {
        // This will fail, but we're testing the function structure, not actual Redis
        let client = redis::Client::open("redis://127.0.0.1:6379/").unwrap();
        let conn = client.get_connection().unwrap_or_else(|_| {
            // If Redis is not available, this will panic, but the test structure will still be verified
            panic!("Redis connection not available for testing")
        });
        Arc::new(Mutex::new(conn))
    }

    #[test]
    fn test_config_set_request_structure() {
        let request = ConfigSetRequest {
            parameter: "maxmemory".to_string(),
            value: "100mb".to_string(),
        };
        assert_eq!(request.parameter, "maxmemory");
        assert_eq!(request.value, "100mb");

        // Test serialization
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("maxmemory"));
        assert!(json.contains("100mb"));

        // Test deserialization
        let deserialized: ConfigSetRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.parameter, "maxmemory");
        assert_eq!(deserialized.value, "100mb");
    }

    #[test]
    fn test_config_get_request_structure() {
        let request = ConfigGetRequest {
            parameter: "timeout".to_string(),
        };
        assert_eq!(request.parameter, "timeout");

        // Test serialization roundtrip
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: ConfigGetRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.parameter, "timeout");
    }

    #[test]
    fn test_admin_response_structure() {
        // Test success response
        let success_response = AdminResponse {
            success: true,
            data: Some(serde_json::json!({"result": "ok"})),
            error: None,
        };
        assert!(success_response.success);
        assert!(success_response.data.is_some());
        assert!(success_response.error.is_none());

        // Test error response
        let error_response = AdminResponse {
            success: false,
            data: None,
            error: Some("Connection failed".to_string()),
        };
        assert!(!error_response.success);
        assert!(error_response.data.is_none());
        assert!(error_response.error.is_some());

        // Test serialization
        let json = serde_json::to_string(&success_response).unwrap();
        assert!(json.contains("success"));
        let deserialized: AdminResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.success, true);
    }

    #[test]
    fn test_server_info_structure() {
        let info = ServerInfo {
            info: "server info content".to_string(),
            section: Some("memory".to_string()),
        };
        assert_eq!(info.info, "server info content");
        assert_eq!(info.section, Some("memory".to_string()));

        // Test with no section
        let info_no_section = ServerInfo {
            info: "full server info".to_string(),
            section: None,
        };
        assert!(info_no_section.section.is_none());

        // Test serialization
        let json = serde_json::to_string(&info).unwrap();
        let deserialized: ServerInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.info, "server info content");
        assert_eq!(deserialized.section, Some("memory".to_string()));
    }

    #[test]
    fn test_debug_implementations() {
        let config_set = ConfigSetRequest {
            parameter: "test".to_string(),
            value: "value".to_string(),
        };
        let debug_str = format!("{:?}", config_set);
        assert!(debug_str.contains("ConfigSetRequest"));
        assert!(debug_str.contains("test"));
        assert!(debug_str.contains("value"));

        let config_get = ConfigGetRequest {
            parameter: "test".to_string(),
        };
        let debug_str = format!("{:?}", config_get);
        assert!(debug_str.contains("ConfigGetRequest"));

        let response = AdminResponse {
            success: true,
            data: None,
            error: None,
        };
        let debug_str = format!("{:?}", response);
        assert!(debug_str.contains("AdminResponse"));

        let info = ServerInfo {
            info: "info".to_string(),
            section: None,
        };
        let debug_str = format!("{:?}", info);
        assert!(debug_str.contains("ServerInfo"));
    }

    #[test]
    fn test_clone_implementations() {
        let original = ConfigSetRequest {
            parameter: "original".to_string(),
            value: "value".to_string(),
        };
        let cloned = original.clone();
        assert_eq!(original.parameter, cloned.parameter);
        assert_eq!(original.value, cloned.value);

        let original_get = ConfigGetRequest {
            parameter: "test".to_string(),
        };
        let cloned_get = original_get.clone();
        assert_eq!(original_get.parameter, cloned_get.parameter);

        let original_response = AdminResponse {
            success: true,
            data: Some(serde_json::json!({"test": "data"})),
            error: None,
        };
        let cloned_response = original_response.clone();
        assert_eq!(original_response.success, cloned_response.success);

        let original_info = ServerInfo {
            info: "info".to_string(),
            section: Some("section".to_string()),
        };
        let cloned_info = original_info.clone();
        assert_eq!(original_info.info, cloned_info.info);
        assert_eq!(original_info.section, cloned_info.section);
    }

    #[test]
    fn test_edge_case_values() {
        // Test empty strings
        let empty_config = ConfigSetRequest {
            parameter: "".to_string(),
            value: "".to_string(),
        };
        let json = serde_json::to_string(&empty_config).unwrap();
        let deserialized: ConfigSetRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.parameter, "");
        assert_eq!(deserialized.value, "");

        // Test unicode values
        let unicode_config = ConfigSetRequest {
            parameter: "设置参数".to_string(),
            value: "数值🎉".to_string(),
        };
        let json = serde_json::to_string(&unicode_config).unwrap();
        let deserialized: ConfigSetRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.parameter, "设置参数");
        assert_eq!(deserialized.value, "数值🎉");

        // Test very long strings
        let long_parameter = "a".repeat(1000);
        let long_value = "b".repeat(1000);
        let long_config = ConfigSetRequest {
            parameter: long_parameter.clone(),
            value: long_value.clone(),
        };
        let json = serde_json::to_string(&long_config).unwrap();
        let deserialized: ConfigSetRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.parameter, long_parameter);
        assert_eq!(deserialized.value, long_value);
    }

    #[test]
    fn test_admin_response_with_complex_data() {
        // Test with complex JSON data
        let complex_data = serde_json::json!({
            "stats": {
                "memory": {
                    "used": 1024,
                    "peak": 2048
                },
                "connections": {
                    "current": 10,
                    "total": 1000
                }
            },
            "version": "6.0.0",
            "uptime": 86400
        });

        let response = AdminResponse {
            success: true,
            data: Some(complex_data.clone()),
            error: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: AdminResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.data, Some(complex_data));
    }

    #[test]
    fn test_server_info_with_large_content() {
        let large_info = "x".repeat(10000);
        let info = ServerInfo {
            info: large_info.clone(),
            section: Some("memory".to_string()),
        };

        let json = serde_json::to_string(&info).unwrap();
        let deserialized: ServerInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.info.len(), 10000);
        assert_eq!(deserialized.section, Some("memory".to_string()));
    }
}
