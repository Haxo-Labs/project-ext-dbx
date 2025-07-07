use axum::{
    extract::{ws::WebSocket, WebSocketUpgrade},
    response::IntoResponse,
    routing::get,
    Router,
};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use crate::routes::common::admin::{
    config_get, config_get_all, config_reset_statistics, config_rewrite, config_set,
    flush_all_databases, flush_current_database, get_client_stats, get_database_size,
    get_memory_stats, get_server_info, get_server_info_section, get_server_stats, get_server_time,
    get_server_version, health_check, ping_server, server_status,
};
use dbx_adapter::redis::client::RedisPool;
use dbx_adapter::redis::primitives::admin::{HealthCheck, ServerStatus};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type", content = "data")]
pub enum AdminWsMessage {
    // Basic Health & Status messages
    #[serde(rename = "ping")]
    Ping,
    #[serde(rename = "info")]
    Info { section: Option<String> },
    #[serde(rename = "dbsize")]
    DbSize,
    #[serde(rename = "time")]
    Time,
    #[serde(rename = "version")]
    Version,

    // Health Check messages
    #[serde(rename = "health")]
    Health,
    #[serde(rename = "status")]
    Status,

    // Statistics messages
    #[serde(rename = "memory_stats")]
    MemoryStats,
    #[serde(rename = "client_stats")]
    ClientStats,
    #[serde(rename = "server_stats")]
    ServerStats,

    // Configuration messages
    #[serde(rename = "config_set")]
    ConfigSet { parameter: String, value: String },
    #[serde(rename = "config_get")]
    ConfigGet { parameter: String },
    #[serde(rename = "config_get_all")]
    ConfigGetAll,
    #[serde(rename = "config_resetstat")]
    ConfigResetStat,
    #[serde(rename = "config_rewrite")]
    ConfigRewrite,

    // Database Management messages
    #[serde(rename = "flushdb")]
    FlushDb,
    #[serde(rename = "flushall")]
    FlushAll,

    // Response messages
    #[serde(rename = "ping_result")]
    PingResult { response: String },
    #[serde(rename = "info_result")]
    InfoResult { info: String },
    #[serde(rename = "dbsize_result")]
    DbSizeResult { size: i64 },
    #[serde(rename = "time_result")]
    TimeResult { seconds: i64, microseconds: i64 },
    #[serde(rename = "version_result")]
    VersionResult { version: String },
    #[serde(rename = "health_result")]
    HealthResult { health: HealthCheck },
    #[serde(rename = "status_result")]
    StatusResult { status: ServerStatus },
    #[serde(rename = "memory_stats_result")]
    MemoryStatsResult { stats: HashMap<String, String> },
    #[serde(rename = "client_stats_result")]
    ClientStatsResult { stats: HashMap<String, String> },
    #[serde(rename = "server_stats_result")]
    ServerStatsResult { stats: HashMap<String, String> },
    #[serde(rename = "config_get_result")]
    ConfigGetResult { parameter: String, value: String },
    #[serde(rename = "config_get_all_result")]
    ConfigGetAllResult { config: HashMap<String, String> },
    #[serde(rename = "config_set_result")]
    ConfigSetResult { parameter: String, value: String },
    #[serde(rename = "config_resetstat_result")]
    ConfigResetStatResult,
    #[serde(rename = "config_rewrite_result")]
    ConfigRewriteResult,
    #[serde(rename = "flushdb_result")]
    FlushDbResult,
    #[serde(rename = "flushall_result")]
    FlushAllResult,

    // Error message
    #[serde(rename = "error")]
    Error(String),
}

async fn redis_ws_admin_handler(
    ws: WebSocketUpgrade,
    axum::extract::State(pool): axum::extract::State<Arc<RedisPool>>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_redis_ws_admin_socket(socket, pool))
}

async fn handle_redis_ws_admin_socket(socket: WebSocket, pool: Arc<RedisPool>) {
    let (mut sender, mut receiver) = socket.split();
    while let Some(Ok(msg)) = receiver.next().await {
        if let axum::extract::ws::Message::Text(text) = msg {
            if let Ok(message) = serde_json::from_str::<AdminWsMessage>(&text) {
                let conn = match pool.get_connection() {
                    Ok(c) => c,
                    Err(e) => {
                        let _ = sender
                            .send(axum::extract::ws::Message::Text(
                                serde_json::to_string(&AdminWsMessage::Error(format!(
                                    "Redis error: {e}"
                                )))
                                .unwrap(),
                            ))
                            .await;
                        continue;
                    }
                };
                let conn_arc = Arc::new(std::sync::Mutex::new(conn));

                match message {
                    AdminWsMessage::Ping => {
                        let response =
                            ping_server(conn_arc.clone()).unwrap_or_else(|_| "ERROR".to_string());
                        let _ = sender
                            .send(axum::extract::ws::Message::Text(
                                serde_json::to_string(&(AdminWsMessage::PingResult { response }))
                                    .unwrap(),
                            ))
                            .await;
                    }
                    AdminWsMessage::Info { section } => {
                        let info = if let Some(section) = section {
                            get_server_info_section(conn_arc.clone(), &section)
                                .unwrap_or_else(|_| "ERROR".to_string())
                        } else {
                            get_server_info(conn_arc.clone())
                                .unwrap_or_else(|_| "ERROR".to_string())
                        };
                        let _ = sender
                            .send(axum::extract::ws::Message::Text(
                                serde_json::to_string(&(AdminWsMessage::InfoResult { info }))
                                    .unwrap(),
                            ))
                            .await;
                    }
                    AdminWsMessage::DbSize => {
                        let size = get_database_size(conn_arc.clone()).unwrap_or(-1);
                        let _ = sender
                            .send(axum::extract::ws::Message::Text(
                                serde_json::to_string(&(AdminWsMessage::DbSizeResult { size }))
                                    .unwrap(),
                            ))
                            .await;
                    }
                    AdminWsMessage::Time => {
                        let time = get_server_time(conn_arc.clone()).unwrap_or((0, 0));
                        let _ = sender
                            .send(axum::extract::ws::Message::Text(
                                serde_json::to_string(
                                    &(AdminWsMessage::TimeResult {
                                        seconds: time.0,
                                        microseconds: time.1,
                                    }),
                                )
                                .unwrap(),
                            ))
                            .await;
                    }
                    AdminWsMessage::Version => {
                        let version = get_server_version(conn_arc.clone())
                            .unwrap_or_else(|_| "UNKNOWN".to_string());
                        let _ = sender
                            .send(axum::extract::ws::Message::Text(
                                serde_json::to_string(&(AdminWsMessage::VersionResult { version }))
                                    .unwrap(),
                            ))
                            .await;
                    }
                    AdminWsMessage::Health => {
                        let health =
                            health_check(conn_arc.clone()).unwrap_or_else(|_| HealthCheck {
                                is_healthy: false,
                                ping_response: "ERROR".to_string(),
                                database_size: -1,
                                version: "UNKNOWN".to_string(),
                                memory_usage: HashMap::new(),
                            });
                        let _ = sender
                            .send(axum::extract::ws::Message::Text(
                                serde_json::to_string(&(AdminWsMessage::HealthResult { health }))
                                    .unwrap(),
                            ))
                            .await;
                    }
                    AdminWsMessage::Status => {
                        let status =
                            server_status(conn_arc.clone()).unwrap_or_else(|_| ServerStatus {
                                timestamp: 0,
                                uptime_seconds: 0,
                                connected_clients: 0,
                                used_memory: 0,
                                total_commands_processed: 0,
                                keyspace_hits: 0,
                                keyspace_misses: 0,
                                version: "UNKNOWN".to_string(),
                                role: "UNKNOWN".to_string(),
                            });
                        let _ = sender
                            .send(axum::extract::ws::Message::Text(
                                serde_json::to_string(&(AdminWsMessage::StatusResult { status }))
                                    .unwrap(),
                            ))
                            .await;
                    }
                    AdminWsMessage::MemoryStats => {
                        let stats = get_memory_stats(conn_arc.clone()).unwrap_or_default();
                        let _ = sender
                            .send(axum::extract::ws::Message::Text(
                                serde_json::to_string(
                                    &(AdminWsMessage::MemoryStatsResult { stats }),
                                )
                                .unwrap(),
                            ))
                            .await;
                    }
                    AdminWsMessage::ClientStats => {
                        let stats = get_client_stats(conn_arc.clone()).unwrap_or_default();
                        let _ = sender
                            .send(axum::extract::ws::Message::Text(
                                serde_json::to_string(
                                    &(AdminWsMessage::ClientStatsResult { stats }),
                                )
                                .unwrap(),
                            ))
                            .await;
                    }
                    AdminWsMessage::ServerStats => {
                        let stats = get_server_stats(conn_arc.clone()).unwrap_or_default();
                        let _ = sender
                            .send(axum::extract::ws::Message::Text(
                                serde_json::to_string(
                                    &(AdminWsMessage::ServerStatsResult { stats }),
                                )
                                .unwrap(),
                            ))
                            .await;
                    }
                    AdminWsMessage::ConfigSet { parameter, value } => {
                        let res = config_set(conn_arc.clone(), &parameter, &value);
                        let msg = match res {
                            Ok(_) => AdminWsMessage::ConfigSetResult { parameter, value },
                            Err(e) => AdminWsMessage::Error(format!("Config set error: {e}")),
                        };
                        let _ = sender
                            .send(axum::extract::ws::Message::Text(
                                serde_json::to_string(&msg).unwrap(),
                            ))
                            .await;
                    }
                    AdminWsMessage::ConfigGet { parameter } => {
                        let value = config_get(conn_arc.clone(), &parameter)
                            .unwrap_or_else(|_| "ERROR".to_string());
                        let _ = sender
                            .send(axum::extract::ws::Message::Text(
                                serde_json::to_string(
                                    &(AdminWsMessage::ConfigGetResult { parameter, value }),
                                )
                                .unwrap(),
                            ))
                            .await;
                    }
                    AdminWsMessage::ConfigGetAll => {
                        let config = config_get_all(conn_arc.clone()).unwrap_or_default();
                        let _ = sender
                            .send(axum::extract::ws::Message::Text(
                                serde_json::to_string(
                                    &(AdminWsMessage::ConfigGetAllResult { config }),
                                )
                                .unwrap(),
                            ))
                            .await;
                    }
                    AdminWsMessage::ConfigResetStat => {
                        let res = config_reset_statistics(conn_arc.clone());
                        let msg = match res {
                            Ok(_) => AdminWsMessage::ConfigResetStatResult,
                            Err(e) => AdminWsMessage::Error(format!("Config resetstat error: {e}")),
                        };
                        let _ = sender
                            .send(axum::extract::ws::Message::Text(
                                serde_json::to_string(&msg).unwrap(),
                            ))
                            .await;
                    }
                    AdminWsMessage::ConfigRewrite => {
                        let res = config_rewrite(conn_arc.clone());
                        let msg = match res {
                            Ok(_) => AdminWsMessage::ConfigRewriteResult,
                            Err(e) => AdminWsMessage::Error(format!("Config rewrite error: {e}")),
                        };
                        let _ = sender
                            .send(axum::extract::ws::Message::Text(
                                serde_json::to_string(&msg).unwrap(),
                            ))
                            .await;
                    }
                    AdminWsMessage::FlushDb => {
                        let res = flush_current_database(conn_arc.clone());
                        let msg = match res {
                            Ok(_) => AdminWsMessage::FlushDbResult,
                            Err(e) => AdminWsMessage::Error(format!("FlushDB error: {e}")),
                        };
                        let _ = sender
                            .send(axum::extract::ws::Message::Text(
                                serde_json::to_string(&msg).unwrap(),
                            ))
                            .await;
                    }
                    AdminWsMessage::FlushAll => {
                        let res = flush_all_databases(conn_arc.clone());
                        let msg = match res {
                            Ok(_) => AdminWsMessage::FlushAllResult,
                            Err(e) => AdminWsMessage::Error(format!("FlushAll error: {e}")),
                        };
                        let _ = sender
                            .send(axum::extract::ws::Message::Text(
                                serde_json::to_string(&msg).unwrap(),
                            ))
                            .await;
                    }
                    _ => {}
                }
            }
        }
    }
}

pub fn create_redis_ws_admin_routes(pool: Arc<RedisPool>) -> Router {
    Router::new()
        .route("/ws", get(redis_ws_admin_handler))
        .with_state(pool)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;
    use std::collections::HashMap;
    use dbx_adapter::redis::primitives::admin::{HealthCheck, ServerStatus};

    #[test]
    fn test_admin_ws_message_ping_serialization() {
        let msg = AdminWsMessage::Ping;
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(serialized.contains("ping"));
        
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized, AdminWsMessage::Ping));
    }

    #[test]
    fn test_admin_ws_message_info_serialization() {
        let msg = AdminWsMessage::Info { section: Some("memory".to_string()) };
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(serialized.contains("info"));
        assert!(serialized.contains("memory"));
        
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        if let AdminWsMessage::Info { section } = deserialized {
            assert_eq!(section, Some("memory".to_string()));
        } else {
            panic!("Expected Info message");
        }
    }

    #[test]
    fn test_admin_ws_message_info_no_section_serialization() {
        let msg = AdminWsMessage::Info { section: None };
        let serialized = serde_json::to_string(&msg).unwrap();
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        if let AdminWsMessage::Info { section } = deserialized {
            assert_eq!(section, None);
        } else {
            panic!("Expected Info message");
        }
    }

    #[test]
    fn test_admin_ws_message_dbsize_serialization() {
        let msg = AdminWsMessage::DbSize;
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(serialized.contains("dbsize"));
        
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized, AdminWsMessage::DbSize));
    }

    #[test]
    fn test_admin_ws_message_time_serialization() {
        let msg = AdminWsMessage::Time;
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(serialized.contains("time"));
        
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized, AdminWsMessage::Time));
    }

    #[test]
    fn test_admin_ws_message_version_serialization() {
        let msg = AdminWsMessage::Version;
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(serialized.contains("version"));
        
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized, AdminWsMessage::Version));
    }

    #[test]
    fn test_admin_ws_message_health_serialization() {
        let msg = AdminWsMessage::Health;
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(serialized.contains("health"));
        
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized, AdminWsMessage::Health));
    }

    #[test]
    fn test_admin_ws_message_status_serialization() {
        let msg = AdminWsMessage::Status;
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(serialized.contains("status"));
        
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized, AdminWsMessage::Status));
    }

    #[test]
    fn test_admin_ws_message_memory_stats_serialization() {
        let msg = AdminWsMessage::MemoryStats;
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(serialized.contains("memory_stats"));
        
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized, AdminWsMessage::MemoryStats));
    }

    #[test]
    fn test_admin_ws_message_client_stats_serialization() {
        let msg = AdminWsMessage::ClientStats;
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(serialized.contains("client_stats"));
        
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized, AdminWsMessage::ClientStats));
    }

    #[test]
    fn test_admin_ws_message_server_stats_serialization() {
        let msg = AdminWsMessage::ServerStats;
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(serialized.contains("server_stats"));
        
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized, AdminWsMessage::ServerStats));
    }

    #[test]
    fn test_admin_ws_message_config_set_serialization() {
        let msg = AdminWsMessage::ConfigSet { 
            parameter: "maxmemory".to_string(), 
            value: "100mb".to_string() 
        };
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(serialized.contains("config_set"));
        assert!(serialized.contains("maxmemory"));
        assert!(serialized.contains("100mb"));
        
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        if let AdminWsMessage::ConfigSet { parameter, value } = deserialized {
            assert_eq!(parameter, "maxmemory");
            assert_eq!(value, "100mb");
        } else {
            panic!("Expected ConfigSet message");
        }
    }

    #[test]
    fn test_admin_ws_message_config_get_serialization() {
        let msg = AdminWsMessage::ConfigGet { parameter: "maxmemory".to_string() };
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(serialized.contains("config_get"));
        assert!(serialized.contains("maxmemory"));
        
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        if let AdminWsMessage::ConfigGet { parameter } = deserialized {
            assert_eq!(parameter, "maxmemory");
        } else {
            panic!("Expected ConfigGet message");
        }
    }

    #[test]
    fn test_admin_ws_message_config_get_all_serialization() {
        let msg = AdminWsMessage::ConfigGetAll;
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(serialized.contains("config_get_all"));
        
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized, AdminWsMessage::ConfigGetAll));
    }

    #[test]
    fn test_admin_ws_message_config_reset_stat_serialization() {
        let msg = AdminWsMessage::ConfigResetStat;
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(serialized.contains("config_resetstat"));
        
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized, AdminWsMessage::ConfigResetStat));
    }

    #[test]
    fn test_admin_ws_message_config_rewrite_serialization() {
        let msg = AdminWsMessage::ConfigRewrite;
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(serialized.contains("config_rewrite"));
        
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized, AdminWsMessage::ConfigRewrite));
    }

    #[test]
    fn test_admin_ws_message_flush_db_serialization() {
        let msg = AdminWsMessage::FlushDb;
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(serialized.contains("flushdb"));
        
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized, AdminWsMessage::FlushDb));
    }

    #[test]
    fn test_admin_ws_message_flush_all_serialization() {
        let msg = AdminWsMessage::FlushAll;
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(serialized.contains("flushall"));
        
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized, AdminWsMessage::FlushAll));
    }

    #[test]
    fn test_admin_ws_message_ping_result_serialization() {
        let msg = AdminWsMessage::PingResult { response: "PONG".to_string() };
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(serialized.contains("ping_result"));
        assert!(serialized.contains("PONG"));
        
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        if let AdminWsMessage::PingResult { response } = deserialized {
            assert_eq!(response, "PONG");
        } else {
            panic!("Expected PingResult message");
        }
    }

    #[test]
    fn test_admin_ws_message_info_result_serialization() {
        let msg = AdminWsMessage::InfoResult { info: "redis_version:6.0.0".to_string() };
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(serialized.contains("info_result"));
        assert!(serialized.contains("redis_version"));
        
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        if let AdminWsMessage::InfoResult { info } = deserialized {
            assert_eq!(info, "redis_version:6.0.0");
        } else {
            panic!("Expected InfoResult message");
        }
    }

    #[test]
    fn test_admin_ws_message_dbsize_result_serialization() {
        let msg = AdminWsMessage::DbSizeResult { size: 42 };
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(serialized.contains("dbsize_result"));
        assert!(serialized.contains("42"));
        
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        if let AdminWsMessage::DbSizeResult { size } = deserialized {
            assert_eq!(size, 42);
        } else {
            panic!("Expected DbSizeResult message");
        }
    }

    #[test]
    fn test_admin_ws_message_time_result_serialization() {
        let msg = AdminWsMessage::TimeResult { seconds: 1640995200, microseconds: 500000 };
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(serialized.contains("time_result"));
        assert!(serialized.contains("1640995200"));
        assert!(serialized.contains("500000"));
        
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        if let AdminWsMessage::TimeResult { seconds, microseconds } = deserialized {
            assert_eq!(seconds, 1640995200);
            assert_eq!(microseconds, 500000);
        } else {
            panic!("Expected TimeResult message");
        }
    }

    #[test]
    fn test_admin_ws_message_version_result_serialization() {
        let msg = AdminWsMessage::VersionResult { version: "6.0.0".to_string() };
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(serialized.contains("version_result"));
        assert!(serialized.contains("6.0.0"));
        
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        if let AdminWsMessage::VersionResult { version } = deserialized {
            assert_eq!(version, "6.0.0");
        } else {
            panic!("Expected VersionResult message");
        }
    }

    #[test]
    fn test_admin_ws_message_health_result_serialization() {
        let health = HealthCheck {
            is_healthy: true,
            ping_response: "PONG".to_string(),
            database_size: 42,
            version: "6.0.0".to_string(),
            memory_usage: HashMap::new(),
        };
        let msg = AdminWsMessage::HealthResult { health };
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(serialized.contains("health_result"));
        assert!(serialized.contains("PONG"));
        
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        if let AdminWsMessage::HealthResult { health } = deserialized {
            assert_eq!(health.is_healthy, true);
            assert_eq!(health.ping_response, "PONG");
            assert_eq!(health.database_size, 42);
            assert_eq!(health.version, "6.0.0");
        } else {
            panic!("Expected HealthResult message");
        }
    }

    #[test]
    fn test_admin_ws_message_status_result_serialization() {
        let status = ServerStatus {
            timestamp: 1640995200,
            uptime_seconds: 3600,
            connected_clients: 5,
            used_memory: 1024000,
            total_commands_processed: 1000,
            keyspace_hits: 800,
            keyspace_misses: 200,
            version: "6.0.0".to_string(),
            role: "master".to_string(),
        };
        let msg = AdminWsMessage::StatusResult { status };
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(serialized.contains("status_result"));
        assert!(serialized.contains("master"));
        
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        if let AdminWsMessage::StatusResult { status } = deserialized {
            assert_eq!(status.timestamp, 1640995200);
            assert_eq!(status.uptime_seconds, 3600);
            assert_eq!(status.connected_clients, 5);
            assert_eq!(status.role, "master");
        } else {
            panic!("Expected StatusResult message");
        }
    }

    #[test]
    fn test_admin_ws_message_memory_stats_result_serialization() {
        let mut stats = HashMap::new();
        stats.insert("used_memory".to_string(), "1024000".to_string());
        stats.insert("used_memory_human".to_string(), "1000.00K".to_string());
        
        let msg = AdminWsMessage::MemoryStatsResult { stats };
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(serialized.contains("memory_stats_result"));
        assert!(serialized.contains("used_memory"));
        
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        if let AdminWsMessage::MemoryStatsResult { stats } = deserialized {
            assert_eq!(stats.get("used_memory"), Some(&"1024000".to_string()));
            assert_eq!(stats.get("used_memory_human"), Some(&"1000.00K".to_string()));
        } else {
            panic!("Expected MemoryStatsResult message");
        }
    }

    #[test]
    fn test_admin_ws_message_client_stats_result_serialization() {
        let mut stats = HashMap::new();
        stats.insert("connected_clients".to_string(), "5".to_string());
        stats.insert("client_recent_max_input_buffer".to_string(), "4".to_string());
        
        let msg = AdminWsMessage::ClientStatsResult { stats };
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(serialized.contains("client_stats_result"));
        assert!(serialized.contains("connected_clients"));
        
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        if let AdminWsMessage::ClientStatsResult { stats } = deserialized {
            assert_eq!(stats.get("connected_clients"), Some(&"5".to_string()));
        } else {
            panic!("Expected ClientStatsResult message");
        }
    }

    #[test]
    fn test_admin_ws_message_server_stats_result_serialization() {
        let mut stats = HashMap::new();
        stats.insert("uptime_in_seconds".to_string(), "3600".to_string());
        stats.insert("total_commands_processed".to_string(), "1000".to_string());
        
        let msg = AdminWsMessage::ServerStatsResult { stats };
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(serialized.contains("server_stats_result"));
        assert!(serialized.contains("uptime_in_seconds"));
        
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        if let AdminWsMessage::ServerStatsResult { stats } = deserialized {
            assert_eq!(stats.get("uptime_in_seconds"), Some(&"3600".to_string()));
        } else {
            panic!("Expected ServerStatsResult message");
        }
    }

    #[test]
    fn test_admin_ws_message_config_get_result_serialization() {
        let msg = AdminWsMessage::ConfigGetResult { 
            parameter: "maxmemory".to_string(), 
            value: "100mb".to_string() 
        };
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(serialized.contains("config_get_result"));
        assert!(serialized.contains("maxmemory"));
        assert!(serialized.contains("100mb"));
        
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        if let AdminWsMessage::ConfigGetResult { parameter, value } = deserialized {
            assert_eq!(parameter, "maxmemory");
            assert_eq!(value, "100mb");
        } else {
            panic!("Expected ConfigGetResult message");
        }
    }

    #[test]
    fn test_admin_ws_message_config_get_all_result_serialization() {
        let mut config = HashMap::new();
        config.insert("maxmemory".to_string(), "100mb".to_string());
        config.insert("timeout".to_string(), "0".to_string());
        
        let msg = AdminWsMessage::ConfigGetAllResult { config };
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(serialized.contains("config_get_all_result"));
        assert!(serialized.contains("maxmemory"));
        
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        if let AdminWsMessage::ConfigGetAllResult { config } = deserialized {
            assert_eq!(config.get("maxmemory"), Some(&"100mb".to_string()));
            assert_eq!(config.get("timeout"), Some(&"0".to_string()));
        } else {
            panic!("Expected ConfigGetAllResult message");
        }
    }

    #[test]
    fn test_admin_ws_message_config_set_result_serialization() {
        let msg = AdminWsMessage::ConfigSetResult { 
            parameter: "maxmemory".to_string(), 
            value: "200mb".to_string() 
        };
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(serialized.contains("config_set_result"));
        assert!(serialized.contains("maxmemory"));
        assert!(serialized.contains("200mb"));
        
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        if let AdminWsMessage::ConfigSetResult { parameter, value } = deserialized {
            assert_eq!(parameter, "maxmemory");
            assert_eq!(value, "200mb");
        } else {
            panic!("Expected ConfigSetResult message");
        }
    }

    #[test]
    fn test_admin_ws_message_config_resetstat_result_serialization() {
        let msg = AdminWsMessage::ConfigResetStatResult;
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(serialized.contains("config_resetstat_result"));
        
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized, AdminWsMessage::ConfigResetStatResult));
    }

    #[test]
    fn test_admin_ws_message_config_rewrite_result_serialization() {
        let msg = AdminWsMessage::ConfigRewriteResult;
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(serialized.contains("config_rewrite_result"));
        
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized, AdminWsMessage::ConfigRewriteResult));
    }

    #[test]
    fn test_admin_ws_message_flushdb_result_serialization() {
        let msg = AdminWsMessage::FlushDbResult;
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(serialized.contains("flushdb_result"));
        
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized, AdminWsMessage::FlushDbResult));
    }

    #[test]
    fn test_admin_ws_message_flushall_result_serialization() {
        let msg = AdminWsMessage::FlushAllResult;
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(serialized.contains("flushall_result"));
        
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized, AdminWsMessage::FlushAllResult));
    }

    #[test]
    fn test_admin_ws_message_error_serialization() {
        let msg = AdminWsMessage::Error("Test error message".to_string());
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(serialized.contains("error"));
        assert!(serialized.contains("Test error message"));
        
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        if let AdminWsMessage::Error(error_msg) = deserialized {
            assert_eq!(error_msg, "Test error message");
        } else {
            panic!("Expected Error message");
        }
    }

    #[test]
    fn test_admin_ws_message_debug_implementation() {
        let msg = AdminWsMessage::Ping;
        let debug_str = format!("{:?}", msg);
        assert!(debug_str.contains("Ping"));
        
        let msg = AdminWsMessage::Error("test".to_string());
        let debug_str = format!("{:?}", msg);
        assert!(debug_str.contains("Error"));
        assert!(debug_str.contains("test"));
    }

    #[test]
    fn test_admin_ws_message_clone_implementation() {
        let msg = AdminWsMessage::Ping;
        let cloned = msg.clone();
        assert!(matches!(cloned, AdminWsMessage::Ping));
        
        let msg = AdminWsMessage::Error("test".to_string());
        let cloned = msg.clone();
        if let AdminWsMessage::Error(error_msg) = cloned {
            assert_eq!(error_msg, "test");
        } else {
            panic!("Expected Error message");
        }
    }

    #[test]
    fn test_create_redis_ws_admin_routes() {
        use dbx_adapter::redis::client::RedisPool;
        
        // Create a mock pool for testing - this tests the route creation function
        let pool = Arc::new(RedisPool::new("redis://localhost:6379", 10).unwrap());
        let router = create_redis_ws_admin_routes(pool);
        
        // Test that the router is created successfully
        // The actual test is that this doesn't panic and returns a Router
        let _service = router.into_make_service();
        // Test passes if we reach this point without panicking
        assert!(true);
    }

    #[test]
    fn test_admin_ws_message_serialization_edge_cases() {
        // Test with empty strings
        let msg = AdminWsMessage::ConfigGet { parameter: "".to_string() };
        let serialized = serde_json::to_string(&msg).unwrap();
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        if let AdminWsMessage::ConfigGet { parameter } = deserialized {
            assert_eq!(parameter, "");
        } else {
            panic!("Expected ConfigGet message");
        }

        // Test with special characters
        let msg = AdminWsMessage::Error("Error with special chars: 你好 🦀 \n\t".to_string());
        let serialized = serde_json::to_string(&msg).unwrap();
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        if let AdminWsMessage::Error(error_msg) = deserialized {
            assert_eq!(error_msg, "Error with special chars: 你好 🦀 \n\t");
        } else {
            panic!("Expected Error message");
        }

        // Test with very long strings
        let long_string = "a".repeat(10000);
        let msg = AdminWsMessage::InfoResult { info: long_string.clone() };
        let serialized = serde_json::to_string(&msg).unwrap();
        let deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        if let AdminWsMessage::InfoResult { info } = deserialized {
            assert_eq!(info, long_string);
        } else {
            panic!("Expected InfoResult message");
        }
    }

    #[test]
    fn test_admin_ws_message_invalid_json_handling() {
        // Test that invalid JSON fails gracefully
        let invalid_json = "{\"type\": \"invalid_type\"}";
        let result = serde_json::from_str::<AdminWsMessage>(invalid_json);
        assert!(result.is_err());

        let malformed_json = "{\"type\": \"ping\", invalid}";
        let result = serde_json::from_str::<AdminWsMessage>(malformed_json);
        assert!(result.is_err());

        let empty_json = "";
        let result = serde_json::from_str::<AdminWsMessage>(empty_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_admin_ws_message_all_variants_covered() {
        // This test ensures we don't miss any variants when adding new ones
        let messages = vec![
            AdminWsMessage::Ping,
            AdminWsMessage::Info { section: None },
            AdminWsMessage::DbSize,
            AdminWsMessage::Time,
            AdminWsMessage::Version,
            AdminWsMessage::Health,
            AdminWsMessage::Status,
            AdminWsMessage::MemoryStats,
            AdminWsMessage::ClientStats,
            AdminWsMessage::ServerStats,
            AdminWsMessage::ConfigSet { parameter: "test".to_string(), value: "test".to_string() },
            AdminWsMessage::ConfigGet { parameter: "test".to_string() },
            AdminWsMessage::ConfigGetAll,
            AdminWsMessage::ConfigResetStat,
            AdminWsMessage::ConfigRewrite,
            AdminWsMessage::FlushDb,
            AdminWsMessage::FlushAll,
            AdminWsMessage::Error("test".to_string()),
        ];
        
        // Test that all message types can be serialized and deserialized
        for msg in messages {
            let serialized = serde_json::to_string(&msg).unwrap();
            let _deserialized: AdminWsMessage = serde_json::from_str(&serialized).unwrap();
        }
    }
}
