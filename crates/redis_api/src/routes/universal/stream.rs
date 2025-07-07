use axum::{
    extract::{Json, Path, State, WebSocketUpgrade},
    http::StatusCode,
    response::{Json as ResponseJson, Response},
    routing::{delete, get, post},
    Router,
};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, warn};

use dbx_core::{DataValue, StreamEntry, StreamOperation, StreamResult};
use dbx_router::BackendRouter;

use crate::models::ApiResponse;

/// Universal stream operation request
#[derive(Debug, Serialize, Deserialize)]
pub struct StreamRequest {
    pub data: Option<DataValue>,
    pub fields: Option<HashMap<String, DataValue>>,
    pub stream_id: Option<String>,
    pub maxlen: Option<u64>,
    pub approx_maxlen: Option<bool>,
}

/// Universal pub/sub request
#[derive(Debug, Serialize, Deserialize)]
pub struct PubSubRequest {
    pub message: DataValue,
    pub metadata: Option<HashMap<String, String>>,
}

/// Universal stream response
#[derive(Debug, Serialize, Deserialize)]
pub struct StreamResponse {
    pub success: bool,
    pub data: Option<StreamData>,
    pub metadata: Option<StreamMetadata>,
    pub error: Option<String>,
}

/// Stream operation data
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StreamData {
    Entries(Vec<StreamEntryData>),
    StreamId(String),
    SubscriberCount(u64),
    Message(DataValue),
}

/// Stream entry data
#[derive(Debug, Serialize, Deserialize)]
pub struct StreamEntryData {
    pub id: String,
    pub fields: HashMap<String, DataValue>,
    pub timestamp: Option<u64>,
}

/// Stream response metadata
#[derive(Debug, Serialize, Deserialize)]
pub struct StreamMetadata {
    pub backend_used: String,
    pub operation_time_ms: u64,
    pub stream_length: Option<u64>,
    pub consumer_group: Option<String>,
}

/// WebSocket message for streaming
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum WebSocketMessage {
    Subscribe { channels: Vec<String> },
    Unsubscribe { channels: Vec<String> },
    Message { channel: String, data: DataValue },
    Error { message: String },
    Pong,
}

// =========================
// Universal Stream Handlers
// =========================

/// POST /api/v1/stream/{stream}/add - Add entry to stream
pub async fn add_to_stream(
    State(router): State<Arc<BackendRouter>>,
    Path(stream): Path<String>,
    Json(request): Json<StreamRequest>,
) -> Result<ResponseJson<ApiResponse<StreamResponse>>, StatusCode> {
    debug!(stream = %stream, "Universal STREAM ADD operation");

    let fields = request.fields.unwrap_or_default();
    let operation = StreamOperation::StreamAdd {
        stream: stream.clone(),
        id: request.stream_id,
        fields,
        maxlen: request.maxlen,
        approx_maxlen: request.approx_maxlen.unwrap_or(false),
    };

    match execute_stream_operation(&router, operation).await {
        Ok((result, backend_name, duration)) => {
            let data = match result {
                StreamResult::StreamId(id) => Some(StreamData::StreamId(id)),
                _ => None,
            };

            let response = StreamResponse {
                success: true,
                data,
                metadata: Some(StreamMetadata {
                    backend_used: backend_name,
                    operation_time_ms: duration,
                    stream_length: None,
                    consumer_group: None,
                }),
                error: None,
            };

            Ok(ResponseJson(ApiResponse::success(response)))
        }
        Err(e) => {
            error!(stream = %stream, error = %e, "STREAM ADD operation failed");
            Ok(ResponseJson(ApiResponse::error(format!(
                "Failed to add to stream: {}",
                e
            ))))
        }
    }
}

/// GET /api/v1/stream/{stream}/read - Read from stream
pub async fn read_from_stream(
    State(router): State<Arc<BackendRouter>>,
    Path(stream): Path<String>,
) -> Result<ResponseJson<ApiResponse<StreamResponse>>, StatusCode> {
    debug!(stream = %stream, "Universal STREAM READ operation");

    let operation = StreamOperation::StreamRead {
        stream: stream.clone(),
        start_id: Some("0".to_string()),
        end_id: None,
        count: Some(100), // Default limit
        block_ms: None,
    };

    match execute_stream_operation(&router, operation).await {
        Ok((result, backend_name, duration)) => {
            let data = match result {
                StreamResult::Entries(entries) => {
                    let entry_data: Vec<StreamEntryData> = entries
                        .into_iter()
                        .map(|entry| StreamEntryData {
                            id: entry.id,
                            fields: entry.fields,
                            timestamp: entry.timestamp,
                        })
                        .collect();
                    Some(StreamData::Entries(entry_data))
                }
                _ => None,
            };

            let response = StreamResponse {
                success: true,
                data,
                metadata: Some(StreamMetadata {
                    backend_used: backend_name,
                    operation_time_ms: duration,
                    stream_length: None,
                    consumer_group: None,
                }),
                error: None,
            };

            Ok(ResponseJson(ApiResponse::success(response)))
        }
        Err(e) => {
            error!(stream = %stream, error = %e, "STREAM READ operation failed");
            Ok(ResponseJson(ApiResponse::error(format!(
                "Failed to read from stream: {}",
                e
            ))))
        }
    }
}

/// POST /api/v1/stream/{stream}/create - Create stream
pub async fn create_stream(
    State(router): State<Arc<BackendRouter>>,
    Path(stream): Path<String>,
    Json(request): Json<StreamRequest>,
) -> Result<ResponseJson<ApiResponse<StreamResponse>>, StatusCode> {
    debug!(stream = %stream, "Universal STREAM CREATE operation");

    let operation = StreamOperation::CreateStream {
        name: stream.clone(),
        maxlen: request.maxlen,
        approx_maxlen: request.approx_maxlen.unwrap_or(false),
    };

    match execute_stream_operation(&router, operation).await {
        Ok((result, backend_name, duration)) => {
            let response = StreamResponse {
                success: true,
                data: None,
                metadata: Some(StreamMetadata {
                    backend_used: backend_name,
                    operation_time_ms: duration,
                    stream_length: Some(0),
                    consumer_group: None,
                }),
                error: None,
            };

            Ok(ResponseJson(ApiResponse::success(response)))
        }
        Err(e) => {
            error!(stream = %stream, error = %e, "STREAM CREATE operation failed");
            Ok(ResponseJson(ApiResponse::error(format!(
                "Failed to create stream: {}",
                e
            ))))
        }
    }
}

/// POST /api/v1/pubsub/{channel}/publish - Publish message to channel
pub async fn publish_message(
    State(router): State<Arc<BackendRouter>>,
    Path(channel): Path<String>,
    Json(request): Json<PubSubRequest>,
) -> Result<ResponseJson<ApiResponse<StreamResponse>>, StatusCode> {
    debug!(channel = %channel, "Universal PUBLISH operation");

    let operation = StreamOperation::Publish {
        channel: channel.clone(),
        message: request.message,
    };

    match execute_stream_operation(&router, operation).await {
        Ok((result, backend_name, duration)) => {
            let data = match result {
                StreamResult::SubscriberCount(count) => Some(StreamData::SubscriberCount(count)),
                _ => None,
            };

            let response = StreamResponse {
                success: true,
                data,
                metadata: Some(StreamMetadata {
                    backend_used: backend_name,
                    operation_time_ms: duration,
                    stream_length: None,
                    consumer_group: None,
                }),
                error: None,
            };

            Ok(ResponseJson(ApiResponse::success(response)))
        }
        Err(e) => {
            error!(channel = %channel, error = %e, "PUBLISH operation failed");
            Ok(ResponseJson(ApiResponse::error(format!(
                "Failed to publish message: {}",
                e
            ))))
        }
    }
}

/// WebSocket endpoint for real-time subscriptions
pub async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(router): State<Arc<BackendRouter>>,
) -> Response {
    debug!("Universal WebSocket connection established");
    ws.on_upgrade(|socket| handle_websocket(socket, router))
}

/// Handle WebSocket connection for streaming
async fn handle_websocket(mut socket: axum::extract::ws::WebSocket, router: Arc<BackendRouter>) {
    debug!("WebSocket handler started");

    // Track subscribed channels
    let mut subscriptions: Vec<String> = Vec::new();

    while let Some(msg) = socket.recv().await {
        match msg {
            Ok(axum::extract::ws::Message::Text(text)) => {
                match serde_json::from_str::<WebSocketMessage>(&text) {
                    Ok(WebSocketMessage::Subscribe { channels }) => {
                        debug!(channels = ?channels, "WebSocket SUBSCRIBE request");

                        for channel in &channels {
                            let operation = StreamOperation::Subscribe {
                                channel: channel.clone(),
                                callback: None,
                            };

                            match execute_stream_operation(&router, operation).await {
                                Ok(_) => {
                                    subscriptions.push(channel.clone());
                                    debug!(channel = %channel, "Subscribed to channel");
                                }
                                Err(e) => {
                                    error!(channel = %channel, error = %e, "Failed to subscribe");
                                    let error_msg = WebSocketMessage::Error {
                                        message: format!(
                                            "Failed to subscribe to {}: {}",
                                            channel, e
                                        ),
                                    };
                                    if let Ok(msg_text) = serde_json::to_string(&error_msg) {
                                        let _ = socket
                                            .send(axum::extract::ws::Message::Text(msg_text))
                                            .await;
                                    }
                                }
                            }
                        }
                    }
                    Ok(WebSocketMessage::Unsubscribe { channels }) => {
                        debug!(channels = ?channels, "WebSocket UNSUBSCRIBE request");

                        for channel in &channels {
                            let operation = StreamOperation::Unsubscribe {
                                channel: channel.clone(),
                            };

                            match execute_stream_operation(&router, operation).await {
                                Ok(_) => {
                                    subscriptions.retain(|c| c != channel);
                                    debug!(channel = %channel, "Unsubscribed from channel");
                                }
                                Err(e) => {
                                    error!(channel = %channel, error = %e, "Failed to unsubscribe");
                                }
                            }
                        }
                    }
                    Ok(WebSocketMessage::Pong) => {
                        debug!("WebSocket pong received");
                    }
                    Ok(_) => {
                        warn!("Unexpected WebSocket message type");
                    }
                    Err(e) => {
                        error!(error = %e, "Failed to parse WebSocket message");
                        let error_msg = WebSocketMessage::Error {
                            message: format!("Invalid message format: {}", e),
                        };
                        if let Ok(msg_text) = serde_json::to_string(&error_msg) {
                            let _ = socket
                                .send(axum::extract::ws::Message::Text(msg_text))
                                .await;
                        }
                    }
                }
            }
            Ok(axum::extract::ws::Message::Close(_)) => {
                debug!("WebSocket connection closed");
                break;
            }
            Ok(_) => {
                warn!("Received non-text WebSocket message");
            }
            Err(e) => {
                error!(error = %e, "WebSocket error");
                break;
            }
        }
    }

    // Clean up subscriptions
    for channel in subscriptions {
        let operation = StreamOperation::Unsubscribe { channel };
        let _ = execute_stream_operation(&router, operation).await;
    }

    debug!("WebSocket handler terminated");
}

// =========================
// Helper Functions
// =========================

/// Execute stream operation and measure performance
async fn execute_stream_operation(
    router: &BackendRouter,
    operation: StreamOperation,
) -> Result<(StreamResult, String, u64), dbx_core::DbxError> {
    let start_time = std::time::Instant::now();

    // Route the operation to appropriate backend
    let backend = router.route_stream_operation(&operation).await?;
    let backend_name = backend.name().to_string();

    // Execute the operation
    let result = backend.execute_stream(operation).await?;

    let duration = start_time.elapsed().as_millis() as u64;

    Ok((result, backend_name, duration))
}

/// Create universal stream routes
pub fn create_universal_stream_routes(router: Arc<BackendRouter>) -> Router {
    Router::new()
        .route("/stream/:stream/add", post(add_to_stream))
        .route("/stream/:stream/read", get(read_from_stream))
        .route("/stream/:stream/create", post(create_stream))
        .route("/pubsub/:channel/publish", post(publish_message))
        .route("/ws", get(websocket_handler))
        .with_state(router)
}
