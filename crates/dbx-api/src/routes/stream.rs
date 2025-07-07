use axum::{extract::State, http::StatusCode, response::Json, routing::post, Router};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use crate::models::ApiResponse;
use dbx_core::{DataValue, StreamConfig, StreamOperation, StreamResult};
use dbx_router::BackendRouter;

#[derive(Debug, Deserialize)]
pub struct AddStreamEntryRequest {
    pub stream: String,
    pub fields: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct ReadStreamRequest {
    pub stream: String,
    pub from: Option<String>,
    pub count: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct CreateStreamRequest {
    pub name: String,
    pub max_length: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct SubscribeRequest {
    pub channel: String,
}

#[derive(Debug, Deserialize)]
pub struct PublishRequest {
    pub channel: String,
    pub message: serde_json::Value,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type")]
pub enum StreamResponse {
    EntryAdded {
        stream: String,
        entry_id: String,
    },
    StreamRead {
        stream: String,
        entries: Vec<StreamEntryResponse>,
    },
    StreamCreated {
        stream: String,
        stream_id: String,
    },
    Subscribed {
        channel: String,
        subscriber_id: String,
    },
    Published {
        channel: String,
        message_id: String,
    },
    Error {
        operation_id: String,
        error: String,
    },
}

#[derive(Debug, Serialize)]
pub struct StreamEntryResponse {
    pub id: String,
    pub fields: HashMap<String, serde_json::Value>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

pub fn create_stream_routes() -> Router<Arc<BackendRouter>> {
    Router::new()
        .route("/add", post(add_stream_entry))
        .route("/read", post(read_stream))
        .route("/create", post(create_stream))
        .route("/subscribe", post(subscribe))
        .route("/publish", post(publish))
}

async fn add_stream_entry(
    State(router): State<Arc<BackendRouter>>,
    Json(request): Json<AddStreamEntryRequest>,
) -> Result<Json<ApiResponse<StreamResponse>>, StatusCode> {
    let operation = StreamOperation::StreamAdd {
        stream: request.stream,
        fields: request
            .fields
            .into_iter()
            .map(|(k, v)| (k, json_to_data_value(v)))
            .collect(),
    };

    match router.route_stream_operation(&operation).await {
        Ok(backend) => match backend.execute_stream(operation).await {
            Ok(result) => {
                let response = match result {
                    StreamResult::StreamEntryAdded { stream, entry_id } => {
                        StreamResponse::EntryAdded { stream, entry_id }
                    }
                    StreamResult::Error {
                        operation_id,
                        error,
                    } => StreamResponse::Error {
                        operation_id: operation_id.to_string(),
                        error: error.to_string(),
                    },
                    _ => StreamResponse::Error {
                        operation_id: uuid::Uuid::new_v4().to_string(),
                        error: "Unexpected result type".to_string(),
                    },
                };
                Ok(Json(ApiResponse::success(response)))
            }
            Err(e) => Ok(Json(ApiResponse::error(format!(
                "Failed to add stream entry: {}",
                e
            )))),
        },
        Err(e) => Ok(Json(ApiResponse::error(format!(
            "Failed to route stream operation: {}",
            e
        )))),
    }
}

async fn read_stream(
    State(router): State<Arc<BackendRouter>>,
    Json(request): Json<ReadStreamRequest>,
) -> Result<Json<ApiResponse<StreamResponse>>, StatusCode> {
    let operation = StreamOperation::StreamRead {
        stream: request.stream,
        from: request.from,
        count: request.count,
    };

    match router.route_stream_operation(&operation).await {
        Ok(backend) => match backend.execute_stream(operation).await {
            Ok(result) => {
                let response = match result {
                    StreamResult::StreamRead { stream, entries } => {
                        let converted_entries: Vec<StreamEntryResponse> = entries
                            .into_iter()
                            .map(|entry| StreamEntryResponse {
                                id: entry.id,
                                fields: entry
                                    .fields
                                    .into_iter()
                                    .map(|(k, v)| (k, data_value_to_json(v)))
                                    .collect(),
                                timestamp: entry.timestamp,
                            })
                            .collect();
                        StreamResponse::StreamRead {
                            stream,
                            entries: converted_entries,
                        }
                    }
                    StreamResult::Error {
                        operation_id,
                        error,
                    } => StreamResponse::Error {
                        operation_id: operation_id.to_string(),
                        error: error.to_string(),
                    },
                    _ => StreamResponse::Error {
                        operation_id: uuid::Uuid::new_v4().to_string(),
                        error: "Unexpected result type".to_string(),
                    },
                };
                Ok(Json(ApiResponse::success(response)))
            }
            Err(e) => Ok(Json(ApiResponse::error(format!(
                "Failed to read from stream: {}",
                e
            )))),
        },
        Err(e) => Ok(Json(ApiResponse::error(format!(
            "Failed to route stream operation: {}",
            e
        )))),
    }
}

async fn create_stream(
    State(router): State<Arc<BackendRouter>>,
    Json(request): Json<CreateStreamRequest>,
) -> Result<Json<ApiResponse<StreamResponse>>, StatusCode> {
    let operation = StreamOperation::CreateStream {
        name: request.name,
        config: StreamConfig {
            max_length: request.max_length,
            trim_strategy: None,
        },
    };

    match router.route_stream_operation(&operation).await {
        Ok(backend) => match backend.execute_stream(operation).await {
            Ok(result) => {
                let response = match result {
                    StreamResult::StreamCreated { stream, stream_id } => {
                        StreamResponse::StreamCreated { stream, stream_id }
                    }
                    StreamResult::Error {
                        operation_id,
                        error,
                    } => StreamResponse::Error {
                        operation_id: operation_id.to_string(),
                        error: error.to_string(),
                    },
                    _ => StreamResponse::Error {
                        operation_id: uuid::Uuid::new_v4().to_string(),
                        error: "Unexpected result type".to_string(),
                    },
                };
                Ok(Json(ApiResponse::success(response)))
            }
            Err(e) => Ok(Json(ApiResponse::error(format!(
                "Failed to create stream: {}",
                e
            )))),
        },
        Err(e) => Ok(Json(ApiResponse::error(format!(
            "Failed to route stream operation: {}",
            e
        )))),
    }
}

async fn subscribe(
    State(router): State<Arc<BackendRouter>>,
    Json(request): Json<SubscribeRequest>,
) -> Result<Json<ApiResponse<StreamResponse>>, StatusCode> {
    let operation = StreamOperation::Subscribe {
        channel: request.channel,
    };

    match router.route_stream_operation(&operation).await {
        Ok(backend) => match backend.execute_stream(operation).await {
            Ok(result) => {
                let response = match result {
                    StreamResult::Subscribed {
                        channel,
                        subscriber_id,
                    } => StreamResponse::Subscribed {
                        channel,
                        subscriber_id: subscriber_id.to_string(),
                    },
                    StreamResult::Error {
                        operation_id,
                        error,
                    } => StreamResponse::Error {
                        operation_id: operation_id.to_string(),
                        error: error.to_string(),
                    },
                    _ => StreamResponse::Error {
                        operation_id: uuid::Uuid::new_v4().to_string(),
                        error: "Unexpected result type".to_string(),
                    },
                };
                Ok(Json(ApiResponse::success(response)))
            }
            Err(e) => Ok(Json(ApiResponse::error(format!(
                "Failed to subscribe: {}",
                e
            )))),
        },
        Err(e) => Ok(Json(ApiResponse::error(format!(
            "Failed to route stream operation: {}",
            e
        )))),
    }
}

async fn publish(
    State(router): State<Arc<BackendRouter>>,
    Json(request): Json<PublishRequest>,
) -> Result<Json<ApiResponse<StreamResponse>>, StatusCode> {
    let operation = StreamOperation::Publish {
        channel: request.channel,
        message: json_to_data_value(request.message),
    };

    match router.route_stream_operation(&operation).await {
        Ok(backend) => match backend.execute_stream(operation).await {
            Ok(result) => {
                let response = match result {
                    StreamResult::Published {
                        channel,
                        message_id,
                    } => StreamResponse::Published {
                        channel,
                        message_id,
                    },
                    StreamResult::Error {
                        operation_id,
                        error,
                    } => StreamResponse::Error {
                        operation_id: operation_id.to_string(),
                        error: error.to_string(),
                    },
                    _ => StreamResponse::Error {
                        operation_id: uuid::Uuid::new_v4().to_string(),
                        error: "Unexpected result type".to_string(),
                    },
                };
                Ok(Json(ApiResponse::success(response)))
            }
            Err(e) => Ok(Json(ApiResponse::error(format!(
                "Failed to publish: {}",
                e
            )))),
        },
        Err(e) => Ok(Json(ApiResponse::error(format!(
            "Failed to route stream operation: {}",
            e
        )))),
    }
}

fn json_to_data_value(value: serde_json::Value) -> DataValue {
    match value {
        serde_json::Value::Null => DataValue::Null,
        serde_json::Value::Bool(b) => DataValue::Bool(b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                DataValue::Int(i)
            } else if let Some(f) = n.as_f64() {
                DataValue::Float(f)
            } else {
                DataValue::String(n.to_string())
            }
        }
        serde_json::Value::String(s) => DataValue::String(s),
        serde_json::Value::Array(arr) => {
            DataValue::Array(arr.into_iter().map(json_to_data_value).collect())
        }
        serde_json::Value::Object(obj) => DataValue::Object(
            obj.into_iter()
                .map(|(k, v)| (k, json_to_data_value(v)))
                .collect(),
        ),
    }
}

fn data_value_to_json(value: DataValue) -> serde_json::Value {
    match value {
        DataValue::Null => serde_json::Value::Null,
        DataValue::Bool(b) => serde_json::Value::Bool(b),
        DataValue::Int(i) => serde_json::Value::Number(serde_json::Number::from(i)),
        DataValue::Float(f) => serde_json::Value::Number(
            serde_json::Number::from_f64(f).unwrap_or(serde_json::Number::from(0)),
        ),
        DataValue::String(s) => serde_json::Value::String(s),
        DataValue::Bytes(b) => {
            serde_json::Value::String(base64::prelude::BASE64_STANDARD.encode(b))
        }
        DataValue::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(data_value_to_json).collect())
        }
        DataValue::Object(obj) => serde_json::Value::Object(
            obj.into_iter()
                .map(|(k, v)| (k, data_value_to_json(v)))
                .collect(),
        ),
    }
}
