use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Universal data operation that can be executed on any backend
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum DataOperation {
    /// Get data by key, optionally specifying fields
    Get {
        key: String,
        fields: Option<Vec<String>>,
    },
    /// Set data with optional TTL
    Set {
        key: String,
        value: DataValue,
        ttl: Option<u64>,
    },
    /// Update specific fields of existing data
    Update {
        key: String,
        fields: HashMap<String, DataValue>,
        ttl: Option<u64>,
    },
    /// Delete data or specific fields
    Delete {
        key: String,
        fields: Option<Vec<String>>,
    },
    /// Check if data or fields exist
    Exists {
        key: String,
        fields: Option<Vec<String>>,
    },
    /// Get TTL for data
    GetTtl { key: String },
    /// Set TTL for data
    SetTtl { key: String, ttl: u64 },
    /// Batch operations
    Batch { operations: Vec<DataOperation> },
}

/// Universal query operation for complex data retrieval
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryOperation {
    pub id: Uuid,
    pub filter: QueryFilter,
    pub projection: Option<Vec<String>>,
    pub sort: Option<Vec<SortField>>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// Query filter for universal queries
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum QueryFilter {
    /// Key pattern matching
    KeyPattern {
        pattern: String,
    },
    /// Field-based filtering
    FieldFilter {
        field: String,
        operator: FilterOperator,
        value: DataValue,
    },
    /// Range queries
    Range {
        field: String,
        min: Option<DataValue>,
        max: Option<DataValue>,
    },
    /// Text search
    TextSearch {
        query: String,
        fields: Option<Vec<String>>,
    },
    /// Logical operations
    And {
        filters: Vec<QueryFilter>,
    },
    Or {
        filters: Vec<QueryFilter>,
    },
    Not {
        filter: Box<QueryFilter>,
    },
}

/// Filter operators for field-based queries
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FilterOperator {
    Eq,
    Ne,
    Gt,
    Gte,
    Lt,
    Lte,
    Contains,
    StartsWith,
    EndsWith,
    In,
    NotIn,
}

/// Sort field specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SortField {
    pub field: String,
    pub direction: SortDirection,
}

/// Sort direction
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SortDirection {
    Asc,
    Desc,
}

/// Universal stream operation for pub/sub and event streaming
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum StreamOperation {
    /// Subscribe to a channel
    Subscribe { channel: String },
    /// Unsubscribe from a channel
    Unsubscribe { channel: String },
    /// Publish message to channel
    Publish { channel: String, message: DataValue },
    /// Create a stream
    CreateStream { name: String, config: StreamConfig },
    /// Add entry to stream
    StreamAdd {
        stream: String,
        fields: HashMap<String, DataValue>,
    },
    /// Read from stream
    StreamRead {
        stream: String,
        from: Option<String>,
        count: Option<usize>,
    },
}

/// Stream configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamConfig {
    pub max_length: Option<usize>,
    pub trim_strategy: Option<TrimStrategy>,
}

/// Stream trim strategy
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrimStrategy {
    MaxLen,
    MinId,
}

/// Universal data value that can represent any data type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DataValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    Bytes(Vec<u8>),
    Array(Vec<DataValue>),
    Object(HashMap<String, DataValue>),
}

impl DataValue {
    /// Check if value is null
    pub fn is_null(&self) -> bool {
        matches!(self, DataValue::Null)
    }

    /// Convert to string representation
    pub fn to_string_lossy(&self) -> String {
        match self {
            DataValue::Null => "null".to_string(),
            DataValue::Bool(b) => b.to_string(),
            DataValue::Int(i) => i.to_string(),
            DataValue::Float(f) => f.to_string(),
            DataValue::String(s) => s.clone(),
            DataValue::Bytes(b) => String::from_utf8_lossy(b).to_string(),
            DataValue::Array(_) | DataValue::Object(_) => {
                serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
            }
        }
    }

    /// Try to convert to a specific type
    pub fn as_string(&self) -> Option<&String> {
        match self {
            DataValue::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            DataValue::Int(i) => Some(*i),
            _ => None,
        }
    }

    pub fn as_float(&self) -> Option<f64> {
        match self {
            DataValue::Float(f) => Some(*f),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            DataValue::Bool(b) => Some(*b),
            _ => None,
        }
    }
}

impl From<String> for DataValue {
    fn from(s: String) -> Self {
        DataValue::String(s)
    }
}

impl From<&str> for DataValue {
    fn from(s: &str) -> Self {
        DataValue::String(s.to_string())
    }
}

impl From<i64> for DataValue {
    fn from(i: i64) -> Self {
        DataValue::Int(i)
    }
}

impl From<f64> for DataValue {
    fn from(f: f64) -> Self {
        DataValue::Float(f)
    }
}

impl From<bool> for DataValue {
    fn from(b: bool) -> Self {
        DataValue::Bool(b)
    }
}

impl From<Vec<u8>> for DataValue {
    fn from(b: Vec<u8>) -> Self {
        DataValue::Bytes(b)
    }
}

impl From<HashMap<String, DataValue>> for DataValue {
    fn from(map: HashMap<String, DataValue>) -> Self {
        DataValue::Object(map)
    }
}

impl From<Vec<DataValue>> for DataValue {
    fn from(vec: Vec<DataValue>) -> Self {
        DataValue::Array(vec)
    }
}
