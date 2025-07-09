use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Data operation that can be executed on any backend
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

/// Query operation for complex data retrieval
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryOperation {
    pub id: Uuid,
    pub filter: QueryFilter,
    pub projection: Option<Vec<String>>,
    pub sort: Option<Vec<SortField>>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// Query filter for database queries
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

/// Stream operation for pub/sub and event streaming
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

/// Data value that can represent any data type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "value")]
pub enum DataValue {
    #[serde(rename = "null")]
    Null,
    #[serde(rename = "bool")]
    Bool(bool),
    #[serde(rename = "int")]
    Int(i64),
    #[serde(rename = "float")]
    Float(f64),
    #[serde(rename = "string")]
    String(String),
    #[serde(rename = "bytes")]
    Bytes(Vec<u8>),
    #[serde(rename = "array")]
    Array(Vec<DataValue>),
    #[serde(rename = "object")]
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;
    use std::collections::HashMap;

    #[test]
    fn test_data_value_is_null() {
        assert!(DataValue::Null.is_null());
        assert!(!DataValue::Bool(true).is_null());
        assert!(!DataValue::String("test".to_string()).is_null());
    }

    #[test]
    fn test_data_value_to_string_lossy() {
        assert_eq!(DataValue::Null.to_string_lossy(), "null");
        assert_eq!(DataValue::Bool(true).to_string_lossy(), "true");
        assert_eq!(DataValue::Int(42).to_string_lossy(), "42");
        assert_eq!(DataValue::Float(3.14).to_string_lossy(), "3.14");
        assert_eq!(
            DataValue::String("hello".to_string()).to_string_lossy(),
            "hello"
        );
        assert_eq!(
            DataValue::Bytes(vec![72, 101, 108, 108, 111]).to_string_lossy(),
            "Hello"
        );

        let arr = DataValue::Array(vec![DataValue::Int(1), DataValue::Int(2)]);
        let arr_str = arr.to_string_lossy();
        assert!(arr_str.contains("1") && arr_str.contains("2"));
    }

    #[test]
    fn test_data_value_type_access() {
        let string_val = DataValue::String("test".to_string());
        assert_eq!(string_val.as_string(), Some(&"test".to_string()));

        let int_val = DataValue::Int(42);
        assert_eq!(int_val.as_int(), Some(42));

        let float_val = DataValue::Float(3.14);
        assert_eq!(float_val.as_float(), Some(3.14));

        let bool_val = DataValue::Bool(true);
        assert_eq!(bool_val.as_bool(), Some(true));

        // Test mismatched access
        assert_eq!(string_val.as_int(), None);
        assert_eq!(int_val.as_string(), None);
    }

    #[test]
    fn test_data_value_from_conversions() {
        assert_eq!(
            DataValue::from("hello"),
            DataValue::String("hello".to_string())
        );
        assert_eq!(
            DataValue::from("world".to_string()),
            DataValue::String("world".to_string())
        );
        assert_eq!(DataValue::from(42i64), DataValue::Int(42));
        assert_eq!(DataValue::from(3.14f64), DataValue::Float(3.14));
        assert_eq!(DataValue::from(true), DataValue::Bool(true));
        assert_eq!(
            DataValue::from(vec![1u8, 2u8, 3u8]),
            DataValue::Bytes(vec![1, 2, 3])
        );

        let mut map = HashMap::new();
        map.insert("key".to_string(), DataValue::String("value".to_string()));
        assert_eq!(DataValue::from(map.clone()), DataValue::Object(map));

        let vec = vec![DataValue::Int(1), DataValue::Int(2)];
        assert_eq!(DataValue::from(vec.clone()), DataValue::Array(vec));
    }

    #[test]
    fn test_data_value_equality() {
        assert_eq!(DataValue::Null, DataValue::Null);
        assert_eq!(DataValue::Bool(true), DataValue::Bool(true));
        assert_eq!(DataValue::Int(42), DataValue::Int(42));
        assert_eq!(DataValue::Float(3.14), DataValue::Float(3.14));
        assert_eq!(
            DataValue::String("test".to_string()),
            DataValue::String("test".to_string())
        );

        assert_ne!(DataValue::Int(42), DataValue::String("42".to_string()));
        assert_ne!(DataValue::Bool(true), DataValue::Int(1));
    }

    #[test]
    fn test_data_value_serialization() {
        let values = vec![
            DataValue::Null,
            DataValue::Bool(true),
            DataValue::Int(42),
            DataValue::Float(3.14),
            DataValue::String("test".to_string()),
            DataValue::Bytes(vec![1, 2, 3]),
        ];

        for value in values {
            let json = serde_json::to_string(&value).unwrap();
            let deserialized: DataValue = serde_json::from_str(&json).unwrap();
            assert_eq!(value, deserialized);
        }
    }

    #[test]
    fn test_data_operation_variants() {
        // Test Get operation
        let get_op = DataOperation::Get {
            key: "test_key".to_string(),
            fields: Some(vec!["field1".to_string(), "field2".to_string()]),
        };

        match get_op {
            DataOperation::Get { key, fields } => {
                assert_eq!(key, "test_key");
                assert_eq!(
                    fields,
                    Some(vec!["field1".to_string(), "field2".to_string()])
                );
            }
            _ => panic!("Expected Get variant"),
        }

        // Test Set operation
        let set_op = DataOperation::Set {
            key: "test_key".to_string(),
            value: DataValue::String("test_value".to_string()),
            ttl: Some(3600),
        };

        match set_op {
            DataOperation::Set { key, value, ttl } => {
                assert_eq!(key, "test_key");
                assert_eq!(value, DataValue::String("test_value".to_string()));
                assert_eq!(ttl, Some(3600));
            }
            _ => panic!("Expected Set variant"),
        }

        // Test Update operation
        let mut fields = HashMap::new();
        fields.insert(
            "field1".to_string(),
            DataValue::String("new_value".to_string()),
        );

        let update_op = DataOperation::Update {
            key: "test_key".to_string(),
            fields: fields.clone(),
            ttl: None,
        };

        match update_op {
            DataOperation::Update {
                key,
                fields: f,
                ttl,
            } => {
                assert_eq!(key, "test_key");
                assert_eq!(f, fields);
                assert_eq!(ttl, None);
            }
            _ => panic!("Expected Update variant"),
        }

        // Test Delete operation
        let delete_op = DataOperation::Delete {
            key: "test_key".to_string(),
            fields: None,
        };

        match delete_op {
            DataOperation::Delete { key, fields } => {
                assert_eq!(key, "test_key");
                assert_eq!(fields, None);
            }
            _ => panic!("Expected Delete variant"),
        }

        // Test Exists operation
        let exists_op = DataOperation::Exists {
            key: "test_key".to_string(),
            fields: Some(vec!["field1".to_string()]),
        };

        match exists_op {
            DataOperation::Exists { key, fields } => {
                assert_eq!(key, "test_key");
                assert_eq!(fields, Some(vec!["field1".to_string()]));
            }
            _ => panic!("Expected Exists variant"),
        }

        // Test GetTtl operation
        let get_ttl_op = DataOperation::GetTtl {
            key: "test_key".to_string(),
        };

        match get_ttl_op {
            DataOperation::GetTtl { key } => {
                assert_eq!(key, "test_key");
            }
            _ => panic!("Expected GetTtl variant"),
        }

        // Test SetTtl operation
        let set_ttl_op = DataOperation::SetTtl {
            key: "test_key".to_string(),
            ttl: 7200,
        };

        match set_ttl_op {
            DataOperation::SetTtl { key, ttl } => {
                assert_eq!(key, "test_key");
                assert_eq!(ttl, 7200);
            }
            _ => panic!("Expected SetTtl variant"),
        }

        // Test Batch operation
        let batch_ops = vec![
            DataOperation::Get {
                key: "key1".to_string(),
                fields: None,
            },
            DataOperation::Set {
                key: "key2".to_string(),
                value: DataValue::Int(42),
                ttl: None,
            },
        ];

        let batch_op = DataOperation::Batch {
            operations: batch_ops.clone(),
        };

        match batch_op {
            DataOperation::Batch { operations } => {
                assert_eq!(operations.len(), 2);
                assert_eq!(operations, batch_ops);
            }
            _ => panic!("Expected Batch variant"),
        }
    }

    #[test]
    fn test_query_operation() {
        let query_id = Uuid::new_v4();
        let filter = QueryFilter::KeyPattern {
            pattern: "user:*".to_string(),
        };
        let projection = Some(vec!["name".to_string(), "email".to_string()]);
        let sort = Some(vec![SortField {
            field: "created_at".to_string(),
            direction: SortDirection::Desc,
        }]);

        let query_op = QueryOperation {
            id: query_id,
            filter: filter.clone(),
            projection: projection.clone(),
            sort: sort.clone(),
            limit: Some(10),
            offset: Some(20),
        };

        assert_eq!(query_op.id, query_id);
        assert_eq!(query_op.limit, Some(10));
        assert_eq!(query_op.offset, Some(20));

        match query_op.filter {
            QueryFilter::KeyPattern { pattern } => {
                assert_eq!(pattern, "user:*");
            }
            _ => panic!("Expected KeyPattern filter"),
        }
    }

    #[test]
    fn test_query_filter_variants() {
        // Test KeyPattern filter
        let key_pattern = QueryFilter::KeyPattern {
            pattern: "prefix:*".to_string(),
        };

        // Test FieldFilter
        let field_filter = QueryFilter::FieldFilter {
            field: "age".to_string(),
            operator: FilterOperator::Gte,
            value: DataValue::Int(18),
        };

        // Test Range filter
        let range_filter = QueryFilter::Range {
            field: "score".to_string(),
            min: Some(DataValue::Float(0.0)),
            max: Some(DataValue::Float(100.0)),
        };

        // Test TextSearch filter
        let text_search = QueryFilter::TextSearch {
            query: "search term".to_string(),
            fields: Some(vec!["title".to_string(), "content".to_string()]),
        };

        // Test And filter
        let and_filter = QueryFilter::And {
            filters: vec![key_pattern.clone(), field_filter.clone()],
        };

        // Test Or filter
        let or_filter = QueryFilter::Or {
            filters: vec![range_filter.clone(), text_search.clone()],
        };

        // Test Not filter
        let not_filter = QueryFilter::Not {
            filter: Box::new(field_filter.clone()),
        };

        // Test serialization
        let filters = vec![
            key_pattern,
            field_filter,
            range_filter,
            text_search,
            and_filter,
            or_filter,
            not_filter,
        ];

        for filter in filters {
            let json = serde_json::to_string(&filter).unwrap();
            let _deserialized: QueryFilter = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn test_filter_operators() {
        let operators = vec![
            FilterOperator::Eq,
            FilterOperator::Ne,
            FilterOperator::Gt,
            FilterOperator::Gte,
            FilterOperator::Lt,
            FilterOperator::Lte,
            FilterOperator::Contains,
            FilterOperator::StartsWith,
            FilterOperator::EndsWith,
            FilterOperator::In,
            FilterOperator::NotIn,
        ];

        for operator in operators {
            let json = serde_json::to_string(&operator).unwrap();
            let _deserialized: FilterOperator = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn test_sort_field() {
        let sort_asc = SortField {
            field: "name".to_string(),
            direction: SortDirection::Asc,
        };

        let sort_desc = SortField {
            field: "created_at".to_string(),
            direction: SortDirection::Desc,
        };

        assert_eq!(sort_asc.field, "name");
        assert_eq!(sort_desc.field, "created_at");

        let json_asc = serde_json::to_string(&sort_asc).unwrap();
        let json_desc = serde_json::to_string(&sort_desc).unwrap();

        let _deser_asc: SortField = serde_json::from_str(&json_asc).unwrap();
        let _deser_desc: SortField = serde_json::from_str(&json_desc).unwrap();
    }

    #[test]
    fn test_stream_operation_variants() {
        // Test Subscribe
        let subscribe = StreamOperation::Subscribe {
            channel: "notifications".to_string(),
        };

        // Test Unsubscribe
        let unsubscribe = StreamOperation::Unsubscribe {
            channel: "notifications".to_string(),
        };

        // Test Publish
        let publish = StreamOperation::Publish {
            channel: "messages".to_string(),
            message: DataValue::String("Hello, World!".to_string()),
        };

        // Test CreateStream
        let create_stream = StreamOperation::CreateStream {
            name: "events".to_string(),
            config: StreamConfig {
                max_length: Some(1000),
                trim_strategy: Some(TrimStrategy::MaxLen),
            },
        };

        // Test StreamAdd
        let mut fields = HashMap::new();
        fields.insert(
            "event_type".to_string(),
            DataValue::String("user_login".to_string()),
        );
        fields.insert("user_id".to_string(), DataValue::Int(12345));

        let stream_add = StreamOperation::StreamAdd {
            stream: "user_events".to_string(),
            fields: fields.clone(),
        };

        // Test StreamRead
        let stream_read = StreamOperation::StreamRead {
            stream: "user_events".to_string(),
            from: Some("1234567890-0".to_string()),
            count: Some(100),
        };

        let operations = vec![
            subscribe,
            unsubscribe,
            publish,
            create_stream,
            stream_add,
            stream_read,
        ];

        for operation in operations {
            let json = serde_json::to_string(&operation).unwrap();
            let _deserialized: StreamOperation = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn test_stream_config() {
        let config1 = StreamConfig {
            max_length: Some(1000),
            trim_strategy: Some(TrimStrategy::MaxLen),
        };

        let config2 = StreamConfig {
            max_length: None,
            trim_strategy: Some(TrimStrategy::MinId),
        };

        let config3 = StreamConfig {
            max_length: Some(5000),
            trim_strategy: None,
        };

        let configs = vec![config1, config2, config3];

        for config in configs {
            let json = serde_json::to_string(&config).unwrap();
            let _deserialized: StreamConfig = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn test_trim_strategy() {
        let strategies = vec![TrimStrategy::MaxLen, TrimStrategy::MinId];

        for strategy in strategies {
            let json = serde_json::to_string(&strategy).unwrap();
            let _deserialized: TrimStrategy = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn test_data_operation_serialization() {
        let operations = vec![
            DataOperation::Get {
                key: "test".to_string(),
                fields: None,
            },
            DataOperation::Set {
                key: "test".to_string(),
                value: DataValue::String("value".to_string()),
                ttl: Some(3600),
            },
            DataOperation::Delete {
                key: "test".to_string(),
                fields: Some(vec!["field1".to_string()]),
            },
            DataOperation::Exists {
                key: "test".to_string(),
                fields: None,
            },
        ];

        for operation in operations {
            let json = serde_json::to_string(&operation).unwrap();
            let _deserialized: DataOperation = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn test_complex_data_value_structures() {
        // Test nested object
        let mut inner_obj = HashMap::new();
        inner_obj.insert("nested_field".to_string(), DataValue::Int(42));

        let mut outer_obj = HashMap::new();
        outer_obj.insert("inner".to_string(), DataValue::Object(inner_obj));
        outer_obj.insert("simple".to_string(), DataValue::String("value".to_string()));

        let complex_obj = DataValue::Object(outer_obj);

        // Test nested array
        let nested_array = DataValue::Array(vec![
            DataValue::Array(vec![DataValue::Int(1), DataValue::Int(2)]),
            DataValue::Array(vec![
                DataValue::String("a".to_string()),
                DataValue::String("b".to_string()),
            ]),
        ]);

        // Test mixed array
        let mixed_array = DataValue::Array(vec![
            DataValue::Int(1),
            DataValue::String("text".to_string()),
            DataValue::Bool(true),
            DataValue::Null,
        ]);

        let complex_values = vec![complex_obj, nested_array, mixed_array];

        for value in complex_values {
            let json = serde_json::to_string(&value).unwrap();
            let deserialized: DataValue = serde_json::from_str(&json).unwrap();
            assert_eq!(value, deserialized);
        }
    }
}
