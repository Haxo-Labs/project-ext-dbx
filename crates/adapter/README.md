# DBX Adapter Crate

This crate provides the adapter layer for DBX, implementing backend-specific database connections that conform to the `UniversalBackend` trait defined in `dbx-core`.

## Overview

The adapter crate serves as the bridge between DBX's backend-agnostic API and specific database implementations. Each database backend (Redis, MongoDB, PostgreSQL, etc.) implements the `UniversalBackend` trait, providing a consistent interface for data operations.

## Architecture

### Core Components

- **Backend Factory**: Creates appropriate backend instances based on configuration
- **Backend Implementations**: Database-specific adapter implementations
- **Connection Management**: Handles connection pooling and lifecycle
- **Error Mapping**: Maps database-specific errors to DBX errors

### Supported Backends

#### Redis Adapter

- **Location**: `src/redis/`
- **Features**: Complete Redis protocol implementation
- **Operations**: Strings, hashes, sets, sorted sets, bitmaps, admin
- **Connection**: Redis connection pooling with automatic failover

#### Planned Backends

- **MongoDB**: Document operations and aggregation pipeline
- **PostgreSQL**: SQL operations with prepared statements  
- **SQLite**: Embedded database operations
- **DynamoDB**: AWS NoSQL operations

## Usage

### Basic Backend Creation

```rust
use dbx_adapter::{create_backend, BackendConfig, BackendType};

// Create Redis backend
let config = BackendConfig {
    backend_type: BackendType::Redis,
    redis_url: Some("redis://localhost:6379".to_string()),
    ..Default::default()
};

let backend = create_backend(&config).await?;

// Use backend through UniversalBackend trait
use dbx_core::{DataOperation, DataOperationType};

let operation = DataOperation {
    op_type: DataOperationType::Get,
    key: "test:key".to_string(),
    value: None,
    ttl: None,
};

let result = backend.execute_data(operation).await?;
```

### Backend Configuration

```rust
use dbx_adapter::BackendConfig;

let config = BackendConfig {
    backend_type: BackendType::Redis,
    redis_url: Some("redis://localhost:6379".to_string()),
    pool_size: 10,
    timeout: Duration::from_secs(5),
    retry_attempts: 3,
    ..Default::default()
};
```

### Multi-Backend Support

```rust
use dbx_adapter::{create_backend, BackendRegistry};

let mut registry = BackendRegistry::new();

// Register multiple backends
registry.register("redis", create_backend(&redis_config).await?);
registry.register("postgres", create_backend(&postgres_config).await?);

// Route operations based on requirements
let backend = registry.select_backend(&operation)?;
let result = backend.execute_data(operation).await?;
```

## Adding New Backends

### 1. Implement UniversalBackend Trait

```rust
use async_trait::async_trait;
use dbx_core::{UniversalBackend, DataOperation, DataResult, DbxError};

pub struct YourBackendAdapter {
    // Connection and configuration fields
}

#[async_trait]
impl UniversalBackend for YourBackendAdapter {
    async fn execute_data(&self, operation: DataOperation) -> Result<DataResult, DbxError> {
        match operation.op_type {
            DataOperationType::Get => self.get(&operation.key).await,
            DataOperationType::Set => self.set(&operation.key, &operation.value, operation.ttl).await,
            // Additional operations available
        }
    }
    
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            data_operations: vec![
                DataOperationType::Get,
                DataOperationType::Set,
                // Additional operations available
            ],
            // Additional capabilities available
        }
    }
}
```

### 2. Add to Backend Factory

```rust
// In src/lib.rs
pub async fn create_backend(config: &BackendConfig) -> Result<Box<dyn UniversalBackend>, AdapterError> {
    match config.backend_type {
        BackendType::Redis => {
            let adapter = redis::RedisAdapter::new(config).await?;
            Ok(Box::new(adapter))
        }
        BackendType::YourBackend => {
            let adapter = your_backend::YourBackendAdapter::new(config).await?;
            Ok(Box::new(adapter))
        }
        // ... other backends
    }
}
```

### 3. Update Configuration

```rust
// Add to BackendType enum
#[derive(Debug, Clone)]
pub enum BackendType {
    Redis,
    MongoDB,
    PostgreSQL,
    YourBackend,
}

// Add configuration fields
#[derive(Debug, Clone)]
pub struct BackendConfig {
    pub backend_type: BackendType,
    pub redis_url: Option<String>,
    pub mongo_url: Option<String>,
    pub your_backend_url: Option<String>,
    // ... other config fields
}
```

## Error Handling

### Error Types

The adapter layer maps backend-specific errors to standardized DBX errors:

```rust
use dbx_core::DbxError;

// Backend-specific error mapping
impl From<redis::RedisError> for DbxError {
    fn from(err: redis::RedisError) -> Self {
        match err.kind() {
            redis::ErrorKind::ConnectionRefused => DbxError::Connection("Redis connection failed".to_string()),
            redis::ErrorKind::AuthenticationFailed => DbxError::Authentication("Redis auth failed".to_string()),
            _ => DbxError::Backend(format!("Redis error: {}", err)),
        }
    }
}
```

### Retry Logic

```rust
use dbx_adapter::retry::{RetryPolicy, ExponentialBackoff};

let retry_policy = ExponentialBackoff::new()
    .max_attempts(3)
    .initial_delay(Duration::from_millis(100))
    .max_delay(Duration::from_secs(5));

let result = retry_policy.execute(|| {
    backend.execute_data(operation.clone())
}).await?;
```

## Testing

### Unit Tests

```bash
# Run all adapter tests
cargo test -p dbx-adapter

# Run backend-specific tests  
cargo test -p dbx-adapter redis::
cargo test -p dbx-adapter postgres::

# Run with test features
cargo test -p dbx-adapter --features test-utils
```

### Integration Tests

```bash
# Requires running databases
docker-compose up -d redis postgres mongo

# Run integration tests
cargo test -p dbx-adapter --test integration

# Test specific backend
cargo test -p dbx-adapter --test redis_integration
```

### Mock Testing

```rust
use dbx_adapter::testing::MockBackend;

#[tokio::test]
async fn test_backend_operations() {
    let mut mock = MockBackend::new();
    
    mock.expect_execute_data()
        .with(predicate::eq(operation))
        .returning(|_| Ok(expected_result));
    
    let result = mock.execute_data(operation).await?;
    assert_eq!(result, expected_result);
}
```

## Performance

### Connection Pooling

Each backend adapter implements efficient connection pooling:

```rust
use dbx_adapter::pool::{PoolConfig, ConnectionPool};

let pool_config = PoolConfig {
    max_size: 10,
    min_idle: 2,
    max_lifetime: Duration::from_secs(3600),
    connection_timeout: Duration::from_secs(30),
};

let pool = ConnectionPool::new(pool_config).await?;
```

### Batch Operations

```rust
use dbx_core::{BatchOperation, BatchResult};

// Efficient batch processing
let batch = BatchOperation {
    operations: vec![op1, op2, op3],
    transaction: false,
};

let results = backend.execute_batch(batch).await?;
```

## Configuration

### Environment Variables

```bash
# Redis configuration
REDIS_URL=redis://localhost:6379
REDIS_POOL_SIZE=10
REDIS_TIMEOUT=5000

# PostgreSQL configuration  
POSTGRES_URL=postgresql://localhost:5432/dbx
POSTGRES_POOL_SIZE=20
POSTGRES_SSL_MODE=require

# MongoDB configuration
MONGO_URL=mongodb://localhost:27017/dbx
MONGO_POOL_SIZE=5
MONGO_DATABASE=dbx
```

### Configuration File

```toml
[backends.redis]
url = "redis://localhost:6379"
pool_size = 10
timeout = 5000

[backends.postgresql]  
url = "postgresql://localhost:5432/dbx"
pool_size = 20
ssl_mode = "require"

[backends.mongodb]
url = "mongodb://localhost:27017/dbx"
pool_size = 5
database = "dbx"
```

## Contributing

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/new-backend`
3. **Implement your backend** following the patterns above
4. **Add comprehensive tests** for your implementation
5. **Update documentation** including this README
6. **Submit a pull request**

### Code Standards

- Follow Rust standard formatting (`cargo fmt`)
- Ensure all tests pass (`cargo test`)
- Add comprehensive error handling
- Include both unit and integration tests
- Document public APIs with rustdoc comments

## License

Licensed under MIT or Apache-2.0 license.
