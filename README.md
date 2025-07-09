# DBX - Backend-Agnostic Database API Server

<div align="center">

<a href="https://hub.docker.com/r/effortlesslabs/dbx">
<picture>
<source media="(prefers-color-scheme: dark)" srcset="https://img.shields.io/docker/v/effortlesslabs/dbx?colorA=21262d&colorB=21262d&style=flat">
<img src="https://img.shields.io/docker/v/effortlesslabs/dbx?colorA=f6f8fa&colorB=f6f8fa&style=flat" alt="Docker Version">
</picture>
</a>

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://github.com/effortlesslabs/dbx/actions/workflows/rust.yml/badge.svg)](https://github.com/effortlesslabs/dbx/actions/workflows/rust.yml)

**A high-performance, backend-agnostic database API server with TypeScript SDK and WebSocket support**

</div>

DBX is a minimal and portable HTTP/WebSocket proxy that exposes databases through a unified API layer. Built in Rust with a pluggable backend adapter system, DBX supports multiple database types through a standardized `UniversalBackend` interface. Optimized for edge runtimes like Cloudflare Workers, Raspberry Pi, and RISC-V boards. It enables fast, standardized access to databases using REST and WebSocket, with language bindings and pluggable backend support. Perfect for lightweight clients, embedded apps, and serverless environments.

## Architecture

DBX uses a modular, backend-agnostic architecture built around core abstractions:

### Core Components

- **dbx-core** - Backend traits and operation types (`DataOperation`, `QueryOperation`, `StreamOperation`)
- **dbx-adapter** - Database-specific implementations of the `UniversalBackend` trait
- **dbx-config** - Configuration management and backend detection
- **dbx-router** - HTTP/WebSocket routing with backend abstraction
- **Language Bindings** - Type-safe SDKs for various languages

### UniversalBackend Trait

All database adapters implement a consistent interface:

```rust
#[async_trait]
pub trait UniversalBackend: Send + Sync {
    async fn execute_data(&self, operation: DataOperation) -> Result<DataResult, DbxError>;
    async fn execute_query(&self, operation: QueryOperation) -> Result<QueryResult, DbxError>;
    async fn execute_stream(&self, operation: StreamOperation) -> Result<StreamResult, DbxError>;
    async fn health_check(&self) -> Result<BackendHealth, DbxError>;
    fn capabilities(&self) -> BackendCapabilities;
}
```

### Backend Capabilities

Each backend declares its capabilities, allowing the API layer to adapt:

```rust
pub struct BackendCapabilities {
    pub data_operations: Vec<DataOperationType>,
    pub query_capabilities: QueryCapabilities,
    pub stream_capabilities: StreamCapabilities,
    pub transaction_support: TransactionSupport,
    pub features: Vec<BackendFeature>,
}
```

## Supported Backends

### Currently Available

- **Redis Adapter** - Complete implementation with strings, hashes, sets, sorted sets, bitmaps, and admin operations

### Planned Backends

- **MongoDB** - Document-based operations with collections and aggregations
- **PostgreSQL** - Relational database with SQL query support
- **SQLite** - Embedded database for local storage
- **DynamoDB** - AWS NoSQL database adapter
- **Cassandra** - Wide-column store support

## Quick Start

### Using Docker

```bash
# Pull the latest image
docker pull effortlesslabs/dbx:latest

# Run with Redis backend
docker run -p 3000:3000 -e BACKEND_TYPE=redis -e REDIS_URL=redis://your-redis-server:6379 effortlesslabs/dbx:latest

# Run with auto-discovery
docker run -p 3000:3000 effortlesslabs/dbx:latest
```

### Using Docker Compose

```yaml
version: "3.8"
services:
  dbx:
    image: effortlesslabs/dbx:latest
    ports:
      - "3000:3000"
    environment:
      - BACKEND_TYPE=redis
      - REDIS_URL=redis://redis:6379
    depends_on:
      - redis

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
```

### Using Binary

```bash
# Clone the repository
git clone https://github.com/effortlesslabs/dbx.git
cd dbx

# Build the project
cargo build --release

# Run with Redis backend
BACKEND_TYPE=redis REDIS_URL=redis://localhost:6379 ./target/release/dbx

# Run with auto-detection
./target/release/dbx
```

## Features

- **Backend-Agnostic Design**: Pluggable adapter system for multiple database types
- **Unified Operations**: Standardized data, query, and stream operations across backends
- **Capability Detection**: Runtime detection and adaptation to backend capabilities
- **HTTP REST API**: RESTful endpoints that adapt to backend capabilities
- **WebSocket Support**: Real-time operations via WebSocket connections
- **TypeScript SDK**: Full client library with type safety via NAPI bindings
- **High Performance**: Built in Rust for maximum efficiency
- **Lightweight**: Minimal footprint, perfect for edge computing
- **Extensible**: Easy to add new database backends
- **Batch Operations**: Efficient batch processing for multiple operations
- **Docker Support**: Easy deployment with Docker and Docker Compose

## Configuration

### Backend Configuration

DBX supports multiple configuration methods:

#### Environment Variables

```bash
# Backend type (auto-detected if not specified)
BACKEND_TYPE=redis

# Backend-specific URLs
REDIS_URL=redis://localhost:6379
MONGO_URL=mongodb://localhost:27017/dbx
POSTGRES_URL=postgresql://localhost:5432/dbx

# Server configuration
PORT=3000
HOST=0.0.0.0
LOG_LEVEL=INFO
```

#### Configuration File

```toml
# dbx.toml
[server]
port = 3000
host = "0.0.0.0"
log_level = "INFO"

[backends.redis]
url = "redis://localhost:6379"
pool_size = 10

[backends.mongodb]
url = "mongodb://localhost:27017/dbx"
pool_size = 5
```

## API Endpoints

### Backend-Agnostic Endpoints

DBX provides backend-agnostic endpoints that adapt to the underlying database:

```
GET    /data/{key}              - Get data by key
POST   /data/{key}              - Set data by key
DELETE /data/{key}              - Delete data by key
POST   /query                   - Execute query operation
POST   /stream                  - Stream operation
GET    /admin/health            - Health check
GET    /admin/capabilities      - Backend capabilities
```

### Backend-Specific Endpoints

For backends that support specific operations:

```
# Redis-specific (when Redis backend is active)
GET    /redis/string/{key}      - Redis string operations
POST   /redis/hash/{key}        - Redis hash operations
GET    /redis/set/{key}         - Redis set operations

# Future: MongoDB-specific
POST   /mongo/collection/{name} - MongoDB collection operations
POST   /mongo/aggregate         - MongoDB aggregation pipeline
```

### WebSocket API

```
ws://localhost:3000/data/ws     - Data operations
ws://localhost:3000/query/ws    - Query operations
ws://localhost:3000/stream/ws   - Stream operations
```

## TypeScript SDK

```bash
npm install dbx
```

```typescript
import { DbxClient } from "dbx";

// Create client with auto-detection
const client = new DbxClient("http://localhost:3000");

// Data operations
await client.data.set("user:1", { name: "Alice", age: 30 });
const user = await client.data.get("user:1");

// Query operations
const results = await client.query.execute({
  type: "filter",
  collection: "users",
  filter: { age: { $gte: 18 } }
});

// Backend-specific operations (when available)
if (client.capabilities.supports("redis_strings")) {
  await client.redis.string.set("key", "value", 3600);
}

// WebSocket client
import { DbxWsClient } from "dbx";
const wsClient = new DbxWsClient("ws://localhost:3000/data/ws");
await wsClient.data.set("realtime:key", "value");
```

## Development

### Building from Source

```bash
git clone https://github.com/effortlesslabs/dbx.git
cd dbx

# Build all components
cargo build --release

# Build TypeScript SDK
cd bindings/dbx_ts
npm install && npm run build
cd ../..

# Run tests
cargo test
```

### Adding New Backends

1. **Implement UniversalBackend trait**:

```rust
// crates/adapter/src/your_backend/mod.rs
use dbx_core::{UniversalBackend, DataOperation, DataResult, DbxError};

pub struct YourBackendAdapter {
    // Connection details
}

#[async_trait]
impl UniversalBackend for YourBackendAdapter {
    async fn execute_data(&self, operation: DataOperation) -> Result<DataResult, DbxError> {
        match operation {
            DataOperation::Get { key } => {
                // Your implementation
            }
            DataOperation::Set { key, value, ttl } => {
                // Your implementation
            }
            // Additional operations available
        }
    }
    
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            data_operations: vec![DataOperationType::Get, DataOperationType::Set],
            // Additional capabilities available
        }
    }
}
```

2. **Register in adapter factory**:

```rust
// crates/adapter/src/lib.rs
pub async fn create_backend(config: &BackendConfig) -> Result<Box<dyn UniversalBackend>, AdapterError> {
    match config.backend_type {
        BackendType::Redis => Ok(Box::new(redis::RedisAdapter::new(config).await?)),
        BackendType::YourBackend => Ok(Box::new(your_backend::YourBackendAdapter::new(config).await?)),
    }
}
```

3. **Update configuration and routing as needed**

## Use Cases

- **Edge Computing**: Deploy on Cloudflare Workers, Vercel Edge Functions with any backend
- **IoT Devices**: Raspberry Pi, Arduino, RISC-V boards with local or remote databases
- **Serverless**: AWS Lambda, Google Cloud Functions with managed databases
- **Embedded Systems**: Resource-constrained environments with SQLite or local storage
- **Microservices**: Lightweight database access layer that can switch backends
- **Multi-Database Applications**: Single API for different database types in complex systems
- **Database Migration**: Seamless migration between database types without API changes

## Docker Images

DBX provides Docker images for multiple architectures:

- **Latest**: `effortlesslabs/dbx:latest`
- **Versioned**: `effortlesslabs/dbx:1.0.0`
- **Backend-specific**: `effortlesslabs/dbx:redis`, `effortlesslabs/dbx:mongo`

## Links

- **Documentation**: [https://dbx.effortlesslabs.com](https://dbx.effortlesslabs.com/)
- **Docker Hub**: [https://hub.docker.com/r/effortlesslabs/dbx](https://hub.docker.com/r/effortlesslabs/dbx)
- **NPM Package**: [https://www.npmjs.com/package/dbx](https://www.npmjs.com/package/dbx)
- **GitHub**: [https://github.com/effortlesslabs/dbx](https://github.com/effortlesslabs/dbx)

## Publishing

To publish new versions of DBX (Docker image and TypeScript SDK), see our comprehensive [Publishing Guide](PUBLISHING.md).

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## License

<sup>
Licensed under <a href="LICENSE">MIT license</a>.
</sup>

<br>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in these packages by you, as defined in the MIT license, shall be
licensed as above, without any additional terms or conditions.
</sub>
