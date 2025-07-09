# DBX TypeScript SDK

Backend-agnostic TypeScript SDK for DBX Database API Server with NAPI bindings.

## Features

- **Backend-Agnostic**: Works with Redis, MongoDB, PostgreSQL, SQLite, and more
- **Type Safety**: Full TypeScript types with IntelliSense support
- **Capability Detection**: Runtime detection of backend capabilities
- **HTTP Client**: RESTful API client with connection pooling
- **WebSocket Support**: Real-time operations via WebSocket
- **NAPI Bindings**: High-performance native bindings for core operations
- **Backend-Specific Clients**: Optional typed access to backend features

## Installation

```bash
npm install dbx
```

## Quick Start

### Basic Usage

```typescript
import { DbxClient } from "dbx";

// Create client
const client = new DbxClient("http://localhost:3000");

// Data operations
await client.data.set("user:1", { name: "Alice", age: 30 });
const user = await client.data.get("user:1");
console.log(user); // { name: "Alice", age: 30 }

// Delete data
await client.data.delete("user:1");
```

### Backend Capability Detection

```typescript
import { DbxClient } from "dbx";

const client = new DbxClient("http://localhost:3000");

// Check capabilities
const capabilities = await client.capabilities();
console.log(capabilities);

// Use capabilities to adapt behavior
if (capabilities.supports("redis_strings")) {
  await client.redis.string.set("key", "value", 3600);
}

if (capabilities.supports("mongodb_documents")) {
  await client.mongo.collection("users").insert({ name: "Bob" });
}
```

### WebSocket Client

```typescript
import { DbxWsClient } from "dbx";

const wsClient = new DbxWsClient("ws://localhost:3000/data/ws");

// Set up event handlers
wsClient.on("connected", () => {
  console.log("Connected to DBX WebSocket");
});

wsClient.on("data", (data) => {
  console.log("Received data:", data);
});

// Perform operations
await wsClient.data.set("realtime:key", "value");
const value = await wsClient.data.get("realtime:key");
```

## API Reference

### DbxClient

The main client for HTTP operations.

#### Constructor

```typescript
new DbxClient(baseUrl: string, options?: ClientOptions)
```

- `baseUrl`: DBX server URL (e.g., `http://localhost:3000`)
- `options`: Optional configuration

```typescript
interface ClientOptions {
  timeout?: number;           // Request timeout in ms (default: 30000)
  retries?: number;          // Number of retries (default: 3)
  retryDelay?: number;       // Delay between retries in ms (default: 1000)
  headers?: Record<string, string>; // Custom headers
  auth?: {
    apiKey?: string;         // API key authentication
    bearer?: string;         // Bearer token authentication
  };
}
```

#### Data Operations

```typescript
// Get data by key
await client.data.get(key: string): Promise<any>

// Set data by key
await client.data.set(key: string, value: any, ttl?: number): Promise<void>

// Delete data by key
await client.data.delete(key: string): Promise<void>

// Check if key exists
await client.data.exists(key: string): Promise<boolean>

// Get multiple keys
await client.data.getMany(keys: string[]): Promise<any[]>

// Set multiple key-value pairs
await client.data.setMany(data: Record<string, any>): Promise<void>
```

#### Query Operations

```typescript
interface QueryOperation {
  type: "filter" | "search" | "aggregate" | "sql";
  collection?: string;
  table?: string;
  filter?: any;
  query?: string;
  pipeline?: any[];
  limit?: number;
  offset?: number;
}

// Execute query
await client.query.execute(operation: QueryOperation): Promise<any>

// Execute raw query
await client.query.raw(query: string, params?: any[]): Promise<any>
```

#### Stream Operations

```typescript
interface StreamOperation {
  type: "subscribe" | "unsubscribe" | "publish";
  channel: string;
  data?: any;
}

// Execute stream operation
await client.stream.execute(operation: StreamOperation): Promise<any>

// Subscribe to events
await client.stream.subscribe(channel: string, callback: (data: any) => void): Promise<void>

// Publish data
await client.stream.publish(channel: string, data: any): Promise<void>
```

#### Backend-Specific Clients

When the backend supports specific operations, you can access them directly:

```typescript
// Redis operations (when Redis backend is active)
await client.redis.string.get("key");
await client.redis.string.set("key", "value", 3600);
await client.redis.hash.set("hash", "field", "value");
await client.redis.set.add("set", "member");

// MongoDB operations (when MongoDB backend is active)
await client.mongo.collection("users").find({ age: { $gte: 18 } });
await client.mongo.collection("users").insert({ name: "Charlie", age: 25 });

// PostgreSQL operations (when PostgreSQL backend is active)
await client.postgres.query("SELECT * FROM users WHERE age >= $1", [18]);
await client.postgres.table("users").insert({ name: "David", age: 30 });
```

### DbxWsClient

WebSocket client for real-time operations.

#### Constructor

```typescript
new DbxWsClient(url: string, options?: WsClientOptions)
```

```typescript
interface WsClientOptions {
  reconnect?: boolean;        // Auto-reconnect (default: true)
  reconnectDelay?: number;    // Reconnect delay in ms (default: 1000)
  maxReconnects?: number;     // Max reconnect attempts (default: 5)
  heartbeat?: boolean;        // Enable heartbeat (default: true)
  heartbeatInterval?: number; // Heartbeat interval in ms (default: 30000)
}
```

#### Events

```typescript
wsClient.on("connected", () => void);
wsClient.on("disconnected", () => void);
wsClient.on("error", (error: Error) => void);
wsClient.on("data", (data: any) => void);
wsClient.on("reconnecting", (attempt: number) => void);
```

#### Methods

```typescript
// Connect
await wsClient.connect(): Promise<void>

// Disconnect
await wsClient.disconnect(): Promise<void>

// Check connection status
wsClient.isConnected(): boolean

// Send data operation
await wsClient.data.set(key: string, value: any): Promise<void>
await wsClient.data.get(key: string): Promise<any>

// Send query operation
await wsClient.query.execute(operation: QueryOperation): Promise<any>

// Send stream operation
await wsClient.stream.execute(operation: StreamOperation): Promise<any>
```

## Configuration

### Environment Variables

```bash
# Default DBX server URL
DBX_URL=http://localhost:3000

# API authentication
DBX_API_KEY=your-api-key

# Client timeouts
DBX_TIMEOUT=30000
DBX_RETRIES=3
```

### Configuration File

Create a `dbx-client.json` file:

```json
{
  "baseUrl": "http://localhost:3000",
  "timeout": 30000,
  "retries": 3,
  "auth": {
    "apiKey": "your-api-key"
  },
  "headers": {
    "User-Agent": "MyApp/1.0.0"
  }
}
```

Load configuration:

```typescript
import { loadConfig } from "dbx";

const config = loadConfig("./dbx-client.json");
const client = new DbxClient(config.baseUrl, config);
```

## Error Handling

### Error Types

```typescript
import { DbxError, DbxConnectionError, DbxTimeoutError } from "dbx";

try {
  await client.data.get("nonexistent");
} catch (error) {
  if (error instanceof DbxConnectionError) {
    console.error("Connection failed:", error.message);
  } else if (error instanceof DbxTimeoutError) {
    console.error("Request timed out:", error.message);
  } else if (error instanceof DbxError) {
    console.error("DBX error:", error.code, error.message);
  }
}
```

### Error Codes

| Code | Description |
|------|-------------|
| `E_CONNECTION` | Connection failed |
| `E_TIMEOUT` | Request timed out |
| `E_NOT_FOUND` | Key not found |
| `E_INVALID_DATA` | Invalid data format |
| `E_BACKEND_ERROR` | Backend-specific error |
| `E_CAPABILITY_NOT_SUPPORTED` | Operation not supported by backend |

### Retry Configuration

```typescript
const client = new DbxClient("http://localhost:3000", {
  retries: 5,
  retryDelay: 2000,
  retryCondition: (error) => {
    // Retry on connection errors and timeouts
    return error instanceof DbxConnectionError || 
           error instanceof DbxTimeoutError;
  }
});
```

## Backend Examples

### Redis Backend

```typescript
import { DbxClient } from "dbx";

const client = new DbxClient("http://localhost:3000");

// Check if Redis backend is available
if (await client.capabilities().supports("redis_strings")) {
  // String operations
  await client.redis.string.set("user:123", "Alice", 3600);
  const user = await client.redis.string.get("user:123");
  
  // Hash operations
  await client.redis.hash.set("profile:123", "name", "Alice");
  await client.redis.hash.set("profile:123", "age", "30");
  const profile = await client.redis.hash.getAll("profile:123");
  
  // Set operations
  await client.redis.set.add("active_users", "123");
  const isActive = await client.redis.set.isMember("active_users", "123");
  
  // Sorted set operations
  await client.redis.zset.add("leaderboard", "Alice", 100);
  const topUsers = await client.redis.zset.range("leaderboard", 0, 9);
}
```

### MongoDB Backend

```typescript
import { DbxClient } from "dbx";

const client = new DbxClient("http://localhost:3000");

if (await client.capabilities().supports("mongodb_documents")) {
  // Collection operations
  const users = client.mongo.collection("users");
  
  // Insert document
  const result = await users.insert({
    name: "Alice",
    email: "alice@example.com",
    age: 30
  });
  
  // Find documents
  const adults = await users.find({ age: { $gte: 18 } });
  
  // Update document
  await users.update(
    { name: "Alice" },
    { $set: { age: 31 } }
  );
  
  // Aggregation
  const ageGroups = await users.aggregate([
    { $group: { _id: "$age", count: { $sum: 1 } } },
    { $sort: { _id: 1 } }
  ]);
}
```

### PostgreSQL Backend

```typescript
import { DbxClient } from "dbx";

const client = new DbxClient("http://localhost:3000");

if (await client.capabilities().supports("postgresql_sql")) {
  // SQL queries
  const users = await client.postgres.query(
    "SELECT * FROM users WHERE age >= $1",
    [18]
  );
  
  // Table operations
  const usersTable = client.postgres.table("users");
  
  // Insert
  await usersTable.insert({
    name: "Alice",
    email: "alice@example.com",
    age: 30
  });
  
  // Select with conditions
  const adults = await usersTable.select()
    .where("age", ">=", 18)
    .orderBy("name")
    .limit(10);
  
  // Update
  await usersTable.update({ age: 31 })
    .where("name", "=", "Alice");
}
```

## Testing

### Unit Tests

```typescript
import { DbxClient } from "dbx";
import { expect } from "chai";

describe("DbxClient", () => {
  let client: DbxClient;
  
  beforeEach(() => {
    client = new DbxClient("http://localhost:3000");
  });
  
  it("should set and get data", async () => {
    await client.data.set("test:key", "test value");
    const value = await client.data.get("test:key");
    expect(value).to.equal("test value");
  });
  
  it("should handle non-existent keys", async () => {
    const value = await client.data.get("nonexistent");
    expect(value).to.be.null;
  });
});
```

### Integration Tests

```typescript
import { DbxClient, DbxWsClient } from "dbx";

describe("Integration Tests", () => {
  it("should work with WebSocket client", async () => {
    const httpClient = new DbxClient("http://localhost:3000");
    const wsClient = new DbxWsClient("ws://localhost:3000/data/ws");
    
    await wsClient.connect();
    
    // Set via HTTP
    await httpClient.data.set("ws:test", "hello");
    
    // Get via WebSocket
    const value = await wsClient.data.get("ws:test");
    expect(value).to.equal("hello");
    
    await wsClient.disconnect();
  });
});
```

## Performance

### Connection Pooling

```typescript
const client = new DbxClient("http://localhost:3000", {
  pool: {
    maxConnections: 10,
    maxIdleTime: 30000,
    keepAlive: true
  }
});
```

### Batch Operations

```typescript
// Batch set operations
await client.data.setMany({
  "user:1": { name: "Alice" },
  "user:2": { name: "Bob" },
  "user:3": { name: "Charlie" }
});

// Batch get operations
const users = await client.data.getMany(["user:1", "user:2", "user:3"]);
```

### Caching

```typescript
import { DbxClient, CacheConfig } from "dbx";

const client = new DbxClient("http://localhost:3000", {
  cache: {
    enabled: true,
    ttl: 60000,        // 1 minute
    maxSize: 1000,     // Max 1000 cached items
    strategy: "lru"    // Least recently used
  }
});
```

## Migration Guide

### From @0dbx/redis to dbx

1. **Update package name**:

   ```bash
   npm uninstall @0dbx/redis
   npm install dbx
   ```

2. **Update imports**:

   ```typescript
   // Old
   import { RedisClient } from "@0dbx/redis";
   
   // New
   import { DbxClient } from "dbx";
   ```

3. **Update client creation**:

   ```typescript
   // Old
   const client = new RedisClient("http://localhost:3000");
   
   // New
   const client = new DbxClient("http://localhost:3000");
   ```

4. **Update operations**:

   ```typescript
   // Old - Direct Redis operations
   await client.string.set("key", "value");
   
   // New - Backend-agnostic operations
   await client.data.set("key", "value");
   
   // Or Redis-specific operations (when available)
   if (client.capabilities.supports("redis_strings")) {
     await client.redis.string.set("key", "value");
   }
   ```

## Contributing

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for development setup and contribution guidelines.

## License

MIT License - see [LICENSE](../../LICENSE) for details.
