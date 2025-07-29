# DBX TypeScript SDK

High-performance TypeScript SDK for DBX Database API with native NAPI bindings.

## Features

- **Native Performance**: NAPI bindings for high-performance operations
- **Type Safety**: Full TypeScript types with IntelliSense support  
- **Modular Architecture**: Clean separation of concerns with dedicated modules
- **Authentication**: JWT and API key support with auto-refresh
- **Retry Logic**: Built-in retry with exponential backoff
- **Connection Pooling**: HTTP connection pooling for optimal performance
- **Batch Operations**: Efficient batch processing with validation
- **Query Operations**: Pattern and text search capabilities
- **Error Handling**: Comprehensive error types and recovery

## Installation

```bash
npm install @dbx/ts
```

## Quick Start

### Basic Configuration

```typescript
import { DbxClient, DbxConfig } from "@dbx/ts";

const config: DbxConfig = {
  baseUrl: "http://localhost:3000",
  username: "your-username",
  password: "your-password",
  timeoutMs: 30000,
  maxRetries: 3,
  retryDelayMs: 1000,
  poolSize: 10,
  autoRefreshToken: true,
  enableLogging: false
};

const client = new DbxClient(config);
```

### Authentication

```typescript
// Username/password authentication
await client.authenticate("username", "password");

// API key authentication (set in config)
const config: DbxConfig = {
  baseUrl: "http://localhost:3000",
  apiKey: "your-api-key-here"
};
const client = new DbxClient(config);

// Check authentication status
const isAuth = await client.isAuthenticated();
console.log("Authenticated:", isAuth);

// Validate current session
const isValid = await client.validateSession();

// Refresh token manually
await client.refreshAuthToken();

// Logout
await client.logout();
```

### Data Operations

```typescript
// Set data with optional TTL
await client.set("user:123", JSON.stringify({ name: "Alice", age: 30 }), 3600);

// Get data
const response = await client.get("user:123");
if (response.success && response.data) {
  const user = JSON.parse(response.data);
  console.log(user); // { name: "Alice", age: 30 }
}

// Update hash fields
const fields = JSON.stringify({ 
  email: "alice@example.com", 
  lastLogin: new Date().toISOString() 
});
await client.update("user:123", fields);

// Check if key exists
const existsResponse = await client.exists("user:123");
console.log("Exists:", existsResponse.data); // true/false

// Delete data
await client.delete("user:123");

// TTL operations
await client.setTtl("key", 3600); // Set TTL to 1 hour
const ttlResponse = await client.getTtl("key");
console.log("TTL:", ttlResponse.data); // remaining seconds

// Numeric operations
await client.set("counter", "0");
await client.increment("counter", 5); // increment by 5
await client.decrement("counter", 2); // decrement by 2

// String operations
await client.append("log", "New entry\n");
const lengthResponse = await client.length("log");
console.log("Length:", lengthResponse.data);

// Conditional operations
await client.setIfNotExists("unique:key", "value", 3600);
await client.compareAndSwap("key", "expected", "new-value");
```

### Batch Operations

```typescript
import { DbxBatchOperation } from "@dbx/ts";

// Mixed batch operations
const operations: DbxBatchOperation[] = [
  { operationType: "set", key: "user:1", value: JSON.stringify({ name: "Alice" }) },
  { operationType: "set", key: "user:2", value: JSON.stringify({ name: "Bob" }), ttl: 3600 },
  { operationType: "get", key: "user:3" },
  { operationType: "delete", key: "old:key" },
  { operationType: "exists", key: "check:key" }
];

const batchResponse = await client.batch(operations);
console.log("Batch results:", batchResponse.data);

// Specialized batch operations
await client.batchSet([
  ["key1", "value1", 3600],
  ["key2", "value2", null],
  ["key3", "value3", 7200]
]);

const values = await client.batchGet(["key1", "key2", "key3"]);
await client.batchDelete(["old1", "old2", "old3"]);
```

### Query Operations

```typescript
// Pattern search
const patternResults = await client.queryPattern("user:*", 100, 0);
console.log("Found keys:", patternResults.results.length);

patternResults.results.forEach(result => {
  console.log(`Key: ${result.key}, Data: ${result.data}`);
});

// Text search
const textResults = await client.queryText(
  "alice", 
  ["name", "email"], // search fields
  50,  // limit
  0    // offset
);

// Advanced pattern matching
const sessionKeys = await client.queryPattern("session:*:active");
const userProfiles = await client.queryPattern("profile:user:*", 200);
```

### Error Handling

```typescript
import { DbxClient } from "@dbx/ts";

try {
  const response = await client.get("nonexistent:key");
  if (!response.success) {
    console.error("Operation failed:", response.error);
  }
} catch (error) {
  // Network errors, timeouts, authentication failures, etc.
  console.error("Request failed:", error.message);
}

// Check response status
const response = await client.set("key", "value");
if (response.success) {
  console.log("Set successful, operation ID:", response.operationId);
  console.log("Execution time:", response.executionTimeMs, "ms");
  console.log("Backend:", response.backend);
} else {
  console.error("Set failed:", response.error);
}
```

### Health Monitoring

```typescript
// Check service health (no auth required)
const health = await client.health();
console.log("Service status:", health.data);

// Auto-refresh tokens when needed
await client.autoRefreshIfNeeded();

// Get current configuration
const currentConfig = client.getConfig();
console.log("Client config:", currentConfig);
```

## Configuration Options

### DbxConfig Interface

```typescript
interface DbxConfig {
  baseUrl: string;                    // DBX API base URL
  username?: string;                  // Authentication username
  password?: string;                  // Authentication password  
  apiKey?: string;                    // API key (alternative to username/password)
  timeoutMs?: number;                 // Request timeout (default: 30000)
  maxRetries?: number;                // Max retry attempts (default: 3)
  retryDelayMs?: number;              // Delay between retries (default: 1000)
  poolSize?: number;                  // Connection pool size (default: 10)
  autoRefreshToken?: boolean;         // Auto-refresh JWT tokens (default: true)
  enableLogging?: boolean;            // Enable request logging (default: false)
}
```

### Environment Variables

Create a `.env` file:

```bash
# API Configuration
DBX_BASE_URL=http://localhost:3000
DBX_USERNAME=your-username
DBX_PASSWORD=your-password
DBX_API_KEY=your-api-key

# Client Configuration
DBX_CLIENT_TIMEOUT=30000
DBX_CLIENT_RETRIES=3
DBX_CLIENT_RETRY_DELAY=1000
DBX_CLIENT_POOL_SIZE=10
DBX_CLIENT_AUTO_REFRESH=true
DBX_CLIENT_LOGGING=false

# JWT Configuration
JWT_SECRET=your-jwt-secret
JWT_EXPIRATION_SECONDS=900
JWT_AUDIENCE=dbx-users

# Testing
TEST_BASE_URL=http://localhost:3000
TEST_USERNAME=testuser
TEST_PASSWORD=testpassword123
```

Load from environment:

```typescript
const config: DbxConfig = {
  baseUrl: process.env.DBX_BASE_URL || "http://localhost:3000",
  username: process.env.DBX_USERNAME,
  password: process.env.DBX_PASSWORD,
  apiKey: process.env.DBX_API_KEY,
  timeoutMs: parseInt(process.env.DBX_CLIENT_TIMEOUT || "30000"),
  maxRetries: parseInt(process.env.DBX_CLIENT_RETRIES || "3"),
  retryDelayMs: parseInt(process.env.DBX_CLIENT_RETRY_DELAY || "1000"),
  poolSize: parseInt(process.env.DBX_CLIENT_POOL_SIZE || "10"),
  autoRefreshToken: process.env.DBX_CLIENT_AUTO_REFRESH !== "false",
  enableLogging: process.env.DBX_CLIENT_LOGGING === "true"
};
```

## Response Types

### DbxResponse

```typescript
interface DbxResponse {
  success: boolean;           // Operation success status
  data?: string;             // Response data (JSON string)
  error?: string;            // Error message if failed
  operationId?: string;      // Unique operation identifier
  executionTimeMs?: number;  // Execution time in milliseconds
  backend?: string;          // Backend that handled the request
  metadata?: string;         // Additional metadata
}
```

### DbxQueryResponse

```typescript
interface DbxQueryResponse {
  success: boolean;
  queryId: string;
  results: DbxQueryResult[];
  totalCount?: number;
  executionTimeMs?: number;
  backend?: string;
  error?: string;
}

interface DbxQueryResult {
  key: string;
  data: string;              // JSON string
  score?: number;            // Relevance score for text search
}
```

## Performance Tips

### Connection Pooling

The SDK automatically manages HTTP connections with pooling:

```typescript
const config: DbxConfig = {
  baseUrl: "http://localhost:3000",
  poolSize: 20,              // Increase for high-throughput applications
  timeoutMs: 10000,          // Shorter timeout for faster failure detection
  maxRetries: 5,             // More retries for unreliable networks
  retryDelayMs: 500          // Faster retry for low-latency requirements
};
```

### Batch Operations

Use batch operations for multiple keys:

```typescript
// Instead of multiple individual calls
// DON'T DO THIS:
// await client.set("key1", "value1");
// await client.set("key2", "value2");
// await client.set("key3", "value3");

// DO THIS:
await client.batchSet([
  ["key1", "value1"],
  ["key2", "value2"], 
  ["key3", "value3"]
]);
```

### Token Management

Enable auto-refresh to avoid authentication interruptions:

```typescript
const config: DbxConfig = {
  baseUrl: "http://localhost:3000",
  username: "user",
  password: "pass",
  autoRefreshToken: true     // Automatically refresh expiring tokens
};

// Or manually manage tokens
await client.authenticate("user", "pass");
setInterval(async () => {
  if (await client.validateSession()) {
    await client.refreshAuthToken();
  }
}, 300000); // Refresh every 5 minutes
```

## Testing

### Unit Tests

```typescript
import { DbxClient, DbxConfig } from "@dbx/ts";

describe("DbxClient", () => {
  let client: DbxClient;
  
  beforeEach(() => {
    const config: DbxConfig = {
      baseUrl: "http://localhost:3000",
      username: "testuser",
      password: "testpass"
    };
    client = new DbxClient(config);
  });
  
  it("should authenticate and set data", async () => {
    await client.authenticate("testuser", "testpass");
    
    const setResponse = await client.set("test:key", "test value");
    expect(setResponse.success).toBe(true);
    
    const getResponse = await client.get("test:key");
    expect(getResponse.success).toBe(true);
    expect(getResponse.data).toBe("test value");
  });
});
```

### Integration Tests

```typescript
import { DbxClient } from "@dbx/ts";

describe("Integration Tests", () => {
  it("should handle concurrent operations", async () => {
    const client = new DbxClient({
      baseUrl: "http://localhost:3000",
      apiKey: "test-api-key",
      poolSize: 20
    });
    
    // Test concurrent operations
    const promises = Array.from({ length: 100 }, (_, i) =>
      client.set(`concurrent:${i}`, `value-${i}`)
    );
    
    const results = await Promise.all(promises);
    results.forEach(result => {
      expect(result.success).toBe(true);
    });
  });
});
```

## Migration Guide

### From Direct HTTP Calls

```typescript
// Old: Direct HTTP requests
const response = await fetch("http://localhost:3000/api/v1/data/key", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ value: "data" })
});

// New: SDK with type safety and error handling
const client = new DbxClient({ baseUrl: "http://localhost:3000" });
await client.authenticate("user", "pass");
const response = await client.set("key", "data");
```

### From Other Redis Clients

```typescript
// Old: Redis-specific client
import Redis from "ioredis";
const redis = new Redis("redis://localhost:6379");
await redis.set("key", "value");

// New: DBX SDK (backend-agnostic)
import { DbxClient } from "@dbx/ts";
const client = new DbxClient({ 
  baseUrl: "http://localhost:3000",
  apiKey: "your-key"
});
await client.set("key", "value");
```

## Contributing

1. Clone the repository
2. Install dependencies: `npm install`
3. Build the native module: `npm run build`  
4. Run tests: `npm test`

