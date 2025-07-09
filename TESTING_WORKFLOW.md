# DBX Testing Workflow

This document explains the comprehensive testing workflow for DBX Universal Database API Server that ensures all crate tests run against properly configured backend adapters with correct environment variables.

## Overview

The testing workflow addresses the requirement that all crate tests need to run against actual database backends through the DBX Universal API server. This ensures that:

1. **Server is running** - Tests run against an actual DBX API server with backend adapters
2. **Backend configuration** - All required backend environment variables are properly configured
3. **Dependencies are met** - Database backends are available and server is healthy
4. **Tests are sequential** - Tests run in the correct dependency order (core → adapter → api → client)

## New Files

### Scripts

- **`scripts/test-with-server.sh`** - Complete test runner with server and backend setup
- **`scripts/test-simple.sh`** - Simple test runner for existing server
- **`scripts/test-backends.sh`** - Backend-specific testing script

### Workflows

- **`.github/workflows/crates-tests.yml`** - Updated workflow using multi-backend testing
- **`.github/workflows/backend-tests.yml`** - Backend-specific test workflows

## Usage

### Local Development

#### Option 1: Complete Setup (Recommended)

```bash
# Run tests with automatic server and backend setup
./scripts/test-with-server.sh

# Test specific backend
./scripts/test-with-server.sh --backend redis --redis-url redis://localhost:6379

# Test multiple backends
./scripts/test-with-server.sh --backends redis,mongo --mongo-url mongodb://localhost:27017

# Keep server running for debugging
./scripts/test-with-server.sh --skip-cleanup
```

#### Option 2: Manual Server + Simple Tests

```bash
# Start backend (Redis example)
docker run -d --name test-redis -p 6379:6379 redis:7-alpine

# Start DBX server manually
BACKEND_TYPE=redis REDIS_URL=redis://localhost:6379 cargo run -p dbx-api --release &
SERVER_PID=$!

# Wait for server
sleep 5

# Run tests
./scripts/test-simple.sh

# Stop server
kill $SERVER_PID
docker stop test-redis
```

#### Option 3: Existing Server

```bash
# If you have a server running elsewhere
./scripts/test-simple.sh --server-url http://localhost:3000 --backend redis --redis-url redis://localhost:6379
```

### CI/CD Pipeline

The GitHub Actions workflows automatically:

1. **Set up Backend Services** - Uses GitHub Actions services for Redis, MongoDB, PostgreSQL
2. **Create Environment** - Generates `.env` file with backend configuration
3. **Start DBX Server** - Builds and starts DBX API server with specified backend
4. **Run Tests** - Executes all crate tests against the running server with backend
5. **Clean up** - Stops server and cleans up resources

## Configuration

### Environment Variables

The scripts automatically set these environment variables for tests:

```bash
# Server configuration
DBX_BASE_URL=http://localhost:3000
DBX_WS_HOST_URL=ws://localhost:3000/ws

# Backend selection
BACKEND_TYPE=redis  # or mongo, postgres, sqlite

# Backend-specific URLs
REDIS_URL=redis://localhost:6379
MONGO_URL=mongodb://localhost:27017/test
POSTGRES_URL=postgresql://localhost:5432/test
SQLITE_PATH=./test.db

# Optional server settings
HOST=0.0.0.0
PORT=3000
POOL_SIZE=10
LOG_LEVEL=INFO
```

### Backend Configuration Files

Create backend-specific `.env` files:

#### Redis Backend (`.env.redis`)
```bash
BACKEND_TYPE=redis
REDIS_URL=redis://localhost:6379
POOL_SIZE=10
```

#### MongoDB Backend (`.env.mongo`)
```bash
BACKEND_TYPE=mongo
MONGO_URL=mongodb://localhost:27017/dbx_test
MONGO_DATABASE=dbx_test
POOL_SIZE=5
```

#### PostgreSQL Backend (`.env.postgres`)
```bash
BACKEND_TYPE=postgres
POSTGRES_URL=postgresql://localhost:5432/dbx_test
POSTGRES_DATABASE=dbx_test
POOL_SIZE=8
```

## Test Execution Order

All tests run in this sequential order to respect dependencies:

1. **Core tests** (`crates/dbx-core`) - Universal backend trait system
2. **Adapter tests** (`crates/dbx-adapter`) - Generic adapter interfaces
3. **Backend-specific tests** (`crates/adapter/src/redis`, `crates/adapter/src/mongo`) - Specific implementations
4. **API tests** (`crates/dbx-api`) - HTTP/WebSocket server with backends
5. **Client tests** (`crates/dbx-client`) - Client libraries against live server

## Script Options

### test-with-server.sh

```bash
--backend <type>        # Backend type (redis, mongo, postgres, sqlite)
--backends <list>       # Comma-separated list of backends to test
--env-file <path>       # Path to .env file (default: .env)
--redis-url <url>       # Redis connection URL
--mongo-url <url>       # MongoDB connection URL
--postgres-url <url>    # PostgreSQL connection URL
--sqlite-path <path>    # SQLite database file path
--server-port <port>    # Server port (default: 3000)
--skip-server           # Skip starting server (assume it's already running)
--skip-cleanup          # Don't stop server after tests
--skip-backend-setup    # Don't start backend services
--verbose               # Enable verbose output
--help                  # Show help message
```

### test-simple.sh

```bash
--backend <type>        # Backend type being tested
--server-url <url>      # Server base URL (default: http://localhost:3000)
--redis-url <url>       # Redis connection URL (if using Redis)
--mongo-url <url>       # MongoDB connection URL (if using MongoDB)
--postgres-url <url>    # PostgreSQL connection URL (if using PostgreSQL)
--verbose               # Enable verbose output
--help                  # Show help message
```

### test-backends.sh

```bash
--backends <list>       # Backends to test (default: redis)
--parallel              # Run backend tests in parallel
--sequential            # Run backend tests sequentially
--stop-on-failure       # Stop on first backend test failure
--verbose               # Enable verbose output
--help                  # Show help message
```

## Backend-Specific Testing

### Redis Backend Testing

```bash
# Test Redis backend specifically
./scripts/test-with-server.sh --backend redis --redis-url redis://localhost:6379

# Test Redis with different configurations
./scripts/test-with-server.sh --backend redis --env-file .env.redis
```

### MongoDB Backend Testing

```bash
# Test MongoDB backend
./scripts/test-with-server.sh --backend mongo --mongo-url mongodb://localhost:27017/test

# Test with replica set
./scripts/test-with-server.sh --backend mongo --mongo-url mongodb://localhost:27017,localhost:27018,localhost:27019/test?replicaSet=rs0
```

### Multi-Backend Testing

```bash
# Test multiple backends sequentially
./scripts/test-backends.sh --backends redis,mongo,postgres --sequential

# Test all available backends
./scripts/test-backends.sh --backends all
```

## Troubleshooting

### Common Issues

#### Server Not Starting

```bash
# Check if port is in use
lsof -i :3000

# Check server logs
docker logs dbx-test-server

# Try different port
./scripts/test-with-server.sh --server-port 3001
```

#### Backend Connection Issues

```bash
# Redis: Check if Redis is running
docker ps | grep redis
redis-cli ping

# MongoDB: Check MongoDB connection
docker ps | grep mongo
mongosh --eval "db.admin.Command('ismaster')"

# PostgreSQL: Check PostgreSQL connection
docker ps | grep postgres
psql -h localhost -p 5432 -U postgres -c "SELECT 1"
```

#### Test Failures

```bash
# Run with verbose output
./scripts/test-with-server.sh --verbose

# Check server health for specific backend
curl http://localhost:3000/admin/health
curl http://localhost:3000/admin/capabilities

# Run individual test suites
cd crates/dbx-core && cargo test
cd ../dbx-adapter && cargo test
cd ../adapter && cargo test --test redis_integration
```

#### Backend-Specific Issues

```bash
# Redis connection timeout
REDIS_TIMEOUT=10 ./scripts/test-with-server.sh --backend redis

# MongoDB authentication
MONGO_URL=mongodb://user:pass@localhost:27017/test ./scripts/test-with-server.sh --backend mongo

# PostgreSQL SSL issues
POSTGRES_URL=postgresql://localhost:5432/test?sslmode=disable ./scripts/test-with-server.sh --backend postgres
```

### Debug Mode

Enable debug output to see all commands:

```bash
# Set debug environment variable
DEBUG=true ./scripts/test-with-server.sh

# Or use verbose mode with backend details
./scripts/test-with-server.sh --verbose --backend redis
```

### Docker-based Backend Testing

```bash
# Test with Docker Compose backends
docker-compose -f docker-compose.test.yml up -d
./scripts/test-simple.sh --backends redis,mongo,postgres
docker-compose -f docker-compose.test.yml down
```

## GitHub Actions Integration

### Multi-Backend Testing

```yaml
name: Multi-Backend Tests

on: [push, pull_request]

jobs:
  test-backends:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        backend: [redis, mongo, postgres]
    
    services:
      redis:
        image: redis:7-alpine
        ports:
          - 6379:6379
      
      mongodb:
        image: mongo:6
        ports:
          - 27017:27017
      
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: test
        ports:
          - 5432:5432

    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
          
      - name: Run Backend Tests
        run: |
          ./scripts/test-with-server.sh --backend ${{ matrix.backend }}
        env:
          REDIS_URL: redis://localhost:6379
          MONGO_URL: mongodb://localhost:27017/test
          POSTGRES_URL: postgresql://postgres:postgres@localhost:5432/test
```

## Performance Testing

### Backend Performance Tests

```bash
# Test backend performance
./scripts/test-performance.sh --backend redis --duration 60s --connections 100

# Compare backend performance
./scripts/test-performance.sh --backends redis,mongo --compare
```

### Load Testing

```bash
# Load test specific backend
wrk -t12 -c400 -d30s http://localhost:3000/data/test-key

# Backend-specific load testing
wrk -t12 -c400 -d30s http://localhost:3000/redis/string/test-key
```
