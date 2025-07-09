# DBX Scripts

This directory contains various scripts for managing DBX development, testing, and deployment.

## Available Scripts

### Development Scripts

#### `run.sh`

Runs the DBX server locally with development settings.

```bash
./scripts/run.sh
```

**Features:**

- Starts Redis in background if not running
- Sets up development environment variables
- Runs DBX with hot reload enabled
- Includes debug logging

#### `config.sh`

Configuration script for setting up environment variables.

```bash
source ./scripts/config.sh
```

**Sets:**

- `REDIS_URL=redis://localhost:6379`
- `HOST=0.0.0.0`
- `PORT=3000`
- `LOG_LEVEL=DEBUG`

### Testing Scripts

#### `test-simple.sh`

Runs basic unit tests for all workspace members.

```bash
./scripts/test-simple.sh
```

**What it does:**

- Runs `cargo test` for all crates
- Includes both unit and integration tests
- Fast execution, no external dependencies

#### `test-with-server.sh`

Comprehensive testing with a running DBX server instance.

```bash
./scripts/test-with-server.sh
```

**Features:**

- Starts Redis and DBX server
- Runs API tests against live server
- Tests WebSocket connections
- Includes performance benchmarks
- Cleans up services after testing

#### `test-sequential.sh`

Runs tests in sequential order to avoid conflicts.

```bash
./scripts/test-sequential.sh
```

**Use cases:**

- When tests have shared resource conflicts
- For debugging test interactions
- CI/CD environments with limited resources

### Health Monitoring Scripts

#### `check-status.sh`

Comprehensive health check for all DBX components.

```bash
./scripts/check-status.sh
```

**Checks:**

- Redis connection and status
- DBX API server health endpoints
- WebSocket connection status
- Database operation functionality

Example output:

```
DBX System Status Check
======================
✓ Redis: Connected (localhost:6379)
✓ DBX API: Healthy (http://localhost:3000)
✓ WebSocket: Connected (ws://localhost:3000/data/ws)
✓ String Operations: Working
✓ Hash Operations: Working
✓ Set Operations: Working

Overall Status: HEALTHY
```

### Publishing Scripts

#### `publish.sh`

Main publishing script for releases.

```bash
./scripts/publish.sh --version 1.0.0 --docker-tag latest
```

**Options:**

- `--version`: Version number for the release
- `--docker-tag`: Docker tag (default: latest)
- `--npm-publish`: Also publish NPM package
- `--github-release`: Create GitHub release

#### `publish-docker.sh`

Docker-specific publishing script.

```bash
./scripts/publish-docker.sh --tag v1.0.0
```

**Features:**

- Builds multi-architecture Docker images
- Pushes to Docker Hub (`effortlesslabs/dbx`)
- Creates versioned and latest tags
- Includes health checks and metadata

#### `publish-npm.sh`

NPM package publishing script.

```bash
./scripts/publish-npm.sh --version 1.0.0
```

**Process:**

- Builds TypeScript bindings
- Runs tests to ensure functionality
- Publishes to NPM registry
- Updates version tags

#### `quick-publish.sh`

One-command publishing for rapid releases.

```bash
./scripts/quick-publish.sh
```

**Interactive process:**

1. Prompts for version number
2. Builds and tests all components
3. Publishes Docker image and NPM package
4. Creates git tags
5. Updates documentation

### Utility Scripts

#### `common.sh`

Shared utilities and functions used by other scripts.

**Functions:**

- `log_info()`: Colored info logging
- `log_error()`: Colored error logging
- `wait_for_service()`: Wait for service to be ready
- `cleanup()`: Clean up background processes
- `check_dependencies()`: Verify required tools

Usage in other scripts:

```bash
source ./scripts/common.sh

log_info "Starting deployment..."
wait_for_service "http://localhost:3000/admin/health" 30
```

## Script Configuration

### Environment Variables

Scripts use these environment variables (with defaults):

```bash
# Database Configuration
REDIS_URL=redis://localhost:6379
MONGO_URL=mongodb://localhost:27017/dbx
POSTGRES_URL=postgresql://localhost:5432/dbx

# Server Configuration
DBX_HOST=0.0.0.0
DBX_PORT=3000
LOG_LEVEL=INFO

# Docker Configuration
DOCKER_REGISTRY=effortlesslabs
DOCKER_IMAGE=dbx
DOCKER_TAG=latest

# NPM Configuration
NPM_PACKAGE=dbx
NPM_REGISTRY=https://registry.npmjs.org/

# GitHub Configuration
GITHUB_REPO=effortlesslabs/dbx
GITHUB_TOKEN=${GITHUB_TOKEN}
```

### Configuration Files

#### `.env.development`

Development environment configuration:

```bash
# Development settings
REDIS_URL=redis://localhost:6379
HOST=127.0.0.1
PORT=3000
LOG_LEVEL=DEBUG
RUST_LOG=dbx=debug

# Enable development features
AUTO_RELOAD=true
CORS_ORIGINS=*
```

#### `.env.production`

Production environment configuration:

```bash
# Production settings
REDIS_URL=redis://redis:6379
HOST=0.0.0.0
PORT=3000
LOG_LEVEL=WARN

# Security settings
CORS_ORIGINS=https://yourdomain.com
API_KEY_REQUIRED=true
```

## Usage Examples

### Development Workflow

```bash
# Start development environment
./scripts/run.sh

# In another terminal, run tests
./scripts/test-with-server.sh

# Check system status
./scripts/check-status.sh
```

### Testing Workflow

```bash
# Quick unit tests
./scripts/test-simple.sh

# Full integration tests
./scripts/test-with-server.sh

# Sequential tests (for CI)
./scripts/test-sequential.sh
```

### Release Workflow

```bash
# Quick release (interactive)
./scripts/quick-publish.sh

# Or manual release
./scripts/publish.sh --version 1.2.0 --docker-tag v1.2.0 --npm-publish --github-release

# Or individual components
./scripts/publish-docker.sh --tag v1.2.0
./scripts/publish-npm.sh --version 1.2.0
```

### Monitoring Workflow

```bash
# Regular health checks
./scripts/check-status.sh

# Continuous monitoring (every 30 seconds)
watch -n 30 ./scripts/check-status.sh
```

## CI/CD Integration

### GitHub Actions

Example workflow using these scripts:

```yaml
name: DBX CI/CD
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup Dependencies
        run: |
          source ./scripts/common.sh
          check_dependencies
      - name: Run Tests
        run: ./scripts/test-sequential.sh
      
  publish:
    if: github.ref == 'refs/heads/main'
    needs: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Publish Release
        env:
          DOCKER_TOKEN: ${{ secrets.DOCKER_TOKEN }}
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: ./scripts/publish.sh --version auto --docker-tag latest --npm-publish --github-release
```

### Docker Compose

Using scripts with Docker Compose:

```yaml
# docker-compose.dev.yml
version: "3.8"
services:
  dbx-dev:
    build: .
    command: ["./scripts/run.sh"]
    environment:
      - ENV=development
    volumes:
      - .:/app
      - ./scripts:/app/scripts
```

## Troubleshooting

### Common Issues

#### Permission Errors

```bash
# Make scripts executable
chmod +x ./scripts/*.sh
```

#### Service Connection Issues

```bash
# Check if Redis is running
./scripts/check-status.sh

# Start Redis manually
redis-server --daemonize yes
```

#### Docker Build Issues

```bash
# Clean Docker cache
docker system prune -a

# Rebuild without cache
./scripts/publish-docker.sh --no-cache
```

#### NPM Publishing Issues

```bash
# Login to NPM
npm login

# Check package status
npm view dbx

# Force publish (if needed)
./scripts/publish-npm.sh --force
```

### Log Files

Scripts create log files in `./logs/`:

- `development.log`: Development server logs
- `test.log`: Test execution logs
- `publish.log`: Publishing operation logs
- `health.log`: Health check results

### Debug Mode

Enable debug mode for detailed output:

```bash
export DBX_DEBUG=1
./scripts/run.sh
```

## Contributing

When adding new scripts:

1. Follow the existing naming convention
2. Include comprehensive error handling
3. Use functions from `common.sh`
4. Add documentation to this README
5. Include usage examples
6. Test on multiple platforms

### Script Template

```bash
#!/bin/bash

# Script description
# Usage: ./script-name.sh [options]

set -e  # Exit on error

# Source common functions
source "$(dirname "$0")/common.sh"

# Script-specific functions
function main() {
    log_info "Starting script..."
    
    # Implementation
    
    log_info "Script completed successfully"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --option)
            OPTION="$2"
            shift 2
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Run main function
main "$@"
```
