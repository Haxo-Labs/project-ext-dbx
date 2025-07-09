# Publishing Guide

This guide covers the process of publishing new versions of DBX, including the Docker image and TypeScript SDK.

## Overview

DBX consists of multiple components that need to be published:

1. **Docker Image** - The main DBX database API server
2. **TypeScript SDK** - NAPI bindings for Node.js/TypeScript with multi-backend support
3. **GitHub Release** - Source code and binaries

## Prerequisites

### Required Accounts

- **Docker Hub**: [effortlesslabs/dbx](https://hub.docker.com/r/effortlesslabs/dbx)
- **NPM**: [dbx](https://www.npmjs.com/package/dbx)
- **GitHub**: [effortlesslabs/dbx](https://github.com/effortlesslabs/dbx)

### Required Tokens

```bash
# Docker Hub token
export DOCKER_TOKEN="your-docker-hub-token"

# NPM token
export NPM_TOKEN="your-npm-token"

# GitHub token (for releases)
export GITHUB_TOKEN="your-github-token"
```

## Version Management

### Version Format

DBX uses semantic versioning: `MAJOR.MINOR.PATCH`

- **MAJOR**: Breaking changes to UniversalBackend interface or API
- **MINOR**: New backend adapters, new features, backward compatible
- **PATCH**: Bug fixes, backend improvements, backward compatible

### Version Locations

```bash
# Main workspace version
Cargo.toml: [workspace.package].version = "1.0.0"

# TypeScript SDK version
bindings/dbx_ts/package.json: "version": "1.0.0"

# Docker image tags
effortlesslabs/dbx:1.0.0
effortlesslabs/dbx:latest
effortlesslabs/dbx:redis  # Backend-specific tags
```

## Publishing Process

### 1. Update Version

```bash
# Update version in Cargo.toml
sed -i 's/version = "0.9.0"/version = "1.0.0"/' Cargo.toml

# Update version in TypeScript package.json
sed -i 's/"version": "0.9.0"/"version": "1.0.0"/' bindings/dbx_ts/package.json

# Update version in Dockerfile
sed -i 's/LABEL version="0.9.0"/LABEL version="1.0.0"/' Dockerfile
```

### 2. Build and Test

```bash
# Build all components
cargo build --release

# Build TypeScript SDK
cd bindings/dbx_ts
npm run build
cd ../..

# Run comprehensive tests
cargo test
cd bindings/dbx_ts && npm test && cd ../..

# Test Docker build
docker build -t effortlesslabs/dbx:test .

# Test multi-backend support
BACKEND_TYPE=redis docker run -d effortlesslabs/dbx:test
```

### 3. Publish TypeScript SDK

```bash
# Navigate to TypeScript bindings
cd bindings/dbx_ts

# Login to NPM
npm login

# Publish package
npm publish

# Verify publication
npm view dbx version
```

### 4. Build and Push Docker Image

```bash
# Build multi-arch image
docker buildx build --platform linux/amd64,linux/arm64 \
  -t effortlesslabs/dbx:1.0.0 \
  -t effortlesslabs/dbx:latest \
  --push .

# Build backend-specific images
docker buildx build --platform linux/amd64,linux/arm64 \
  -t effortlesslabs/dbx:1.0.0-redis \
  -t effortlesslabs/dbx:redis \
  --build-arg DEFAULT_BACKEND=redis \
  --push .

# Build lightweight edge image
docker buildx build --platform linux/amd64 \
  -t effortlesslabs/dbx:1.0.0-edge \
  -t effortlesslabs/dbx:edge \
  --target runtime \
  --push .
```

### 5. Create GitHub Release

```bash
# Create git tag
git tag v1.0.0
git push origin v1.0.0

# Or use GitHub CLI
gh release create v1.0.0 \
  --title "DBX v1.0.0" \
  --notes "- Added backend-agnostic architecture
- Complete Redis adapter implementation
- Enhanced TypeScript SDK
- Multi-backend Docker images" \
  --draft
```

## Automated Publishing

### Using Scripts

DBX provides several publishing scripts:

```bash
# Interactive publishing
./scripts/quick-publish.sh

# Manual publishing with backend selection
./scripts/publish-release.sh --version 1.0.0 \
  --backends redis,mongo,postgres \
  --docker-username effortlesslabs \
  --docker-password $DOCKER_TOKEN \
  --npm-token $NPM_TOKEN

# Release script
./scripts/publish-universal.sh --version 1.0.0
```

### GitHub Actions

The easiest way to publish is using GitHub Actions:

1. **Create a git tag**: `git tag v1.0.0 && git push origin v1.0.0`
2. **Or manually trigger** the workflow from GitHub Actions with backend selection

## Publishing Scripts

### Quick Publish Script

```bash
#!/bin/bash
# scripts/quick-publish.sh

echo "DBX Database API Server - Quick Publish"
echo "======================================="

# Get current version
CURRENT_VERSION=$(grep 'version = ' Cargo.toml | cut -d'"' -f2)
echo "Current version: $CURRENT_VERSION"

# Prompt for new version
read -p "New version: " NEW_VERSION

# Prompt for backends to include
echo "Available backends: redis, mongo, postgres, sqlite"
read -p "Backends to publish (comma-separated): " BACKENDS

# Update versions
sed -i "s/version = \"$CURRENT_VERSION\"/version = \"$NEW_VERSION\"/" Cargo.toml
sed -i "s/\"version\": \"$CURRENT_VERSION\"/\"version\": \"$NEW_VERSION\"/" bindings/dbx_ts/package.json
sed -i "s/LABEL version=\"$CURRENT_VERSION\"/LABEL version=\"$NEW_VERSION\"/" Dockerfile

# Build and publish
./scripts/publish-release.sh --version $NEW_VERSION --backends $BACKENDS
```

### Release Script

```bash
#!/bin/bash
# scripts/publish-universal.sh

set -e

VERSION=""
BACKENDS="redis"  # Default to Redis for now
DOCKER_REPO="effortlesslabs/dbx"
NPM_PACKAGE="dbx"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --version)
      VERSION="$2"
      shift 2
      ;;
    --backends)
      BACKENDS="$2"
      shift 2
      ;;
    --docker-username)
      DOCKER_USERNAME="$2"
      shift 2
      ;;
    --docker-password)
      DOCKER_PASSWORD="$2"
      shift 2
      ;;
    --npm-token)
      NPM_TOKEN="$2"
      shift 2
      ;;
    *)
      echo "Unknown option $1"
      exit 1
      ;;
  esac
done

# Validate required parameters
if [[ -z "$VERSION" ]]; then
  echo "Error: --version is required"
  exit 1
fi

echo "Publishing DBX v$VERSION"
echo "Backends: $BACKENDS"

# Build and test
echo "Building and testing..."
cargo build --release
cargo test

# Build TypeScript SDK
echo "Building TypeScript SDK..."
cd bindings/dbx_ts
npm run build
npm test
cd ../..

# Publish NPM package
if [[ -n "$NPM_TOKEN" ]]; then
  echo "Publishing NPM package..."
  cd bindings/dbx_ts
  echo "//registry.npmjs.org/:_authToken=$NPM_TOKEN" > .npmrc
  npm publish
  rm .npmrc
  cd ../..
fi

# Build and push Docker images
if [[ -n "$DOCKER_PASSWORD" ]]; then
  echo "Building and pushing Docker images..."
  echo "$DOCKER_PASSWORD" | docker login -u "$DOCKER_USERNAME" --password-stdin
  
  # Main image
  docker buildx build --platform linux/amd64,linux/arm64 \
    -t $DOCKER_REPO:$VERSION \
    -t $DOCKER_REPO:latest \
    --push .
  
  # Backend-specific images
  IFS=',' read -ra BACKEND_ARRAY <<< "$BACKENDS"
  for backend in "${BACKEND_ARRAY[@]}"; do
    docker buildx build --platform linux/amd64,linux/arm64 \
      -t $DOCKER_REPO:$VERSION-$backend \
      -t $DOCKER_REPO:$backend \
      --build-arg DEFAULT_BACKEND=$backend \
      --push .
  done
fi

echo "Publishing complete!"
```

## Backend-Specific Publishing

### Redis Backend

```bash
# Publish Redis image
docker buildx build --platform linux/amd64,linux/arm64 \
  -t effortlesslabs/dbx:1.0.0-redis \
  -t effortlesslabs/dbx:redis \
  --build-arg DEFAULT_BACKEND=redis \
  --build-arg OPTIMIZE_FOR=redis \
  --push .
```

### Multi-Backend Image

```bash
# Publish image with all backends
docker buildx build --platform linux/amd64,linux/arm64 \
  -t effortlesslabs/dbx:1.0.0-all \
  -t effortlesslabs/dbx:all \
  --build-arg BACKENDS=redis,mongo,postgres,sqlite \
  --push .
```

## Testing Published Versions

### Docker Image Testing

```bash
# Test main image
docker run -d --name dbx-test effortlesslabs/dbx:latest
docker exec dbx-test curl -f http://localhost:3000/admin/health
docker rm -f dbx-test

# Test Redis backend
docker run -d --name dbx-redis-test \
  -e BACKEND_TYPE=redis \
  -e REDIS_URL=redis://redis:6379 \
  effortlesslabs/dbx:redis
```

### NPM Package Testing

```bash
# Test installation
npm install dbx

# Test basic functionality
node -e "
const { DbxClient } = require('dbx');
const client = new DbxClient('http://localhost:3000');
console.log('SDK imported successfully');
"
```

## Troubleshooting

### Common Issues

#### Docker Build Failures

```bash
# Check build context size
du -sh .dockerignore

# Build with verbose output
docker build --progress=plain --no-cache .

# Check platform support
docker buildx ls
```

#### NPM Publish Failures

```bash
# Check authentication
npm whoami

# Verify package.json
npm pack --dry-run

# Check for existing version
npm view dbx versions --json
```

#### Version Conflicts

```bash
# Check existing Docker tags
curl -s https://hub.docker.com/v2/repositories/effortlesslabs/dbx/tags/ | jq '.results[].name'

# Check existing NPM versions
npm view dbx versions --json
```

## Rollback Procedures

### Docker Image Rollback

```bash
# Retag previous version as latest
docker pull effortlesslabs/dbx:0.9.0
docker tag effortlesslabs/dbx:0.9.0 effortlesslabs/dbx:latest
docker push effortlesslabs/dbx:latest
```

### NPM Package Rollback

```bash
# Deprecate problematic version
npm deprecate dbx@1.0.0 "Version deprecated due to critical bug"

# Or unpublish (within 24 hours only)
npm unpublish dbx@1.0.0
```

## Release Notes Template

```markdown
# DBX v1.0.0

## New Features

- **Backend-Agnostic Architecture**: Complete UniversalBackend trait system
- **MongoDB Adapter**: Full MongoDB support with document operations
- **TypeScript SDK**: Client with capability detection
- **Multi-Backend Docker Images**: Images optimized for different backends

## Backend Support

- **Redis**: Complete implementation (strings, hashes, sets, sorted sets, bitmaps)
- **MongoDB**: Document CRUD, aggregation pipeline, change streams
- **PostgreSQL**: SQL operations, JSON support, transactions

## API Changes

- Added backend-agnostic endpoints: `/data/*`, `/query/*`, `/stream/*`
- Maintained backward compatibility with backend-specific endpoints
- Capability detection at `/admin/capabilities`

## Bug Fixes

- Fixed connection pooling issues across backends
- Error handling and error message consistency
- Resolved memory leaks in long-running connections

## Breaking Changes

- TypeScript SDK package name remains `dbx`
- Docker image name changed from `effortlesslabs/0dbx_redis` to `effortlesslabs/dbx`
- Configuration format updated for multi-backend support

## Migration Guide

See [MIGRATION.md](MIGRATION.md) for detailed migration instructions.
```
