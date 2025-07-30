#!/bin/bash

# Script to check the current status of DBX project
# Shows versions, publishing status, and available commands

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}INFO: $1${NC}"
}

log_success() {
    echo -e "${GREEN}SUCCESS: $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}WARNING: $1${NC}"
}

log_error() {
	echo -e "${RED}❌ $1${NC}"
}

# Header
echo "DBX Project Status Check"
echo "========================"
echo ""

# Check current versions
log_info "Current Versions:"

# Workspace version
WORKSPACE_VERSION=$(grep '^version = ' Cargo.toml | cut -d'"' -f2)
echo "   • Workspace (Cargo.toml): $WORKSPACE_VERSION"

# Get TypeScript version
TS_VERSION=$(grep '"version"' bindings/redis_ts/package.json | cut -d'"' -f4)
echo "   • TypeScript SDK: $TS_VERSION"

# Dockerfile version
DOCKER_VERSION=$(grep 'LABEL version=' Dockerfile | cut -d'"' -f2)
echo "   • Dockerfile: $DOCKER_VERSION"

echo ""

# Check version consistency
if [ "$WORKSPACE_VERSION" = "$TS_VERSION" ] && [ "$WORKSPACE_VERSION" = "$DOCKER_VERSION" ]; then
	log_success "All versions are consistent"
else
	log_warning "Version mismatch detected!"
	echo "   Please ensure all versions are the same before publishing"
fi

echo ""

# Check Docker Hub status
log_info "Docker Hub Status:"
DOCKER_USERNAME="effortlesslabs"
DOCKER_REPO="dbx"

# Check if docker is available
if command -v docker &>/dev/null; then
	echo "   • Docker: Available"

	# Check if image exists locally
	if docker images | grep -q "$DOCKER_USERNAME/$DOCKER_REPO"; then
		echo "   • Local image: Available"
		docker images | grep "$DOCKER_USERNAME/$DOCKER_REPO" | head -1
	else
		echo "   • Local image: Not found"
	fi
else
	echo "   • Docker: Not available"
fi

echo "   • Registry: https://hub.docker.com/r/$DOCKER_USERNAME/$DOCKER_REPO"

echo ""

# Check NPM status
log_info "NPM Status:"
echo "   • Package: @dbx/ts"
echo "   • Registry: https://www.npmjs.com/package/@dbx/ts"

# Check if npm is available
if command -v npm &>/dev/null; then
	echo "   • NPM: Available"

	# Check if package is installed locally
	if [ -d "bindings/redis_ts/node_modules" ]; then
		echo "   • Local package: Installed"
	else
		echo "   • Local package: Not installed"
	fi
else
	echo "   • NPM: Not available"
fi

echo ""

# Check git status
log_info "Git Status:"
if [ -d ".git" ]; then
	echo "   • Repository: Initialized"

	# Check current branch
	BRANCH=$(git branch --show-current 2>/dev/null || echo "unknown")
	echo "   • Current branch: $BRANCH"

	# Check for uncommitted changes
	if [ -n "$(git status --porcelain)" ]; then
		log_warning "   • Uncommitted changes detected"
	else
		log_success "   • Working directory clean"
	fi

	# Check for unpushed commits
	if [ -n "$(git log --branches --not --remotes)" ]; then
		log_warning "   • Unpushed commits detected"
	else
		log_success "   • All commits pushed"
	fi
else
	echo "   • Repository: Not initialized"
fi

echo ""

# Check build status
log_info "Build Status:"

# Check Rust build
if [ -d "target" ]; then
	echo "   • Rust build: Available"
else
	echo "   • Rust build: Not built"
fi

# Check TypeScript dependencies
if [ -d "bindings/redis_ts/node_modules" ]; then
	echo "   INSTALLED: TypeScript dependencies"
else
	echo "   ❌ TypeScript dependencies missing"
	echo "      Run: cd bindings/redis_ts && npm install"
fi

# Check TypeScript build
if [ -d "bindings/redis_ts/dist" ]; then
	echo "   EXISTS: TypeScript build"
else
	echo "   ❌ TypeScript build missing"
	echo "      Run: cd bindings/redis_ts && npm run build"
fi

echo ""

# Check test status
log_info "Test Status:"
echo "   • Rust tests (sequential): adapter → api → client"
echo "   • TypeScript tests: cd bindings/redis_ts && npm test"

echo ""

# Available commands
log_info "Available Commands:"

echo "📦 Publishing:"
echo "   • Quick publish: ./scripts/quick-publish.sh"
echo "   • Manual publish: ./scripts/publish-release.sh --version <version>"
echo "   • Docker only: ./scripts/publish.sh --tag <tag> --push"

echo ""
echo "Development:"
echo "   • Build Rust: cargo build --release"
echo "   • Build TypeScript: cd bindings/redis_ts && npm run build"
echo "   • Run tests (sequential): cd crates/adapter && cargo test && cd ../redis_api && cargo test && cd ../redis_client && cargo test"
echo "   • Run TypeScript tests: cd bindings/redis_ts && npm test"
echo "   • Run locally: cargo run --bin api"

echo ""
echo "🐳 Docker:"
echo "   • Build image: docker build -t effortlesslabs/dbx ."
echo "   • Run container: docker run -p 3000:3000 effortlesslabs/dbx"
echo "   • Multi-platform: ./scripts/publish.sh --tag <tag> --push"

echo ""
echo "📚 Documentation:"
echo "   • API docs: docs/pages/docs/api/"
echo "   • TypeScript bindings: bindings/redis_ts/README.md"
echo "   • Rust client: crates/redis_client/README.md"

echo ""
log_info "Next Steps:"
echo "1. Ensure all versions are consistent"
echo "2. Run tests (sequential): cd crates/adapter && cargo test && cd ../redis_api && cargo test && cd ../redis_client && cargo test"
echo "3. Run TypeScript tests: cd bindings/redis_ts && npm test"
echo "4. Choose publishing method:"
echo "   • GitHub Actions (recommended): Create git tag"
echo "   • Quick publish: ./scripts/quick-publish.sh"
echo "   • Manual: ./scripts/publish-release.sh"
