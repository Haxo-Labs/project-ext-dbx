#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"
source "$SCRIPT_DIR/config.sh"

DEFAULT_PORT=3000
DEFAULT_POOL_SIZE=10
DEFAULT_LOG_LEVEL=INFO
DEFAULT_BACKEND_TYPE=redis

usage() {
	echo "Usage: $0 [OPTIONS]"
	echo "Options:"
	echo "  --backend-url <url>       Backend URL (required)"
	echo "  --backend-type <type>     Backend type (default: redis)"
	echo "  --port <port>             Port (default: 3000)"
	echo "  --pool-size <size>        Pool size (default: 10)"
	echo "  --log-level <level>       Log level (default: INFO)"
	echo "  --help                    Show this help"
	exit 1
}

BACKEND_URL=""
BACKEND_TYPE="$DEFAULT_BACKEND_TYPE"
PORT="$DEFAULT_PORT"
POOL_SIZE="$DEFAULT_POOL_SIZE"
LOG_LEVEL="$DEFAULT_LOG_LEVEL"

while [[ $# -gt 0 ]]; do
	case $1 in
	--backend-url)
		BACKEND_URL="$2"
		shift 2
		;;
	--backend-type)
		BACKEND_TYPE="$2"
		shift 2
		;;
	--port)
		PORT="$2"
		shift 2
		;;
	--pool-size)
		POOL_SIZE="$2"
		shift 2
		;;
	--log-level)
		LOG_LEVEL="$2"
		shift 2
		;;
	--help)
		usage
		;;
	*)
		echo "Unknown option: $1"
		usage
		;;
	esac
done

if [ -z "$BACKEND_URL" ]; then
	echo "Error: --backend-url is required"
	usage
fi

IMAGE_NAME="dbx-api:local"

echo "Starting DBX API with configuration:"
echo "  Image: $IMAGE_NAME (building from local Dockerfile)"
echo "  Backend Type: $BACKEND_TYPE"
echo "  Backend URL: $BACKEND_URL"
echo "  Host: 0.0.0.0"
echo "  Port: $PORT"
echo "  Pool Size: $POOL_SIZE"
echo "  Log Level: $LOG_LEVEL"

echo "Building Docker image..."
docker build -t "$IMAGE_NAME" .

# Stop and remove existing container if it exists
docker stop dbx-api 2>/dev/null || true
docker rm dbx-api 2>/dev/null || true

# Create a Docker network if it doesn't exist
docker network create dbx-network 2>/dev/null || true

# Check if Redis is running and start it if needed
if ! docker ps --format "table {{.Names}}" | grep -q "redis-dbx"; then
	echo "Starting Redis container..."
	docker run -d \
		--name redis-dbx \
		--network dbx-network \
		-p 6379:6379 \
		redis:7-alpine \
		redis-server --appendonly yes

	echo "Waiting for Redis to be ready..."
	for i in {1..30}; do
		if docker exec redis-dbx redis-cli ping >/dev/null 2>&1; then
			echo "Redis is ready"
			break
		fi
		if [ $i -eq 30 ]; then
			echo "Redis failed to start within 30 seconds"
			exit 1
		fi
		sleep 1
	done
else
	echo "Redis container already running"
fi

# Update the backend URL to use the container name
if [[ $BACKEND_URL == *"localhost"* ]]; then
	BACKEND_URL="${BACKEND_URL/localhost/redis-dbx}"
	echo "Updated Backend URL for container networking: $BACKEND_URL"
fi

# Run the container with proper DBX environment variables
docker run -d \
	--name dbx-api \
	--network dbx-network \
	-p "$PORT:3000" \
	-e DBX_BACKEND_1_PROVIDER="$BACKEND_TYPE" \
	-e DBX_BACKEND_1_URL="$BACKEND_URL" \
	-e DBX_BACKEND_1_NAME=default \
	-e DBX_DEFAULT_BACKEND=default \
	-e DBX_HOST=0.0.0.0 \
	-e DBX_PORT=3000 \
	-e DBX_WORKERS=4 \
	-e DBX_WEBSOCKET_ENABLED=true \
	-e DBX_AUTH_REQUIRED=true \
	-e DBX_TLS_ENABLED=false \
	-e DBX_CACHE_ENABLED=true \
	-e DBX_METRICS_ENABLED=true \
	-e POOL_SIZE="$POOL_SIZE" \
	-e LOG_LEVEL="$LOG_LEVEL" \
	-e RUST_LOG="$LOG_LEVEL" \
	-e RUST_BACKTRACE=0 \
	-e JWT_SECRET=your_jwt_secret_key_change_in_production \
	-e JWT_EXPIRATION_SECONDS=900 \
	-e JWT_AUDIENCE=dbx-users \
	-e KEY_PREFIX=dbx:rate_limit \
	-e HOST_VALIDATION_ENABLED=true \
	-e STRICT_PORT_VALIDATION=true \
	-e ALLOWED_PORTS=80,443,3000,8080 \
	-e CREATE_DEFAULT_ADMIN=true \
	-e DEFAULT_ADMIN_USERNAME=testadmin \
	-e DEFAULT_ADMIN_PASSWORD=password \
	"$IMAGE_NAME"

echo "DBX API is starting up..."
echo "Check logs with: docker logs -f dbx-api"
echo "Stop with: docker stop dbx-api && docker rm dbx-api"
echo "Available endpoints:"
echo "  HTTP API: http://0.0.0.0:$PORT"
echo "  Health check: http://0.0.0.0:$PORT/health"
echo "  API documentation: http://0.0.0.0:$PORT/api/v1"
echo "API Endpoints:"
echo "  Authentication: http://0.0.0.0:$PORT/api/v1/auth/*"
echo "  Data operations: http://0.0.0.0:$PORT/api/v1/data/*"
echo "  Query operations: http://0.0.0.0:$PORT/api/v1/query/*"
echo "  Admin operations: http://0.0.0.0:$PORT/api/v1/admin/*"
echo "WebSocket Endpoints:"
echo "  Data streams: ws://0.0.0.0:$PORT/api/v1/stream/*"
echo "  Admin streams: ws://0.0.0.0:$PORT/api/v1/admin/stream/*"
echo "Backend Configuration:"
echo "  Provider: $BACKEND_TYPE"
echo "  URL: $BACKEND_URL"
echo "  Default Backend: default"
