# API Key Authentication System

The DBX API supports API key-based authentication as an alternative to JWT tokens, providing a convenient authentication mechanism for programmatic access and service-to-service communication.

## Overview

The API key authentication system provides:

- **Secure API key generation** with cryptographic randomness
- **Flexible authentication** via headers, query parameters, or Authorization header
- **Role-based permissions** (ReadOnly, ReadWrite, Admin)
- **Key management** including creation, rotation, and revocation
- **Usage tracking and analytics** for monitoring API key usage
- **Rate limiting** per API key
- **Expiration policies** for enhanced security

## Features

- **Multiple authentication methods** - API keys work alongside JWT authentication
- **Permission mapping** - API key permissions map to user roles (ReadOnly → ReadOnly, ReadWrite → User, Admin → Admin)
- **Secure storage** - API keys are hashed using SHA256 before storage
- **Key rotation** - Generate new keys while maintaining metadata
- **Usage analytics** - Track total requests, daily/hourly usage, and last usage time
- **Rate limiting** - Configure per-key request limits with time windows

## Authentication Methods

### 1. X-API-Key Header (Recommended)

```bash
curl -X GET "http://localhost:3000/api/v1/data/user:123" \
  -H "X-API-Key: dbx_1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
```

### 2. Authorization Header

```bash
curl -X GET "http://localhost:3000/api/v1/data/user:123" \
  -H "Authorization: ApiKey dbx_1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
```

### 3. Query Parameter

```bash
curl -X GET "http://localhost:3000/api/v1/data/user:123?api_key=dbx_1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
```

## API Key Management

All API key management operations require JWT authentication. API keys cannot be used to manage other API keys.

### Create API Key

**POST /api/v1/api-keys**

```bash
curl -X POST "http://localhost:3000/api/v1/api-keys" \
  -H "Authorization: Bearer <jwt_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production API Key",
    "description": "API key for production services",
    "permission": "ReadWrite",
    "expires_in_days": 90,
    "rate_limit_requests": 10000,
    "rate_limit_window_seconds": 3600
  }'
```

**Response:**

```json
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "Production API Key",
    "description": "API key for production services",
    "key_prefix": "dbx_abcd****",
    "permission": "ReadWrite",
    "created_at": "2024-01-15T10:30:00Z",
    "expires_at": "2024-04-15T10:30:00Z",
    "is_active": true,
    "usage_stats": {
      "total_requests": 0,
      "last_used_at": null,
      "requests_today": 0,
      "requests_this_hour": 0
    },
    "rate_limit_requests": 10000,
    "rate_limit_window_seconds": 3600,
    "key": "dbx_1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
  }
}
```

**Note:** The `key` field is only included in the creation response. Store this securely as it cannot be retrieved again.

### List API Keys

**GET /api/v1/api-keys**

```bash
curl -X GET "http://localhost:3000/api/v1/api-keys?limit=10&offset=0&active_only=true" \
  -H "Authorization: Bearer <jwt_token>"
```

**Response:**

```json
{
  "success": true,
  "data": {
    "keys": [
      {
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "name": "Production API Key",
        "description": "API key for production services",
        "key_prefix": "dbx_abcd****",
        "permission": "ReadWrite",
        "created_at": "2024-01-15T10:30:00Z",
        "expires_at": "2024-04-15T10:30:00Z",
        "is_active": true,
        "usage_stats": {
          "total_requests": 1542,
          "last_used_at": "2024-01-20T14:22:15Z",
          "requests_today": 87,
          "requests_this_hour": 12
        },
        "rate_limit_requests": 10000,
        "rate_limit_window_seconds": 3600
      }
    ],
    "total": 1,
    "limit": 10,
    "offset": 0
  }
}
```

### Get API Key Details

**GET /api/v1/api-keys/{id}**

```bash
curl -X GET "http://localhost:3000/api/v1/api-keys/550e8400-e29b-41d4-a716-446655440000" \
  -H "Authorization: Bearer <jwt_token>"
```

### Update API Key

**PUT /api/v1/api-keys/{id}**

```bash
curl -X PUT "http://localhost:3000/api/v1/api-keys/550e8400-e29b-41d4-a716-446655440000" \
  -H "Authorization: Bearer <jwt_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Updated Production API Key",
    "description": "Updated description",
    "is_active": true,
    "rate_limit_requests": 15000,
    "rate_limit_window_seconds": 3600
  }'
```

### Rotate API Key

**POST /api/v1/api-keys/{id}/rotate**

```bash
curl -X POST "http://localhost:3000/api/v1/api-keys/550e8400-e29b-41d4-a716-446655440000/rotate" \
  -H "Authorization: Bearer <jwt_token>"
```

**Response:**

```json
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "new_key": "dbx_fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321",
    "key_prefix": "dbx_fedc****",
    "rotated_at": "2024-01-20T15:45:30Z"
  }
}
```

### Delete API Key

**DELETE /api/v1/api-keys/{id}**

```bash
curl -X DELETE "http://localhost:3000/api/v1/api-keys/550e8400-e29b-41d4-a716-446655440000" \
  -H "Authorization: Bearer <jwt_token>"
```

## Permission Levels

### ReadOnly

- Access to read operations only
- Maps to `ReadOnly` user role
- Limited to GET requests on data endpoints

### ReadWrite  

- Access to read and write operations
- Maps to `User` user role
- Access to GET, POST, PUT, DELETE on data endpoints
- Cannot access admin endpoints

### Admin

- Full access to all operations
- Maps to `Admin` user role
- Access to all endpoints including admin operations

## Rate Limiting

API keys support per-key rate limiting:

```json
{
  "rate_limit_requests": 1000,
  "rate_limit_window_seconds": 3600
}
```

This allows 1000 requests per hour for this specific API key.

**Rate Limit Headers:**

- `X-RateLimit-Limit`: Maximum requests allowed in the time window
- `X-RateLimit-Remaining`: Remaining requests in current window
- `X-RateLimit-Reset`: Timestamp when the rate limit resets

## Usage Analytics

Each API key tracks detailed usage statistics:

- **Total Requests**: Lifetime request count
- **Last Used**: Timestamp of most recent request
- **Daily Requests**: Requests made today
- **Hourly Requests**: Requests made in the current hour

## Security Best Practices

### API Key Security

1. **Store keys securely** - Never expose API keys in client-side code
2. **Use HTTPS only** - Always transmit API keys over encrypted connections
3. **Rotate keys regularly** - Implement key rotation policies
4. **Monitor usage** - Set up alerts for unusual usage patterns
5. **Use least privilege** - Assign minimal necessary permissions

### Key Management

1. **Name keys descriptively** - Use clear names to identify key purposes
2. **Set expiration dates** - Implement reasonable expiration policies
3. **Deactivate unused keys** - Regularly audit and disable inactive keys
4. **Monitor rate limits** - Set appropriate rate limits for each use case

## Integration Examples

### Node.js

```javascript
const axios = require('axios');

const client = axios.create({
  baseURL: 'http://localhost:3000',
  headers: {
    'X-API-Key': 'dbx_your_api_key_here'
  }
});

// Get data
const response = await client.get('/api/v1/data/user:123');
console.log(response.data);

// Set data
await client.put('/api/v1/data/user:123', {
  name: 'John Doe',
  email: 'john@example.com'
});
```

### Python

```python
import requests

headers = {
    'X-API-Key': 'dbx_your_api_key_here',
    'Content-Type': 'application/json'
}

# Get data
response = requests.get(
    'http://localhost:3000/api/v1/data/user:123',
    headers=headers
)
data = response.json()

# Set data
requests.put(
    'http://localhost:3000/api/v1/data/user:123',
    headers=headers,
    json={'name': 'John Doe', 'email': 'john@example.com'}
)
```

### cURL

```bash
# Set data
curl -X PUT "http://localhost:3000/api/v1/data/user:123" \
  -H "X-API-Key: dbx_your_api_key_here" \
  -H "Content-Type: application/json" \
  -d '{"name": "John Doe", "email": "john@example.com"}'

# Get data  
curl -X GET "http://localhost:3000/api/v1/data/user:123" \
  -H "X-API-Key: dbx_your_api_key_here"
```

## Error Handling

### Authentication Errors

**401 Unauthorized - Missing API Key**

```json
{
  "success": false,
  "error": "Authentication required. Provide either a valid JWT token or API key."
}
```

**401 Unauthorized - Invalid API Key**

```json
{
  "success": false,
  "error": "Invalid API key"
}
```

**401 Unauthorized - Expired API Key**

```json
{
  "success": false,
  "error": "API key has expired"
}
```

**401 Unauthorized - Inactive API Key**

```json
{
  "success": false,
  "error": "API key is inactive"
}
```

### Rate Limiting Errors

**429 Too Many Requests**

```json
{
  "success": false,
  "error": "Rate limit exceeded"
}
```

### Permission Errors

**403 Forbidden**

```json
{
  "success": false,
  "error": "Admin role required"
}
```

## Configuration

API key behavior can be configured through environment variables:

```bash
# Default API key expiration (days)
API_KEY_DEFAULT_EXPIRATION=90

# Maximum API key lifetime (days)  
API_KEY_MAX_EXPIRATION=365

# Default rate limit (requests per hour)
API_KEY_DEFAULT_RATE_LIMIT=1000

# Enable API key analytics
API_KEY_ANALYTICS_ENABLED=true
```

## Authentication Strategy

API keys work alongside JWT tokens as part of the flexible authentication system:

1. **JWT Authentication**: Interactive user sessions and web applications
2. **API Key Authentication**: Service-to-service communication and programmatic access
3. **Flexible Middleware**: Automatically detects and validates both authentication methods

Both authentication methods use the same authorization middleware, ensuring consistent behavior across all endpoints.

## Troubleshooting

### Common Issues

**API Key Not Working**

- Verify key format (should start with `dbx_` and be 67 characters total)
- Check key is active and not expired
- Ensure proper header format (`X-API-Key: dbx_...`)

**Rate Limit Issues**

- Check current usage in API key details
- Verify rate limit configuration
- Consider increasing limits or implementing backoff

**Permission Denied**

- Verify API key permission level matches required access
- Check endpoint requires appropriate role (User vs Admin)
- Ensure API key hasn't been deactivated

### Monitoring

Enable logging to monitor API key usage:

```bash
# Enable API key request logging
API_KEY_LOG_REQUESTS=true

# Log level for API key operations
API_KEY_LOG_LEVEL=info
```

## Security Considerations

- API keys are hashed with SHA256 before storage
- Original keys cannot be retrieved after creation
- Rate limiting prevents abuse
- Usage tracking enables audit trails
- Expiration policies enforce key rotation
- Permission levels enforce least privilege access