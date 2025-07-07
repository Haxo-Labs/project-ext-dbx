# JWT Authentication System

The DBX Redis API implements a comprehensive JWT-based authentication system with role-based access control (RBAC) to secure all Redis operations.

## Overview

The authentication system provides stateless, scalable security using JSON Web Tokens (JWT) with configurable role-based permissions. All Redis endpoints require valid authentication tokens, and access is controlled based on user roles.

## Features

- **JWT-based authentication** with access and refresh tokens
- **Role-based access control** (Admin, User, ReadOnly)
- **Secure token generation** using HS256 algorithm
- **Token refresh mechanism** for seamless user experience
- **Production-ready security** with configurable JWT secrets
- **Comprehensive error handling** for authentication failures

## User Roles

### Admin

- Full access to all Redis operations
- Access to admin endpoints (`/redis/admin/*`)
- Can perform all user and readonly operations

### User  

- Access to standard Redis operations
- Can perform string, hash, and set operations
- Can access all readonly operations

### ReadOnly

- Basic authenticated access
- Future implementation for read-only Redis operations

## Configuration

### Environment Variables

Configure the JWT system using these environment variables:

```bash
# JWT Configuration
JWT_SECRET=dbx-jwt-secret
JWT_ACCESS_TOKEN_EXPIRATION=900     # 15 minutes  
JWT_REFRESH_TOKEN_EXPIRATION=604800 # 7 days
JWT_ISSUER=dbx-api
```

### Security Recommendations

1. **Generate a secure JWT secret** for production:

   ```bash
   openssl rand -base64 32
   ```

2. **Use environment variables** for all secrets
3. **Set appropriate token expiration** times
4. **Use HTTPS** in production

## Available Users

The system includes pre-configured demo users for development and testing:

| Username | Password | Role | Description |
|----------|----------|------|-------------|
| `admin` | `admin123` | Admin | Full access to all operations |
| `user` | `user123` | User | Access to standard operations |
| `readonly` | `readonly123` | ReadOnly | Basic authenticated access |

## API Reference

### Authentication Endpoints

#### POST /auth/login

Authenticates a user and returns access and refresh tokens.

**Request:**

```json
{
  "username": "admin",
  "password": "admin123"
}
```

**Response:**

```json
{
  "success": true,
  "data": {
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "token_type": "Bearer",
    "expires_in": 900,
    "user": {
      "id": "uuid-here",
      "username": "admin",
      "role": "Admin"
    }
  }
}
```

#### POST /auth/refresh

Refreshes an access token using a valid refresh token.

**Request:**

```json
{
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

**Response:** Returns the same structure as the login endpoint with new tokens.

#### POST /auth/logout

Invalidates the current session (client-side token removal).

**Response:**

```json
{
  "success": true,
  "data": "Successfully logged out"
}
```

#### GET /auth/validate

Validates the current access token and returns token information.

**Headers:**

```
Authorization: Bearer <access_token>
```

**Response:**

```json
{
  "success": true,
  "data": {
    "valid": true,
    "user": {
      "id": "uuid-here",
      "username": "admin",
      "role": "Admin"
    },
    "expires_at": "2024-01-01T12:00:00Z"
  }
}
```

#### GET /auth/me

Returns information about the currently authenticated user.

**Headers:**

```
Authorization: Bearer <access_token>
```

**Response:**

```json
{
  "success": true,
  "data": {
    "id": "uuid-here",
    "username": "admin",
    "role": "Admin"
  }
}
```

### Protected Redis Endpoints

All Redis endpoints require authentication with appropriate role permissions:

#### Admin Endpoints (Admin role required)

- `GET /redis/admin/ping` - Health check
- `GET /redis/admin/health` - Server health status
- `GET /redis/admin/info` - Redis server info
- `POST /redis/admin/flushdb` - Clear database
- WebSocket: `ws://host/redis_ws/admin/ws`

#### User Endpoints (User role or higher required)

- `POST /redis/string/{key}` - Set string value
- `GET /redis/string/{key}` - Get string value  
- `DELETE /redis/string/{key}` - Delete string
- `POST /redis/hash/{key}` - Hash operations
- `POST /redis/set/{key}` - Set operations
- WebSocket equivalents at `ws://host/redis_ws/*/ws`

## Usage Examples

### Basic Authentication Flow

```bash
# Authenticate user
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'

# Use returned access token for protected endpoints
curl -H "Authorization: Bearer <access_token>" \
  http://localhost:3000/redis/admin/ping
```

### JavaScript/Node.js Implementation

```javascript
// Authenticate
const loginResponse = await fetch('http://localhost:3000/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username: 'admin', password: 'admin123' })
});

const { data } = await loginResponse.json();
const accessToken = data.access_token;

// Access protected resources
const redisResponse = await fetch('http://localhost:3000/redis/admin/ping', {
  headers: { 'Authorization': `Bearer ${accessToken}` }
});
```

### Python Implementation

```python
import requests

# Authenticate
login_response = requests.post('http://localhost:3000/auth/login', json={
    'username': 'admin',
    'password': 'admin123'
})

access_token = login_response.json()['data']['access_token']

# Access protected resources
headers = {'Authorization': f'Bearer {access_token}'}
redis_response = requests.get('http://localhost:3000/redis/admin/ping', headers=headers)
```

### Token Refresh Implementation

```bash
# Refresh expired access token
curl -X POST http://localhost:3000/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "<refresh_token_from_login>"}'
```

## Error Handling

### Authentication Errors

```json
{
  "success": false,
  "error": "Invalid credentials"
}
```

### Authorization Errors

```json
{
  "success": false, 
  "error": "Admin role required"
}
```

### Token Errors

```json
{
  "success": false,
  "error": "Invalid or expired token"
}
```

## Security Architecture

### Token Management

- Access tokens have short expiration times (default: 15 minutes)
- Refresh tokens provide longer-lived session management (default: 7 days)
- Tokens use HS256 signing algorithm with configurable secrets

### Role-Based Access Control

- Middleware enforces role requirements at the route level
- Admin role provides unrestricted access
- User role allows standard operations
- ReadOnly role provides basic authenticated access

### Production Security

1. **Token Storage**: Implement secure client-side token storage
2. **HTTPS**: Enforce HTTPS connections in production
3. **Token Refresh**: Implement automatic token refresh logic
4. **Secret Management**: Use cryptographically secure JWT secrets
5. **Rate Limiting**: Consider implementing rate limiting for authentication endpoints
6. **Audit Logging**: Log authentication events for security monitoring

## Development vs Production

### Development Environment

- Demo users with simple passwords
- Basic JWT secret acceptable for local testing
- HTTP connections permitted for development

### Production Environment

- External user management system integration
- Cryptographically secure JWT secrets
- HTTPS-only connections
- Proper password hashing implementation
- Rate limiting and audit logging
- Consider external authentication providers (OAuth2, SAML)

## WebSocket Authentication

WebSocket connections require JWT authentication through connection headers or query parameters, depending on client implementation.

## Testing

Execute authentication tests:

```bash
cargo test routes::auth
```

The test suite covers:

- Successful authentication flows
- Invalid credential handling
- Token validation
- Role-based access control

## Troubleshooting

### Common Issues

**"Missing authorization token"**

- Verify `Authorization: Bearer <token>` header is present
- Check token format and encoding

**"Invalid or expired token"**

- Confirm access token has not exceeded expiration time
- Use refresh token to obtain new access token

**"Insufficient permissions"**

- Verify user role meets endpoint requirements
- Admin endpoints require Admin role
- User endpoints require User role or higher

**"Connection refused"**

- Ensure Redis server is running and accessible
- Verify Redis connection configuration

### Debug Mode

Enable debug logging for authentication troubleshooting:

```bash
RUST_LOG=debug cargo run
```

This provides detailed JWT validation and role verification information.
