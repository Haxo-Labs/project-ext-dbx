use axum::{
    body::Body,
    http::{header, HeaderValue, Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::str::FromStr;
use tower_http::cors::{Any, CorsLayer};

use crate::config::{CorsConfig, SecurityConfig, SecurityHeadersConfig};

/// Security headers middleware that adds comprehensive security headers to all responses
pub async fn security_headers_middleware(
    security_config: SecurityConfig,
    request: Request<Body>,
    next: Next,
) -> impl IntoResponse {
    let mut response = next.run(request).await;

    let headers = response.headers_mut();

    // Add X-Content-Type-Options
    if let Ok(value) = HeaderValue::from_str(&security_config.headers.x_content_type_options) {
        headers.insert("x-content-type-options", value);
    }

    // Add X-Frame-Options
    if let Ok(value) = HeaderValue::from_str(&security_config.headers.x_frame_options) {
        headers.insert("x-frame-options", value);
    }

    // Add X-XSS-Protection
    if let Ok(value) = HeaderValue::from_str(&security_config.headers.x_xss_protection) {
        headers.insert("x-xss-protection", value);
    }

    // Add Strict-Transport-Security (HTTPS only in production)
    if security_config.strict_transport_security_enabled && !security_config.development_mode {
        if let Some(hsts_value) = &security_config.headers.strict_transport_security {
            if let Ok(value) = HeaderValue::from_str(hsts_value) {
                headers.insert("strict-transport-security", value);
            }
        }
    }

    // Add Referrer-Policy
    if let Ok(value) = HeaderValue::from_str(&security_config.headers.referrer_policy) {
        headers.insert("referrer-policy", value);
    }

    // Add Content-Security-Policy
    if let Ok(value) = HeaderValue::from_str(&security_config.headers.content_security_policy) {
        headers.insert("content-security-policy", value);
    }

    // Add Permissions-Policy
    if let Some(permissions_policy) = &security_config.headers.permissions_policy {
        if let Ok(value) = HeaderValue::from_str(permissions_policy) {
            headers.insert("permissions-policy", value);
        }
    }

    // Add security-specific headers for API responses
    if let Ok(value) = HeaderValue::from_str("no-cache, no-store, must-revalidate") {
        headers.insert("cache-control", value);
    }

    if let Ok(value) = HeaderValue::from_str("no-cache") {
        headers.insert("pragma", value);
    }

    response
}

/// Create a configured CORS layer based on security configuration
pub fn create_cors_layer(cors_config: &CorsConfig) -> CorsLayer {
    let mut cors = CorsLayer::new();

    // Configure allowed origins
    if cors_config.allowed_origins.contains(&"*".to_string()) {
        cors = cors.allow_origin(Any);
    } else {
        for origin in &cors_config.allowed_origins {
            if let Ok(header_value) = HeaderValue::from_str(origin) {
                cors = cors.allow_origin(header_value);
            }
        }
    }

    // Configure allowed methods
    let methods: Vec<Method> = cors_config
        .allowed_methods
        .iter()
        .filter_map(|method| Method::from_str(method).ok())
        .collect();
    cors = cors.allow_methods(methods);

    // Configure allowed headers
    let headers: Vec<header::HeaderName> = cors_config
        .allowed_headers
        .iter()
        .filter_map(|header| header::HeaderName::from_str(header).ok())
        .collect();
    cors = cors.allow_headers(headers);

    // Configure exposed headers
    let exposed_headers: Vec<header::HeaderName> = cors_config
        .exposed_headers
        .iter()
        .filter_map(|header| header::HeaderName::from_str(header).ok())
        .collect();
    cors = cors.expose_headers(exposed_headers);

    // Configure credentials
    if cors_config.allow_credentials {
        cors = cors.allow_credentials(true);
    }

    // Configure max age
    if let Some(max_age) = cors_config.max_age {
        cors = cors.max_age(std::time::Duration::from_secs(max_age as u64));
    }

    cors
}

/// Security middleware that validates requests based on security policies
pub async fn security_validation_middleware(
    security_config: SecurityConfig,
    request: Request<Body>,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let headers = request.headers();

    // Validate Content-Type for POST/PUT requests
    if matches!(request.method(), &Method::POST | &Method::PUT) {
        if let Some(content_type) = headers.get("content-type") {
            let content_type_str = content_type.to_str().unwrap_or("");
            if !content_type_str.starts_with("application/json")
                && !content_type_str.starts_with("application/x-www-form-urlencoded")
                && !content_type_str.starts_with("multipart/form-data")
            {
                return Err((
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "Unsupported content type",
                ));
            }
        } else {
            return Err((StatusCode::BAD_REQUEST, "Content-Type header required"));
        }
    }

    // Validate Host header to prevent Host header injection
    if let Some(host) = headers.get("host") {
        let host_str = host.to_str().unwrap_or("");
        // Basic validation - in production, this should be more comprehensive
        if host_str.is_empty() || host_str.contains(' ') {
            return Err((StatusCode::BAD_REQUEST, "Invalid Host header"));
        }
    }

    // Block requests with suspicious User-Agent patterns
    if let Some(user_agent) = headers.get("user-agent") {
        let user_agent_str = user_agent.to_str().unwrap_or("");
        let suspicious_patterns = ["<script>", "javascript:", "vbscript:", "<iframe>"];
        if suspicious_patterns
            .iter()
            .any(|pattern| user_agent_str.to_lowercase().contains(pattern))
        {
            return Err((StatusCode::BAD_REQUEST, "Suspicious request detected"));
        }
    }

    // Validate request size (basic DoS protection)
    if let Some(content_length) = headers.get("content-length") {
        if let Ok(length_str) = content_length.to_str() {
            if let Ok(length) = length_str.parse::<usize>() {
                const MAX_REQUEST_SIZE: usize = 10 * 1024 * 1024; // 10MB
                if length > MAX_REQUEST_SIZE {
                    return Err((StatusCode::PAYLOAD_TOO_LARGE, "Request too large"));
                }
            }
        }
    }

    Ok(next.run(request).await)
}

/// Development-specific security middleware with relaxed policies
pub async fn development_security_middleware(
    security_config: SecurityConfig,
    request: Request<Body>,
    next: Next,
) -> Response {
    if security_config.development_mode {
        // In development mode, just add basic headers and skip strict validation
        let mut response = next.run(request).await;
        let headers = response.headers_mut();

        // Add minimal security headers for development
        if let Ok(value) = HeaderValue::from_str("nosniff") {
            headers.insert("x-content-type-options", value);
        }

        if let Ok(value) = HeaderValue::from_str("SAMEORIGIN") {
            headers.insert("x-frame-options", value);
        }

        response
    } else {
        // Production mode - apply full security headers
        security_headers_middleware(security_config, request, next)
            .await
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CorsConfig, SecurityConfig, SecurityHeadersConfig};

    fn create_test_security_config() -> SecurityConfig {
        SecurityConfig {
            headers: SecurityHeadersConfig::default(),
            cors: CorsConfig::default(),
            development_mode: false,
            strict_transport_security_enabled: true,
        }
    }

    fn create_test_development_security_config() -> SecurityConfig {
        SecurityConfig {
            headers: SecurityHeadersConfig::default(),
            cors: CorsConfig::default(),
            development_mode: true,
            strict_transport_security_enabled: false,
        }
    }

    #[test]
    fn test_cors_layer_creation() {
        let cors_config = CorsConfig {
            enabled: true,
            allowed_origins: vec!["http://localhost:3000".to_string()],
            allowed_methods: vec!["GET".to_string(), "POST".to_string()],
            allowed_headers: vec!["Authorization".to_string(), "Content-Type".to_string()],
            exposed_headers: vec!["X-Rate-Limit-Remaining".to_string()],
            allow_credentials: true,
            max_age: Some(3600),
        };

        let _cors_layer = create_cors_layer(&cors_config);
        // This test verifies that the CORS layer can be created without panicking
        assert!(true);
    }

    #[test]
    fn test_security_config_validation() {
        let config = create_test_security_config();
        assert!(!config.development_mode);
        assert!(config.strict_transport_security_enabled);
        assert_eq!(config.headers.x_content_type_options, "nosniff");
        assert_eq!(config.headers.x_frame_options, "DENY");
    }

    #[test]
    fn test_development_security_config() {
        let config = create_test_development_security_config();
        assert!(config.development_mode);
        assert!(!config.strict_transport_security_enabled);
    }

    #[test]
    fn test_wildcard_cors_origin() {
        let cors_config = CorsConfig {
            enabled: true,
            allowed_origins: vec!["*".to_string()],
            allowed_methods: vec!["GET".to_string()],
            allowed_headers: vec!["Authorization".to_string()],
            exposed_headers: vec![],
            allow_credentials: false,
            max_age: None,
        };

        let _cors_layer = create_cors_layer(&cors_config);
        assert!(true);
    }
}
