use axum::{
    body::Body,
    http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use tower_http::cors::{Any, CorsLayer};

use crate::config::{CorsConfig, HostValidationConfig, SecurityConfig};

#[derive(Debug, Clone)]
pub struct TrustedProxyConfig {
    trusted_proxies: HashSet<IpAddr>,
    trusted_networks: Vec<(IpAddr, u8)>, // CIDR blocks
    proxy_headers: Vec<String>,
    max_chain_length: usize,
    require_trusted_path: bool,
}

impl Default for TrustedProxyConfig {
    fn default() -> Self {
        let mut trusted_proxies = HashSet::new();
        // Common trusted proxy IPs (should be configured per environment)
        trusted_proxies.insert(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))); // localhost
        trusted_proxies.insert(IpAddr::V6(Ipv6Addr::LOCALHOST)); // IPv6 localhost

        let mut trusted_networks = Vec::new();
        // RFC 1918 private networks (commonly used by load balancers)
        trusted_networks.push((IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8)); // 10.0.0.0/8
        trusted_networks.push((IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)), 12)); // 172.16.0.0/12
        trusted_networks.push((IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 16)); // 192.168.0.0/16

        Self {
            trusted_proxies,
            trusted_networks,
            proxy_headers: vec![
                "x-forwarded-for".to_string(),
                "x-real-ip".to_string(),
                "x-client-ip".to_string(),
                "cf-connecting-ip".to_string(), // Cloudflare
                "x-cluster-client-ip".to_string(),
                "true-client-ip".to_string(), // Akamai
            ],
            max_chain_length: 10,
            require_trusted_path: true,
        }
    }
}

impl TrustedProxyConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_trusted_proxies(mut self, proxies: Vec<IpAddr>) -> Self {
        self.trusted_proxies.extend(proxies);
        self
    }

    pub fn with_trusted_networks(mut self, networks: Vec<(IpAddr, u8)>) -> Self {
        self.trusted_networks.extend(networks);
        self
    }

    pub fn require_trusted_path(mut self, require: bool) -> Self {
        self.require_trusted_path = require;
        self
    }

    fn is_trusted_proxy(&self, ip: &IpAddr) -> bool {
        if self.trusted_proxies.contains(ip) {
            return true;
        }

        for (network, prefix_len) in &self.trusted_networks {
            if self.ip_in_network(ip, network, *prefix_len) {
                return true;
            }
        }

        false
    }

    fn ip_in_network(&self, ip: &IpAddr, network: &IpAddr, prefix_len: u8) -> bool {
        match (ip, network) {
            (IpAddr::V4(ip), IpAddr::V4(net)) => {
                let ip_bits = u32::from(*ip);
                let net_bits = u32::from(*net);
                let mask = !((1u32 << (32 - prefix_len)) - 1);
                (ip_bits & mask) == (net_bits & mask)
            }
            (IpAddr::V6(ip), IpAddr::V6(net)) => {
                let ip_bits = u128::from(*ip);
                let net_bits = u128::from(*net);
                let mask = !((1u128 << (128 - prefix_len)) - 1);
                (ip_bits & mask) == (net_bits & mask)
            }
            _ => false, // Different IP versions
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClientIpInfo {
    pub ip: IpAddr,
    pub source: String, // Which header or direct connection
    pub proxy_chain: Vec<IpAddr>,
    pub is_trusted: bool,
    pub validation_errors: Vec<String>,
}

pub struct TrustedProxyValidator {
    config: TrustedProxyConfig,
}

impl TrustedProxyValidator {
    pub fn new(config: TrustedProxyConfig) -> Self {
        Self { config }
    }

    pub fn extract_client_ip(
        &self,
        headers: &HeaderMap,
        connect_info: Option<&std::net::SocketAddr>,
    ) -> ClientIpInfo {
        let mut validation_errors = Vec::new();

        // Get the direct connection IP as fallback
        let direct_ip = connect_info.map(|addr| addr.ip());

        // Try each proxy header in order of preference
        for header_name in &self.config.proxy_headers {
            if let Some(header_value) = headers.get(header_name) {
                if let Ok(header_str) = header_value.to_str() {
                    if let Some(client_ip_info) =
                        self.parse_proxy_header(header_str, header_name, direct_ip)
                    {
                        return client_ip_info;
                    }
                }
            }
        }

        // Fallback to direct connection
        if let Some(ip) = direct_ip {
            ClientIpInfo {
                ip,
                source: "direct_connection".to_string(),
                proxy_chain: vec![],
                is_trusted: true, // Direct connections are considered trusted
                validation_errors,
            }
        } else {
            validation_errors.push("No IP address available".to_string());
            ClientIpInfo {
                ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                source: "unknown".to_string(),
                proxy_chain: vec![],
                is_trusted: false,
                validation_errors,
            }
        }
    }

    fn parse_proxy_header(
        &self,
        header_value: &str,
        header_name: &str,
        direct_ip: Option<IpAddr>,
    ) -> Option<ClientIpInfo> {
        let mut validation_errors = Vec::new();

        // Parse comma-separated IPs (standard for X-Forwarded-For)
        let ips: Vec<&str> = header_value
            .split(',')
            .map(|ip| ip.trim())
            .filter(|ip| !ip.is_empty())
            .collect();

        if ips.is_empty() {
            return None;
        }

        if ips.len() > self.config.max_chain_length {
            validation_errors.push(format!(
                "Proxy chain too long: {} (max: {})",
                ips.len(),
                self.config.max_chain_length
            ));
            return None;
        }

        // Parse IPs and build proxy chain
        let mut parsed_ips = Vec::new();
        for ip_str in ips {
            match ip_str.parse::<IpAddr>() {
                Ok(ip) => parsed_ips.push(ip),
                Err(_) => {
                    validation_errors.push(format!("Invalid IP format: {}", ip_str));
                    return None;
                }
            }
        }

        if parsed_ips.is_empty() {
            return None;
        }

        // The first IP in X-Forwarded-For is typically the client IP
        let client_ip = parsed_ips[0];
        let proxy_chain = parsed_ips[1..].to_vec();

        // Validate proxy chain if required
        let is_trusted = if self.config.require_trusted_path {
            self.validate_proxy_chain(&proxy_chain, direct_ip, &mut validation_errors)
        } else {
            true
        };

        Some(ClientIpInfo {
            ip: client_ip,
            source: header_name.to_string(),
            proxy_chain,
            is_trusted,
            validation_errors,
        })
    }

    fn validate_proxy_chain(
        &self,
        proxy_chain: &[IpAddr],
        direct_ip: Option<IpAddr>,
        validation_errors: &mut Vec<String>,
    ) -> bool {
        // If we have a direct IP, it should be the last proxy in the chain
        if let Some(direct) = direct_ip {
            if !proxy_chain.is_empty() {
                let last_proxy = proxy_chain[proxy_chain.len() - 1];
                if last_proxy != direct {
                    validation_errors.push(format!(
                        "Proxy chain mismatch: last proxy {} != direct connection {}",
                        last_proxy, direct
                    ));
                    return false;
                }
            }

            // Check if direct connection is from trusted proxy
            if !self.config.is_trusted_proxy(&direct) {
                validation_errors.push(format!("Untrusted direct proxy: {}", direct));
                return false;
            }
        }

        // Validate each proxy in the chain
        for (i, proxy_ip) in proxy_chain.iter().enumerate() {
            if !self.config.is_trusted_proxy(proxy_ip) {
                validation_errors.push(format!("Untrusted proxy at position {}: {}", i, proxy_ip));
                return false;
            }
        }

        true
    }

    pub fn get_trusted_client_ip(
        &self,
        headers: &HeaderMap,
        connect_info: Option<&std::net::SocketAddr>,
    ) -> Option<IpAddr> {
        let client_ip_info = self.extract_client_ip(headers, connect_info);

        if client_ip_info.is_trusted && client_ip_info.validation_errors.is_empty() {
            Some(client_ip_info.ip)
        } else {
            None
        }
    }
}

// Create a static instance for the trusted proxy validator
static DEFAULT_TRUSTED_PROXY_VALIDATOR: std::sync::OnceLock<TrustedProxyValidator> =
    std::sync::OnceLock::new();

pub fn get_trusted_proxy_validator() -> &'static TrustedProxyValidator {
    DEFAULT_TRUSTED_PROXY_VALIDATOR.get_or_init(|| {
        let config = TrustedProxyConfig::default();
        TrustedProxyValidator::new(config)
    })
}

pub fn extract_trusted_client_ip(
    headers: &HeaderMap,
    connect_info: Option<&std::net::SocketAddr>,
) -> Option<IpAddr> {
    get_trusted_proxy_validator().get_trusted_client_ip(headers, connect_info)
}

pub fn extract_client_ip_info(
    headers: &HeaderMap,
    connect_info: Option<&std::net::SocketAddr>,
) -> ClientIpInfo {
    get_trusted_proxy_validator().extract_client_ip(headers, connect_info)
}

/// Validates Host header to prevent injection attacks
fn validate_host_header(host: &str, config: &SecurityConfig) -> Result<(), &'static str> {
    let host_config = &config.host_validation;

    // Skip validation if disabled
    if !host_config.enabled {
        return Ok(());
    }

    // Format validation
    if host.is_empty() {
        return Err("Host header cannot be empty");
    }

    if host.len() > host_config.max_host_length {
        return Err("Host header exceeds maximum length");
    }

    // Security checks for malicious patterns
    if host.contains(' ') || host.contains('\t') || host.contains('\n') || host.contains('\r') {
        return Err("Host header contains invalid whitespace characters");
    }

    if host.chars().any(|c| c.is_control()) {
        return Err("Host header contains control characters");
    }

    if host.contains('@') {
        return Err("Host header contains @ character (potential user info injection)");
    }

    if host.contains("..") {
        return Err("Host header contains consecutive dots (potential path traversal)");
    }

    if host.starts_with('.') || host.ends_with('.') {
        return Err("Host header cannot start or end with dot");
    }

    if host.starts_with('-') || host.ends_with('-') {
        return Err("Host header cannot start or end with hyphen");
    }

    // Parse host and port
    let (hostname, port) = parse_host_and_port(host)?;

    // Validate port if present
    if let Some(port_num) = port {
        validate_port(port_num, host_config)?;
    }

    // Validate hostname format
    validate_hostname_format(&hostname, host_config)?;

    // Check against allowed hosts list
    validate_against_allowlist(&hostname, port, host_config)?;

    Ok(())
}

/// Parse host header into hostname and optional port
fn parse_host_and_port(host: &str) -> Result<(&str, Option<u16>), &'static str> {
    // Handle IPv6 addresses with brackets
    if host.starts_with('[') {
        if let Some(bracket_end) = host.find(']') {
            let ipv6_addr = &host[1..bracket_end];

            // Validate IPv6 format
            if ipv6_addr.parse::<Ipv6Addr>().is_err() {
                return Err("Invalid IPv6 address format");
            }

            // Check for port after bracket
            if bracket_end + 1 < host.len() {
                if !host[bracket_end + 1..].starts_with(':') {
                    return Err("Invalid characters after IPv6 address");
                }

                let port_str = &host[bracket_end + 2..];
                if port_str.is_empty() {
                    return Err("Empty port after colon");
                }

                let port = port_str.parse::<u16>().map_err(|_| "Invalid port number")?;

                return Ok((ipv6_addr, Some(port)));
            }

            return Ok((ipv6_addr, None));
        } else {
            return Err("Unclosed IPv6 bracket");
        }
    }

    // Handle regular hostname or IPv4 address with optional port
    if let Some(colon_pos) = host.rfind(':') {
        let hostname = &host[..colon_pos];
        let port_str = &host[colon_pos + 1..];

        if port_str.is_empty() {
            return Err("Empty port after colon");
        }

        // Check if this is actually part of an IPv6 address (multiple colons)
        if hostname.contains(':') {
            // This might be an IPv6 address without brackets
            if host.parse::<Ipv6Addr>().is_ok() {
                return Ok((host, None));
            } else {
                return Err("Invalid IPv6 address or ambiguous port specification");
            }
        }

        let port = port_str.parse::<u16>().map_err(|_| "Invalid port number")?;

        Ok((hostname, Some(port)))
    } else {
        Ok((host, None))
    }
}

/// Validate port number against security policies
fn validate_port(port: u16, config: &HostValidationConfig) -> Result<(), &'static str> {
    if port == 0 {
        return Err("Port number cannot be zero");
    }

    if config.strict_port_validation {
        if let Some(ref allowed_ports) = config.allowed_ports {
            if !allowed_ports.contains(&port) {
                return Err("Port not in allowed list");
            }
        }
    }

    Ok(())
}

/// Validate hostname format according to RFC standards
fn validate_hostname_format(
    hostname: &str,
    config: &HostValidationConfig,
) -> Result<(), &'static str> {
    if hostname.is_empty() {
        return Err("Hostname cannot be empty");
    }

    // Check if it's an IP address
    if let Ok(_) = hostname.parse::<Ipv4Addr>() {
        return validate_ipv4_address(hostname, config);
    }

    if let Ok(_) = hostname.parse::<Ipv6Addr>() {
        return validate_ipv6_address(hostname, config);
    }

    // Validate as domain name
    validate_domain_name(hostname)
}

/// Validate IPv4 address
fn validate_ipv4_address(ip: &str, config: &HostValidationConfig) -> Result<(), &'static str> {
    let addr = ip.parse::<Ipv4Addr>().map_err(|_| "Invalid IPv4 address")?;

    // Check for localhost
    if addr.is_loopback() && !config.allow_localhost {
        return Err("Localhost IP addresses not allowed");
    }

    // Check for private IP addresses
    if addr.is_private() && !config.allow_private_ips {
        return Err("Private IP addresses not allowed");
    }

    // Block special/reserved addresses
    if addr.is_unspecified() || addr.is_broadcast() || addr.is_multicast() {
        return Err("Special/reserved IP addresses not allowed");
    }

    Ok(())
}

/// Validate IPv6 address
fn validate_ipv6_address(ip: &str, config: &HostValidationConfig) -> Result<(), &'static str> {
    if !config.allow_ipv6 {
        return Err("IPv6 addresses not allowed");
    }

    let addr = ip.parse::<Ipv6Addr>().map_err(|_| "Invalid IPv6 address")?;

    // Check for localhost
    if addr.is_loopback() && !config.allow_localhost {
        return Err("Localhost IPv6 addresses not allowed");
    }

    // Block special addresses
    if addr.is_unspecified() || addr.is_multicast() {
        return Err("Special/reserved IPv6 addresses not allowed");
    }

    Ok(())
}

/// Validate domain name according to RFC standards
fn validate_domain_name(domain: &str) -> Result<(), &'static str> {
    if domain.len() > 253 {
        return Err("Domain name too long");
    }

    // Split into labels and validate each
    let labels: Vec<&str> = domain.split('.').collect();

    for label in &labels {
        if label.is_empty() {
            return Err("Empty domain label");
        }

        if label.len() > 63 {
            return Err("Domain label too long");
        }

        if label.starts_with('-') || label.ends_with('-') {
            return Err("Domain label cannot start or end with hyphen");
        }

        // Validate characters (allow only ASCII alphanumeric and hyphens)
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err("Invalid characters in domain label");
        }
    }

    // Additional security checks for homograph attacks
    if domain.chars().any(|c| !c.is_ascii()) {
        return Err("Non-ASCII characters not allowed in domain");
    }

    Ok(())
}

/// Validate hostname against allowlist
fn validate_against_allowlist(
    hostname: &str,
    port: Option<u16>,
    config: &HostValidationConfig,
) -> Result<(), &'static str> {
    if config.allowed_hosts.is_empty() {
        return Ok(()); // No restrictions if allowlist is empty
    }

    // Normalize hostname for comparison
    let normalized_host = hostname.to_lowercase();

    // Check exact matches first
    for allowed_host in &config.allowed_hosts {
        let normalized_allowed = allowed_host.to_lowercase();

        // Exact match
        if normalized_host == normalized_allowed {
            return Ok(());
        }

        // Match with port
        if let Some(p) = port {
            let host_with_port = format!("{}:{}", normalized_host, p);
            if host_with_port == normalized_allowed {
                return Ok(());
            }
        }

        // Wildcard subdomain matching (*.example.com)
        if normalized_allowed.starts_with("*.") {
            let wildcard_domain = &normalized_allowed[2..];
            if normalized_host.ends_with(wildcard_domain) {
                // Ensure it's a proper subdomain, not just suffix match
                let prefix_len = normalized_host.len() - wildcard_domain.len();
                if prefix_len > 0 && normalized_host.chars().nth(prefix_len - 1) == Some('.') {
                    return Ok(());
                }
            }
        }
    }

    Err("Host not in allowed list")
}

/// Security headers middleware that adds security headers to all responses
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

    // Add Strict-Transport-Security (HTTPS only in non-development mode)
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

/// Security middleware with validation policies
pub async fn security_middleware(
    security_config: SecurityConfig,
    request: Request<Body>,
    next: Next,
) -> Response {
    // Always apply full security headers regardless of environment
    security_headers_middleware(security_config, request, next)
        .await
        .into_response()
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

    // Validate Host header to prevent Host header injection and domain attacks
    if let Some(host) = headers.get("host") {
        let host_str = host.to_str().unwrap_or("");

        if let Err(error_msg) = validate_host_header(host_str, &security_config) {
            return Err((StatusCode::BAD_REQUEST, error_msg));
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

    // Validate request size (DoS protection)
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
        // In development mode, add headers and skip strict validation
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
        // Non-development mode - apply security headers
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
        let mut host_config = HostValidationConfig::default();
        // Add test IPs and hosts to allowed hosts for testing
        host_config.allowed_hosts.extend(vec![
            "192.168.1.1".to_string(),
            "10.0.0.1".to_string(),
            "192.168.1.1:8080".to_string(),
            "example.com".to_string(),
            "sub.example.com".to_string(),
            "test-site.example.com".to_string(),
            "example.com:80".to_string(),
            "example.com:443".to_string(),
            "example.com:3000".to_string(),
            // IPv6 addresses
            "2001:db8::1".to_string(),
            "[2001:db8::1]".to_string(),
            "[::1]:8080".to_string(),
            // For length limit tests - add specific long domains
            {
                let label1 = "a".repeat(63);
                let label2 = "b".repeat(63);
                let label3 = "c".repeat(63);
                let label4 = "d".repeat(57);
                format!("{}.{}.{}.{}.com", label1, label2, label3, label4)
            },
            format!("{}.com", "a".repeat(249)),
            format!("{}.com", "a".repeat(63)),
        ]);

        // Allow longer host lengths for length limit tests
        host_config.max_host_length = 500;

        SecurityConfig {
            headers: SecurityHeadersConfig::default(),
            cors: CorsConfig::default(),
            host_validation: host_config,
            development_mode: false,
            strict_transport_security_enabled: true,
        }
    }

    fn create_test_development_security_config() -> SecurityConfig {
        SecurityConfig {
            headers: SecurityHeadersConfig::default(),
            cors: CorsConfig::default(),
            host_validation: HostValidationConfig::default(),
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

    #[test]
    fn test_host_validation_valid_domains() {
        let config = create_test_security_config();

        // Valid domain names
        assert!(validate_host_header("example.com", &config).is_ok());
        assert!(validate_host_header("sub.example.com", &config).is_ok());
        assert!(validate_host_header("test-site.example.com", &config).is_ok());
        assert!(validate_host_header("localhost", &config).is_ok());
        assert!(validate_host_header("localhost:3000", &config).is_ok());
        assert!(validate_host_header("127.0.0.1", &config).is_ok());
        assert!(validate_host_header("127.0.0.1:8080", &config).is_ok());
    }

    #[test]
    fn test_host_validation_invalid_formats() {
        let config = create_test_security_config();

        // Empty host
        assert!(validate_host_header("", &config).is_err());

        // Control characters
        assert!(validate_host_header("example.com\n", &config).is_err());
        assert!(validate_host_header("example.com\r", &config).is_err());
        assert!(validate_host_header("example.com\t", &config).is_err());

        // Whitespace
        assert!(validate_host_header("example .com", &config).is_err());

        // @ character (user info injection)
        assert!(validate_host_header("user@example.com", &config).is_err());

        // Path traversal patterns
        assert!(validate_host_header("example..com", &config).is_err());
        assert!(validate_host_header("..example.com", &config).is_err());
        assert!(validate_host_header(".example.com", &config).is_err());
        assert!(validate_host_header("example.com.", &config).is_err());

        // Invalid start/end with hyphen
        assert!(validate_host_header("-example.com", &config).is_err());
        assert!(validate_host_header("example.com-", &config).is_err());
    }

    #[test]
    fn test_host_validation_ipv4_addresses() {
        let config = create_test_security_config();

        // Valid IPv4
        assert!(validate_host_header("192.168.1.1", &config).is_ok());
        assert!(validate_host_header("10.0.0.1", &config).is_ok());
        assert!(validate_host_header("127.0.0.1", &config).is_ok());

        // IPv4 with port
        assert!(validate_host_header("192.168.1.1:8080", &config).is_ok());

        // Invalid IPv4
        assert!(validate_host_header("256.256.256.256", &config).is_err());
        assert!(validate_host_header("192.168.1", &config).is_err());
    }

    #[test]
    fn test_host_validation_ipv6_addresses() {
        let config = create_test_security_config();

        // Valid IPv6 with brackets
        assert!(validate_host_header("[::1]", &config).is_ok());
        assert!(validate_host_header("[2001:db8::1]", &config).is_ok());
        assert!(validate_host_header("[::1]:8080", &config).is_ok());

        // Valid IPv6 without brackets (no port)
        assert!(validate_host_header("::1", &config).is_ok());
        assert!(validate_host_header("2001:db8::1", &config).is_ok());

        // Invalid IPv6
        assert!(validate_host_header("[invalid::ipv6", &config).is_err());
        assert!(validate_host_header("[::1", &config).is_err());
    }

    #[test]
    fn test_host_validation_port_validation() {
        let config = create_test_security_config();

        // Valid ports
        assert!(validate_host_header("example.com:80", &config).is_ok());
        assert!(validate_host_header("example.com:443", &config).is_ok());
        assert!(validate_host_header("example.com:3000", &config).is_ok());

        // Invalid ports
        assert!(validate_host_header("example.com:0", &config).is_err());
        assert!(validate_host_header("example.com:99999", &config).is_err());
        assert!(validate_host_header("example.com:", &config).is_err());
        assert!(validate_host_header("example.com:abc", &config).is_err());
    }

    #[test]
    fn test_host_validation_allowlist() {
        let mut config = create_test_security_config();
        config.host_validation.allowed_hosts = vec![
            "allowed.com".to_string(),
            "*.subdomain.com".to_string(),
            "127.0.0.1".to_string(),
        ];

        // Allowed hosts
        assert!(validate_host_header("allowed.com", &config).is_ok());
        assert!(validate_host_header("test.subdomain.com", &config).is_ok());
        assert!(validate_host_header("deep.test.subdomain.com", &config).is_ok());
        assert!(validate_host_header("127.0.0.1", &config).is_ok());

        // Disallowed hosts
        assert!(validate_host_header("evil.com", &config).is_err());
        assert!(validate_host_header("subdomain.com", &config).is_err()); // Wildcard doesn't match exact
        assert!(validate_host_header("fakesubdomain.com", &config).is_err()); // Suffix but not subdomain
    }

    #[test]
    fn test_host_validation_disabled() {
        let mut config = create_test_security_config();
        config.host_validation.enabled = false;

        // Should pass even with invalid input when disabled
        assert!(validate_host_header("", &config).is_ok());
        assert!(validate_host_header("invalid..host", &config).is_ok());
        assert!(validate_host_header("user@evil.com", &config).is_ok());
    }

    #[test]
    fn test_host_validation_length_limits() {
        let config = create_test_security_config();

        // Test maximum domain length (253 characters)
        // Create a domain with multiple labels that totals exactly 253 characters
        let label1 = "a".repeat(63);
        let label2 = "b".repeat(63);
        let label3 = "c".repeat(63);
        let label4 = "d".repeat(57); // 63+1+63+1+63+1+57+4 = 253 chars total
        let long_domain = format!("{}.{}.{}.{}.com", label1, label2, label3, label4);
        match validate_host_header(&long_domain, &config) {
            Ok(_) => {}
            Err(e) => panic!(
                "Expected long domain '{}' (len={}) to be valid, but got error: {}",
                long_domain,
                long_domain.len(),
                e
            ),
        }

        // Test exceeding maximum domain length
        let too_long_domain = "a".repeat(260);
        assert!(validate_host_header(&too_long_domain, &config).is_err());

        // Test maximum label length (63 characters)
        let long_label = "a".repeat(63) + ".com";
        assert!(validate_host_header(&long_label, &config).is_ok());

        // Test exceeding maximum label length
        let too_long_label = "a".repeat(64) + ".com";
        assert!(validate_host_header(&too_long_label, &config).is_err());
    }

    #[test]
    fn test_host_validation_security_attacks() {
        let config = create_test_security_config();

        // Test various attack patterns
        assert!(validate_host_header("example.com\x00", &config).is_err()); // Null byte
        assert!(validate_host_header("example.com\x1f", &config).is_err()); // Control character
        assert!(validate_host_header("examplé.com", &config).is_err()); // Non-ASCII (IDN attack)
        assert!(validate_host_header("еxample.com", &config).is_err()); // Cyrillic 'e' (homograph)

        // CRLF injection attempts
        assert!(validate_host_header("example.com\r\nHost: evil.com", &config).is_err());
    }

    #[test]
    fn test_parse_host_and_port() {
        // Valid cases
        assert_eq!(
            parse_host_and_port("example.com").unwrap(),
            ("example.com", None)
        );
        assert_eq!(
            parse_host_and_port("example.com:80").unwrap(),
            ("example.com", Some(80))
        );
        assert_eq!(
            parse_host_and_port("127.0.0.1:3000").unwrap(),
            ("127.0.0.1", Some(3000))
        );
        assert_eq!(parse_host_and_port("[::1]").unwrap(), ("::1", None));
        assert_eq!(
            parse_host_and_port("[::1]:8080").unwrap(),
            ("::1", Some(8080))
        );
        assert_eq!(
            parse_host_and_port("2001:db8::1").unwrap(),
            ("2001:db8::1", None)
        );

        // Invalid cases
        assert!(parse_host_and_port("[::1").is_err()); // Unclosed bracket
        assert!(parse_host_and_port("example.com:").is_err()); // Empty port
        assert!(parse_host_and_port("example.com:abc").is_err()); // Invalid port
        assert!(parse_host_and_port("[invalid::ipv6]").is_err()); // Invalid IPv6
    }
}
