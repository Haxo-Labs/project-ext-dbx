//! Security middleware tests

use crate::middleware::security::*;
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
    // CORS layer creation test - compiles successfully
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
    // Wildcard CORS test - compiles successfully
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

