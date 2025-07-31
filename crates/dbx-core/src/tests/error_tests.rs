//! Error handling and error type tests

use super::utils;
use crate::*;
use serde_json;

#[test]
fn test_dbx_error_connection() {
    let error = DbxError::connection("redis", "Connection failed");
    assert_eq!(error.category(), "connection");
    assert!(error.is_retryable());
    assert_eq!(error.backend_name(), Some("redis"));
    assert!(format!("{}", error).contains("Connection failed"));
}

#[test]
fn test_dbx_error_unsupported_operation() {
    let error = DbxError::unsupported_operation("ZADD", "simple_kv");
    assert_eq!(error.category(), "operation");
    assert!(!error.is_retryable());
    assert_eq!(error.backend_name(), Some("simple_kv"));
    assert!(format!("{}", error).contains("ZADD"));
}

#[test]
fn test_dbx_error_routing() {
    let error = DbxError::routing("No backend available for key pattern");
    assert_eq!(error.category(), "routing");
    assert!(error.is_retryable());
    assert_eq!(error.backend_name(), None);
    assert!(format!("{}", error).contains("No backend available"));
}

#[test]
fn test_dbx_error_validation() {
    let error1 = DbxError::validation("Invalid data format");
    let error2 = DbxError::validation_field("Value out of range", "age");

    assert_eq!(error1.category(), "validation");
    assert!(!error1.is_retryable());
    assert_eq!(error1.backend_name(), None);
    assert!(format!("{}", error1).contains("Invalid data format"));

    assert_eq!(error2.category(), "validation");
    assert!(!error2.is_retryable());
    assert!(format!("{}", error2).contains("Value out of range"));
}

#[test]
fn test_dbx_error_serialization() {
    let error = DbxError::serialization("Failed to serialize JSON");
    assert_eq!(error.category(), "serialization");
    assert!(!error.is_retryable());
    assert!(format!("{}", error).contains("Failed to serialize JSON"));
}

#[test]
fn test_dbx_error_authentication() {
    let error = DbxError::authentication("Invalid credentials");
    assert_eq!(error.category(), "authentication");
    assert!(!error.is_retryable());
    assert!(format!("{}", error).contains("Invalid credentials"));
}

#[test]
fn test_dbx_error_rate_limit() {
    let error = DbxError::rate_limit("Too many requests", Some(60));
    assert_eq!(error.category(), "rate_limit");
    assert!(error.is_retryable());
    assert!(format!("{}", error).contains("Too many requests"));
}

#[test]
fn test_dbx_error_configuration() {
    let error1 = DbxError::configuration("Missing required setting");
    let error2 = DbxError::configuration_field("Invalid port", "port");

    assert_eq!(error1.category(), "configuration");
    assert!(!error1.is_retryable());
    assert!(format!("{}", error1).contains("Missing required setting"));

    assert_eq!(error2.category(), "configuration");
    assert!(!error2.is_retryable());
    assert!(format!("{}", error2).contains("Invalid port"));
}

#[test]
fn test_dbx_error_timeout() {
    let error = DbxError::timeout("Operation timed out", 5000);
    assert_eq!(error.category(), "timeout");
    assert!(error.is_retryable());
    assert!(format!("{}", error).contains("Operation timed out"));
}

#[test]
fn test_dbx_error_backend() {
    let error1 = DbxError::backend("postgres", "Connection lost");
    let error2 = DbxError::backend_with_code("redis", "READONLY", "ERR_READONLY");

    assert_eq!(error1.category(), "backend");
    assert!(error1.is_retryable());
    assert_eq!(error1.backend_name(), Some("postgres"));
    assert!(format!("{}", error1).contains("Connection lost"));

    assert_eq!(error2.category(), "backend");
    assert!(error2.is_retryable());
    assert_eq!(error2.backend_name(), Some("redis"));
    assert!(format!("{}", error2).contains("READONLY"));
}

#[test]
fn test_dbx_error_not_found() {
    let error1 = DbxError::not_found("Resource not found");
    let error2 = DbxError::not_found_key("Key not found", "user:123");

    assert_eq!(error1.category(), "not_found");
    assert!(!error1.is_retryable());
    assert!(format!("{}", error1).contains("Resource not found"));

    assert_eq!(error2.category(), "not_found");
    assert!(!error2.is_retryable());
    assert!(format!("{}", error2).contains("Key not found"));
}

#[test]
fn test_dbx_error_conflict() {
    let error1 = DbxError::conflict("Resource already exists");
    let error2 = DbxError::conflict_key("Key already exists", "user:456");

    assert_eq!(error1.category(), "conflict");
    assert!(!error1.is_retryable());
    assert!(format!("{}", error1).contains("Resource already exists"));

    assert_eq!(error2.category(), "conflict");
    assert!(!error2.is_retryable());
    assert!(format!("{}", error2).contains("Key already exists"));
}

#[test]
fn test_dbx_error_internal() {
    let error = DbxError::internal("Internal server error");
    assert_eq!(error.category(), "internal");
    assert!(error.is_retryable());
    assert!(format!("{}", error).contains("Internal server error"));
}

#[test]
fn test_dbx_error_display() {
    let error = DbxError::connection("redis", "Connection refused");
    let display_str = format!("{}", error);
    assert!(display_str.contains("Connection error"));
    assert!(display_str.contains("redis"));
    assert!(display_str.contains("Connection refused"));
}

#[test]
fn test_dbx_error_debug() {
    let error = DbxError::validation_field("Invalid value", "email");
    let debug_str = format!("{:?}", error);
    assert!(debug_str.contains("Validation"));
    assert!(debug_str.contains("Invalid value"));
    assert!(debug_str.contains("email"));
}

#[test]
fn test_dbx_error_json_serialization() {
    let errors = vec![
        DbxError::connection("redis", "Connection failed"),
        DbxError::validation("Invalid data"),
        DbxError::timeout("Timeout", 1000),
        DbxError::not_found_key("Not found", "key1"),
        DbxError::rate_limit("Rate limited", Some(30)),
    ];

    for error in errors {
        let json = serde_json::to_string(&error).unwrap();
        let deserialized: DbxError = serde_json::from_str(&json).unwrap();

        // Compare error categories and public API since full equality test would be complex
        assert_eq!(error.category(), deserialized.category());
        assert_eq!(error.is_retryable(), deserialized.is_retryable());
        assert_eq!(error.backend_name(), deserialized.backend_name());
    }
}

#[test]
fn test_dbx_error_from_conversions() {
    // Test From<serde_json::Error>
    let json_error = serde_json::from_str::<serde_json::Value>("invalid json").unwrap_err();
    let dbx_error: DbxError = json_error.into();
    assert_eq!(dbx_error.category(), "serialization");
    assert!(!dbx_error.is_retryable());

    // From implementation compilation test
}

#[test]
fn test_dbx_error_retryable_logic() {
    // Test retryable errors
    let retryable_errors = vec![
        DbxError::connection("redis", "Connection failed"),
        DbxError::routing("No backend available"),
        DbxError::rate_limit("Too many requests", None),
        DbxError::timeout("Timeout", 1000),
        DbxError::backend("postgres", "Connection error"),
        DbxError::internal("Internal error"),
    ];

    for error in retryable_errors {
        assert!(
            error.is_retryable(),
            "Error should be retryable: {:?}",
            error
        );
    }

    // Test non-retryable errors
    let non_retryable_errors = vec![
        DbxError::unsupported_operation("INVALID", "backend"),
        DbxError::validation("Invalid data"),
        DbxError::serialization("Serialization failed"),
        DbxError::authentication("Invalid auth"),
        DbxError::configuration("Bad config"),
        DbxError::not_found("Not found"),
        DbxError::conflict("Conflict"),
    ];

    for error in non_retryable_errors {
        assert!(
            !error.is_retryable(),
            "Error should not be retryable: {:?}",
            error
        );
    }
}

#[test]
fn test_dbx_error_categories() {
    let error_category_pairs = vec![
        (DbxError::connection("redis", "err"), "connection"),
        (
            DbxError::unsupported_operation("op", "backend"),
            "operation",
        ),
        (DbxError::routing("err"), "routing"),
        (DbxError::validation("err"), "validation"),
        (DbxError::serialization("err"), "serialization"),
        (DbxError::authentication("err"), "authentication"),
        (DbxError::rate_limit("err", None), "rate_limit"),
        (DbxError::configuration("err"), "configuration"),
        (DbxError::timeout("err", 1000), "timeout"),
        (DbxError::backend("backend", "err"), "backend"),
        (DbxError::not_found("err"), "not_found"),
        (DbxError::conflict("err"), "conflict"),
        (DbxError::internal("err"), "internal"),
    ];

    for (error, expected_category) in error_category_pairs {
        assert_eq!(error.category(), expected_category);
    }
}

#[test]
fn test_dbx_result_type_alias() {
    let success_result: DbxResult<String> = Ok("success".to_string());
    let error_result: DbxResult<String> = Err(DbxError::internal("error"));

    assert!(success_result.is_ok());
    assert!(error_result.is_err());
}

#[test]
fn test_error_equality() {
    let error1 = DbxError::validation("test error");
    let error2 = DbxError::validation("test error");
    let error3 = DbxError::validation("different error");

    // Test that DbxError now implements PartialEq
    assert_eq!(error1, error2);
    assert_ne!(error1, error3);

    // Also test serialization consistency
    let json1 = serde_json::to_string(&error1).unwrap();
    let json2 = serde_json::to_string(&error2).unwrap();
    let json3 = serde_json::to_string(&error3).unwrap();

    assert_eq!(json1, json2);
    assert_ne!(json1, json3);
}
