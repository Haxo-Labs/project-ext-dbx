//! Adapter library tests

use crate::VERSION;

#[test]
fn test_version_exists() {
    assert!(!VERSION.is_empty(), "Version should be defined");
}

#[test]
fn test_redis_url_from_env() {
    use super::utils::get_test_redis_url;

    // Test that the function returns a valid URL
    let url = get_test_redis_url();
    assert!(!url.is_empty(), "Redis URL should not be empty");
    assert!(
        url.starts_with("redis://"),
        "Redis URL should start with redis://"
    );
}
