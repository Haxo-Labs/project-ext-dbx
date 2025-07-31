#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::env;

    fn clear_env_vars() {
        env::remove_var("HOST");
        env::remove_var("PORT");

        env::remove_var("JWT_SECRET");
        env::remove_var("JWT_EXPIRATION_SECONDS");
        env::remove_var("JWT_ACCESS_TOKEN_EXPIRATION");
        env::remove_var("JWT_REFRESH_TOKEN_EXPIRATION");
        env::remove_var("JWT_ISSUER");
        env::remove_var("CREATE_DEFAULT_ADMIN");
        env::remove_var("DEFAULT_ADMIN_USERNAME");
        env::remove_var("DEFAULT_ADMIN_PASSWORD");

        // Clear backend configuration
        env::remove_var("DBX_BACKEND_1_URL");
        env::remove_var("DBX_BACKEND_1_PROVIDER");
        env::remove_var("DBX_BACKEND_1_NAME");
        env::remove_var("DBX_BACKEND_1_POOL_SIZE");
        env::remove_var("DBX_DEFAULT_BACKEND");

        // Clear environment variables that might interfere with test defaults
        env::remove_var("DEVELOPMENT_MODE");
        env::remove_var("LOG_LEVEL");
    }

    fn setup_test_env() {
        clear_env_vars(); // Clear any existing environment variables

        // Set up test environment with required variables
        env::set_var(
            "JWT_SECRET",
            "test-jwt-secret-that-is-at-least-32-characters-long",
        );
        env::set_var("DBX_BACKEND_1_URL", "mock://localhost:6379");
        env::set_var("DBX_BACKEND_1_PROVIDER", "mock");
        env::set_var("DBX_BACKEND_1_NAME", "test_backend");
        env::set_var("DBX_BACKEND_1_POOL_SIZE", "10");
        env::set_var("DBX_DEFAULT_BACKEND", "test_backend");
    }

    fn cleanup_test_env() {
        clear_env_vars();
    }

    #[test]
    fn test_jwt_config_validation_valid_secret() {
        let config = JwtConfig {
            secret: "test-jwt-secret-that-is-at-least-32-characters-long".to_string(),
            access_token_expiration: 900,
            refresh_token_expiration: 604800,
            issuer: "test".to_string(),
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_jwt_config_validation_invalid_secret() {
        let config = JwtConfig {
            secret: "short".to_string(),
            access_token_expiration: 900,
            refresh_token_expiration: 604800,
            issuer: "test".to_string(),
        };
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidJwtSecret)
        ));
    }

    #[test]
    fn test_database_type_from_str() {
        assert_eq!(
            DatabaseType::from_str("redis").unwrap(),
            DatabaseType::Redis
        );
        assert!(DatabaseType::from_str("invalid").is_err());
    }

    #[test]
    fn test_database_type_display() {
        assert_eq!(DatabaseType::Redis.to_string(), "redis");
    }

    #[tokio::test]
    #[serial]
    async fn test_app_config_from_env_defaults() {
        setup_test_env();

        let config = AppConfig::from_env().await.unwrap();
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 3000);

        assert_eq!(config.jwt.access_token_expiration, 3600);
        assert_eq!(config.jwt.refresh_token_expiration, 25200);
        assert_eq!(config.jwt.issuer, "dbx");
        assert!(!config.create_default_admin);

        cleanup_test_env();
    }

    #[tokio::test]
    #[serial]
    async fn test_app_config_custom_values() {
        setup_test_env(); // Set up backend configuration first

        // Additional environment variables for this test
        env::set_var("HOST", "127.0.0.1");
        env::set_var("PORT", "8080");
        env::set_var("JWT_EXPIRATION_SECONDS", "1800");
        env::set_var("JWT_ISSUER", "test-issuer");
        env::set_var("CREATE_DEFAULT_ADMIN", "true");
        env::set_var("DEFAULT_ADMIN_USERNAME", "testadmin");
        env::set_var("DEFAULT_ADMIN_PASSWORD", "testpassword123");

        let config = AppConfig::from_env().await.unwrap();
        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 8080);

        assert_eq!(config.jwt.access_token_expiration, 1800);
        assert_eq!(config.jwt.refresh_token_expiration, 12600); // 1800 * 7
        assert_eq!(config.jwt.issuer, "test-issuer");
        assert!(config.create_default_admin);
        assert_eq!(config.default_admin_username, Some("testadmin".to_string()));
        assert_eq!(
            config.default_admin_password,
            Some("testpassword123".to_string())
        );

        cleanup_test_env();
    }

    #[tokio::test]
    #[serial]
    async fn test_app_config_missing_jwt_secret() {
        env::remove_var("JWT_SECRET");
        // Ensure backend config is still set
        env::set_var("DBX_BACKEND_1_URL", "mock://localhost:6379");
        env::set_var("DBX_BACKEND_1_PROVIDER", "mock");
        env::set_var("DBX_BACKEND_1_NAME", "test_backend");
        env::set_var("DBX_BACKEND_1_POOL_SIZE", "10");
        env::set_var("DBX_DEFAULT_BACKEND", "test_backend");

        let result = AppConfig::from_env().await;
        assert!(matches!(
            result,
            Err(ConfigError::MissingEnvironmentVariable(_))
        ));

        cleanup_test_env();
    }

    #[tokio::test]
    #[serial]
    async fn test_app_config_invalid_port() {
        setup_test_env();
        env::set_var("PORT", "invalid_port");

        let result = AppConfig::from_env().await;
        assert!(matches!(result, Err(ConfigError::DbxConfig(_))));

        cleanup_test_env();
    }

    #[tokio::test]
    #[serial]
    async fn test_app_config_create_admin_without_password() {
        setup_test_env();
        env::set_var("CREATE_DEFAULT_ADMIN", "true");
        env::set_var("DEFAULT_ADMIN_USERNAME", "admin");
        // Don't set DEFAULT_ADMIN_PASSWORD

        let result = AppConfig::from_env().await;
        assert!(matches!(
            result,
            Err(ConfigError::MissingDefaultAdminPassword)
        ));

        cleanup_test_env();
    }

    #[tokio::test]
    #[serial]
    async fn test_app_config_short_jwt_secret() {
        setup_test_env();
        env::set_var("JWT_SECRET", "short");

        let result = AppConfig::from_env().await;
        assert!(matches!(result, Err(ConfigError::InvalidJwtSecret)));

        cleanup_test_env();
    }
}
