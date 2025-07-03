/// Default configuration values used throughout the application
pub struct Defaults;

impl Defaults {
    /// Default Redis URL for connection
    pub const REDIS_URL: &'static str = "redis://default:redispw@localhost:55000";

    /// Default server host address
    pub const HOST: &'static str = "0.0.0.0";

    /// Default server port
    pub const PORT: u16 = 3000;

    /// Default connection pool size
    pub const POOL_SIZE: u32 = 10;

    /// Default JWT secret
    pub const JWT_SECRET: &'static str = "dbx-jwt-secret";

    /// Default access token expiration (900 seconds = 15 minutes)
    pub const JWT_ACCESS_TOKEN_EXPIRATION: i64 = 900;

    /// Default refresh token expiration (7 days)
    pub const JWT_REFRESH_TOKEN_EXPIRATION: i64 = 604800;

    /// Default JWT issuer
    pub const JWT_ISSUER: &'static str = "dbx-api";
}
