use std::net::SocketAddr;

use dbx_redis_api::{config::{Config, JwtConfig}, constants::defaults::Defaults, server::Server};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load environment variables from .env file
    dotenv::dotenv().ok();

    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Load configuration from environment variables
    let config = Config {
        database_url: std::env::var("REDIS_URL")
            .unwrap_or_else(|_| Defaults::REDIS_URL.to_string()),
        host: std::env::var("HOST").unwrap_or_else(|_| Defaults::HOST.to_string()),
        port: std::env::var("PORT")
            .unwrap_or_else(|_| Defaults::PORT.to_string())
            .parse()
            .unwrap_or(Defaults::PORT),
        pool_size: std::env::var("POOL_SIZE")
            .unwrap_or_else(|_| Defaults::POOL_SIZE.to_string())
            .parse()
            .unwrap_or(Defaults::POOL_SIZE),
        jwt: JwtConfig {
            secret: std::env::var("JWT_SECRET")
                .unwrap_or_else(|_| Defaults::JWT_SECRET.to_string()),
            access_token_expiration: std::env::var("JWT_ACCESS_TOKEN_EXPIRATION")
                .unwrap_or_else(|_| Defaults::JWT_ACCESS_TOKEN_EXPIRATION.to_string())
                .parse()
                .unwrap_or(Defaults::JWT_ACCESS_TOKEN_EXPIRATION),
            refresh_token_expiration: std::env::var("JWT_REFRESH_TOKEN_EXPIRATION")
                .unwrap_or_else(|_| Defaults::JWT_REFRESH_TOKEN_EXPIRATION.to_string())
                .parse()
                .unwrap_or(Defaults::JWT_REFRESH_TOKEN_EXPIRATION),
            issuer: std::env::var("JWT_ISSUER")
                .unwrap_or_else(|_| Defaults::JWT_ISSUER.to_string()),
        },
    };

    // Create and run server
    let server = Server::new(config.clone()).await?;
    let addr = format!("{}:{}", config.host, config.port).parse::<SocketAddr>()?;

    server.run(addr).await?;

    Ok(())
}
