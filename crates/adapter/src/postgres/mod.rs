//! PostgreSQL adapter module
//!
//! PostgreSQL database adapter implementation using deadpool-postgres
//! for high-performance async operations and connection pooling.

pub mod backend;
pub mod client;
pub mod factory;

#[cfg(test)]
mod tests;

// Re-export key types
pub use backend::PostgresBackend;
pub use client::PostgresConnectionPool;
pub use factory::PostgresBackendFactory;
