//! DBX Adapter library
//!
//! Database adapters and utilities for database interactions.

pub mod error;
pub mod postgres;
pub mod redis;
pub mod traits;

#[cfg(test)]
mod tests;

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Library name
pub const NAME: &str = env!("CARGO_PKG_NAME");
