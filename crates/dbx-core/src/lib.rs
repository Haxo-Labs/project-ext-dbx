//! # DBX Core
//!
//! Core types and traits for DBX universal database API.
//! This crate provides the foundational abstractions for database-agnostic operations.

pub mod backends;
pub mod error;
pub mod operations;
pub mod types;

pub use backends::*;
pub use error::*;
pub use operations::*;
pub use types::*;
