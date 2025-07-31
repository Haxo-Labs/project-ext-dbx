//! DBX Core test modules
//!
//! Tests are organized by functionality for maintainability and clarity.
//! Each module focuses on a specific aspect of the core implementation.

/// Shared test utilities and helper functions
pub mod utils;

/// Backend trait and capability tests
mod backend_tests;

/// Data operation tests
mod operation_tests;

/// Core type tests (DataValue, DataResult, etc.)
mod type_tests;

/// Error handling and error type tests
mod error_tests;
