//! PostgreSQL adapter test modules
//!
//! Tests are organized by functionality for maintainability and clarity.
//! Each module focuses on a specific aspect of the PostgreSQL adapter.

/// Shared test utilities and helper functions
pub mod utils;

/// Connection pool tests
mod connection_tests;

/// Backend implementation tests
mod backend_tests;

/// Factory implementation tests
mod factory_tests;

/// Data operation tests (CRUD)
mod data_operation_tests;

/// TTL functionality tests
mod ttl_tests;

/// Transaction and consistency tests
mod transaction_tests;

/// Error handling and edge case tests
mod error_handling_tests;

/// Performance and load tests
mod performance_tests;
