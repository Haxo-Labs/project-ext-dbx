//! DBX API test modules
//!
//! Tests are organized by functionality for maintainability and clarity.
//! Each module focuses on a specific aspect of the API implementation.

/// Shared test utilities and helper functions
pub mod utils;

/// Model serialization and validation tests  
mod model_tests;

/// Configuration and environment tests
mod config_tests;

/// Authentication and authorization tests
mod auth_tests;

/// Route handler tests
mod route_tests;

/// Server initialization and lifecycle tests
mod server_tests;

/// Middleware functionality tests
mod middleware_tests;

/// Main application tests
mod main_tests;
