//! # DBX Router
//!
//! Backend routing and operation dispatch for DBX.
//! This crate provides functionality to route operations to appropriate backends
//! based on configuration rules and load balancing strategies.

pub mod error;
pub mod load_balancer;
pub mod matcher;
pub mod registry;
pub mod router;

pub use error::*;
pub use load_balancer::*;
pub use matcher::*;
pub use registry::*;
pub use router::*;
