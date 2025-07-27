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

pub use error::{RouterError, RouterResult};
pub use load_balancer::LoadBalancer;
pub use matcher::{
    BenchmarkResult, KeyMatcher, MatcherStats, OptimizedKeyMatcher, OptimizedMatcherStats,
};
pub use registry::{BackendRegistry, RegistryStats};
pub use router::{BackendRouter, LegacyBackendRouter, RouterBenchmarkResult, RouterStats};

// Re-export from dbx_core for convenience
pub use dbx_core::LoadBalancingStrategy;
