pub mod auth;
pub mod batch;
pub mod client;
pub mod data;
pub mod error;
pub mod types;
pub mod utils;

// Re-export main types for external use
pub use client::DbxClient;
pub use error::DbxError;
pub use types::{
    DbxApiKey, DbxBatchOperation, DbxConfig, DbxQueryResponse, DbxQueryResult, DbxRateLimitPolicy,
    DbxRateLimitStatus, DbxResponse, DbxRole, DbxStreamConfig, DbxSystemHealth,
    DbxUserRoleAssignment, DbxWebSocketConfig,
};
