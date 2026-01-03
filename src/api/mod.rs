//! API layer for locksign
//!
//! Provides:
//! - gRPC service implementations
//! - Authentication middleware

pub mod auth;
pub mod grpc;

pub use auth::AuthService;
pub use grpc::{AppState, EthereumSignerService, HealthService, KeyManagementService, SolanaSignerService};
