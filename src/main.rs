//! locksign - Secure, in-memory blockchain signing service
//!
//! A self-hosted signing service for Ethereum and Solana that:
//! - Stores encrypted private keys on disk
//! - Decrypts keys only in memory at startup
//! - Exposes a gRPC interface for policy-controlled signing
//!
//! # Security
//!
//! - Keys are encrypted at rest using AES-256-GCM with Argon2id key derivation
//! - Decrypted keys are held in memory-locked pages to prevent swapping
//! - All sensitive memory is zeroed on drop
//! - Policy enforcement prevents unauthorized signing
//!
//! # Usage
//!
//! ```bash
//! # Start the server
//! LOCKSIGN_MASTER_PASSWORD=your_password locksign
//!
//! # Or with a config file
//! locksign --config /etc/locksign/config.toml
//! ```

mod api;
mod config;
mod crypto;
mod errors;
mod keystore;
mod policy;
mod security;
mod signer;

use crate::api::grpc::proto::ethereum::ethereum_signer_server::EthereumSignerServer;
use crate::api::grpc::proto::solana::solana_signer_server::SolanaSignerServer;
use crate::api::{AppState, AuthService, EthereumSignerService, SolanaSignerService};
use crate::config::Config;
use crate::errors::Result;
use crate::keystore::{KeyLoader, MemoryKeyStore};
use crate::policy::PolicyEngine;
use crate::security::setup_memory_protection;
use std::env;
use std::sync::Arc;
use tonic::transport::Server;
use tracing::{error, info, warn};

/// Application version
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    init_logging();

    info!("Starting locksign v{}", VERSION);

    // Set up memory protection (disable core dumps, etc.)
    if let Err(e) = setup_memory_protection() {
        warn!("Could not set up memory protection: {}", e);
    }

    // Load configuration
    let config_path = env::args().nth(2); // --config path
    let config = Config::load(config_path.as_deref())?;
    config.validate()?;

    info!("Configuration loaded");

    // Get master password
    let master_password = get_master_password(&config)?;

    // Initialize components
    let key_store = Arc::new(MemoryKeyStore::new());
    let key_loader = Arc::new(KeyLoader::new(&config.storage.keystore_path, key_store.clone())?);

    // Load keys from encrypted storage
    info!("Loading keys from {:?}", config.storage.keystore_path);
    match key_loader.load_all_keys(&master_password) {
        Ok(keys) => {
            info!("Loaded {} keys into memory", keys.len());
        }
        Err(e) => {
            if config.security.require_master_password {
                error!("Failed to load keys: {}", e);
                return Err(e);
            } else {
                warn!("Could not load keys: {} (continuing without keys)", e);
            }
        }
    }

    // Initialize policy engine
    let mut policy_engine = PolicyEngine::new(config.policy.enabled);
    if let Some(rules_path) = &config.policy.rules_path {
        if rules_path.exists() {
            if let Err(e) = policy_engine.load_from_file(rules_path) {
                warn!("Could not load policy rules: {}", e);
            }
        }
    }
    let policy_engine = Arc::new(policy_engine);

    // Initialize auth service
    let auth_service = Arc::new(AuthService::new(false)); // Disabled for now

    // Create application state
    let state = Arc::new(AppState::new(
        key_store,
        key_loader,
        policy_engine,
        auth_service,
    ));

    // Build gRPC server
    let addr = config.server_addr().parse().map_err(|e| {
        crate::errors::LockSignError::ConfigError(format!("Invalid address: {}", e))
    })?;

    info!("Starting gRPC server on {}", addr);

    // Create services
    let eth_service = EthereumSignerService::new(state.clone());
    let sol_service = SolanaSignerService::new(state.clone());

    // Build and run server
    Server::builder()
        .add_service(EthereumSignerServer::new(eth_service))
        .add_service(SolanaSignerServer::new(sol_service))
        .serve_with_shutdown(addr, shutdown_signal())
        .await
        .map_err(|e| crate::errors::LockSignError::InternalError(e.to_string()))?;

    info!("Server shut down gracefully");
    Ok(())
}

/// Initialize logging
fn init_logging() {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer())
        .init();
}

/// Get master password from environment or prompt
fn get_master_password(config: &Config) -> Result<String> {
    // Try environment variable first
    if let Ok(password) = env::var("LOCKSIGN_MASTER_PASSWORD") {
        info!("Using master password from environment");
        return Ok(password);
    }

    // If not required, return empty
    if !config.security.require_master_password {
        warn!("No master password provided, keys will not be loaded");
        return Ok(String::new());
    }

    // In a real implementation, we'd prompt for password here
    // For now, we'll require the environment variable
    Err(crate::errors::LockSignError::ConfigError(
        "LOCKSIGN_MASTER_PASSWORD environment variable not set".to_string(),
    ))
}

/// Wait for shutdown signal
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C, shutting down...");
        }
        _ = terminate => {
            info!("Received SIGTERM, shutting down...");
        }
    }
}
