//! Configuration management for locksign
//!
//! Supports loading configuration from:
//! - Environment variables (LOCKSIGN_*)
//! - Config file (config.toml)
//! - Command line (future)

use crate::errors::{LockSignError, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::info;

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Server configuration
    pub server: ServerConfig,

    /// Storage configuration
    pub storage: StorageConfig,

    /// Security configuration
    pub security: SecurityConfig,

    /// Policy configuration
    pub policy: PolicyConfig,

    /// Logging configuration
    pub logging: LoggingConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            storage: StorageConfig::default(),
            security: SecurityConfig::default(),
            policy: PolicyConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

/// Server (gRPC) configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Listen address for TCP
    pub listen_addr: String,

    /// Port number
    pub port: u16,

    /// Unix socket path (if using Unix sockets)
    pub unix_socket: Option<PathBuf>,

    /// Use Unix socket instead of TCP
    pub use_unix_socket: bool,

    /// Enable TLS
    pub tls_enabled: bool,

    /// TLS certificate path
    pub tls_cert: Option<PathBuf>,

    /// TLS key path
    pub tls_key: Option<PathBuf>,

    /// Max concurrent connections
    pub max_connections: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1".to_string(),
            port: 50051,
            unix_socket: Some(PathBuf::from("/var/run/locksign/locksign.sock")),
            use_unix_socket: false,
            tls_enabled: false,
            tls_cert: None,
            tls_key: None,
            max_connections: 100,
        }
    }
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Path to encrypted keystore directory
    pub keystore_path: PathBuf,

    /// Encryption algorithm (aes-256-gcm)
    pub encryption_algorithm: String,

    /// Key derivation iterations
    pub kdf_iterations: u32,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            keystore_path: PathBuf::from("./data/keys"),
            encryption_algorithm: "aes-256-gcm".to_string(),
            kdf_iterations: 100_000,
        }
    }
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable memory locking
    pub enable_mlock: bool,

    /// Disable core dumps
    pub disable_core_dumps: bool,

    /// Maximum key age in days (0 = no limit)
    pub max_key_age_days: u32,

    /// Require master password on startup
    pub require_master_password: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enable_mlock: true,
            disable_core_dumps: true,
            max_key_age_days: 0,
            require_master_password: true,
        }
    }
}

/// Policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Enable policy enforcement
    pub enabled: bool,

    /// Path to policy rules file
    pub rules_path: Option<PathBuf>,

    /// Default daily transaction limit (in smallest unit)
    pub default_daily_limit: u64,

    /// Require 2FA for transactions above this value
    pub require_2fa_above: Option<u64>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rules_path: Some(PathBuf::from("./config/policies.json")),
            default_daily_limit: 1_000_000_000_000_000_000, // 1 ETH in wei
            require_2fa_above: None,
        }
    }
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error)
    pub level: String,

    /// Log format (json, pretty)
    pub format: String,

    /// Log to file
    pub file: Option<PathBuf>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: "pretty".to_string(),
            file: None,
        }
    }
}

impl Config {
    /// Load configuration from file and environment
    pub fn load(config_path: Option<&str>) -> Result<Self> {
        let mut builder = config::Config::builder();

        // Start with defaults
        builder = builder.add_source(config::Config::try_from(&Config::default()).unwrap());

        // Load from file if specified
        if let Some(path) = config_path {
            builder = builder.add_source(config::File::with_name(path).required(false));
        } else {
            // Try default locations
            builder = builder
                .add_source(config::File::with_name("config").required(false))
                .add_source(config::File::with_name("/etc/locksign/config").required(false));
        }

        // Load from environment (LOCKSIGN_SERVER__PORT, etc.)
        builder = builder.add_source(
            config::Environment::with_prefix("LOCKSIGN")
                .separator("__")
                .try_parsing(true),
        );

        let config = builder
            .build()
            .map_err(|e| LockSignError::ConfigError(e.to_string()))?;

        config
            .try_deserialize()
            .map_err(|e| LockSignError::ConfigError(e.to_string()))
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        // Validate TLS config
        if self.server.tls_enabled {
            if self.server.tls_cert.is_none() || self.server.tls_key.is_none() {
                return Err(LockSignError::ConfigError(
                    "TLS enabled but cert/key not specified".to_string(),
                ));
            }
        }

        // Validate storage path
        if !self.storage.keystore_path.exists() {
            info!(
                "Keystore directory does not exist, will create: {:?}",
                self.storage.keystore_path
            );
        }

        Ok(())
    }

    /// Get the server address string
    pub fn server_addr(&self) -> String {
        format!("{}:{}", self.server.listen_addr, self.server.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.server.port, 50051);
        assert!(config.policy.enabled);
    }

    #[test]
    fn test_server_addr() {
        let config = Config::default();
        assert_eq!(config.server_addr(), "127.0.0.1:50051");
    }
}
