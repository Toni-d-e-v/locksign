//! Error types for locksign

use thiserror::Error;

/// Main error type for locksign operations
#[derive(Error, Debug)]
pub enum LockSignError {
    // Key management errors
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Key already exists: {0}")]
    KeyAlreadyExists(String),

    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

    #[error("Key is disabled: {0}")]
    KeyDisabled(String),

    // Cryptographic errors
    #[error("Signing failed: {0}")]
    SigningFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    // Policy errors
    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    #[error("Rate limit exceeded: {0}")]
    RateLimitExceeded(String),

    #[error("Address not in allowlist: {0}")]
    AddressNotAllowed(String),

    #[error("Value exceeds limit: requested {requested}, max {max}")]
    ValueLimitExceeded { requested: String, max: String },

    #[error("2FA required but not provided")]
    TwoFactorRequired,

    #[error("Invalid 2FA token")]
    InvalidTwoFactor,

    // Storage errors
    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Failed to load keys: {0}")]
    KeyLoadFailed(String),

    #[error("Failed to save keys: {0}")]
    KeySaveFailed(String),

    // Security errors
    #[error("Memory lock failed: {0}")]
    MemoryLockFailed(String),

    #[error("Security violation: {0}")]
    SecurityViolation(String),

    // Chain-specific errors
    #[error("Unsupported chain: {0}")]
    UnsupportedChain(String),

    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    #[error("Ethereum error: {0}")]
    EthereumError(String),

    #[error("Solana error: {0}")]
    SolanaError(String),

    // Configuration errors
    #[error("Configuration error: {0}")]
    ConfigError(String),

    // Internal errors
    #[error("Internal error: {0}")]
    InternalError(String),
}

impl From<std::io::Error> for LockSignError {
    fn from(err: std::io::Error) -> Self {
        LockSignError::StorageError(err.to_string())
    }
}

impl From<serde_json::Error> for LockSignError {
    fn from(err: serde_json::Error) -> Self {
        LockSignError::StorageError(format!("JSON error: {}", err))
    }
}

impl From<hex::FromHexError> for LockSignError {
    fn from(err: hex::FromHexError) -> Self {
        LockSignError::InvalidKeyFormat(format!("Hex decode error: {}", err))
    }
}

/// Convert LockSignError to tonic::Status for gRPC responses
impl From<LockSignError> for tonic::Status {
    fn from(err: LockSignError) -> Self {
        match err {
            LockSignError::KeyNotFound(_) => tonic::Status::not_found(err.to_string()),
            LockSignError::KeyAlreadyExists(_) => {
                tonic::Status::already_exists(err.to_string())
            }
            LockSignError::PolicyViolation(_)
            | LockSignError::RateLimitExceeded(_)
            | LockSignError::AddressNotAllowed(_)
            | LockSignError::ValueLimitExceeded { .. }
            | LockSignError::TwoFactorRequired
            | LockSignError::InvalidTwoFactor => {
                tonic::Status::permission_denied(err.to_string())
            }
            LockSignError::InvalidKeyFormat(_)
            | LockSignError::InvalidTransaction(_)
            | LockSignError::InvalidSignature(_) => {
                tonic::Status::invalid_argument(err.to_string())
            }
            LockSignError::KeyDisabled(_) => {
                tonic::Status::failed_precondition(err.to_string())
            }
            LockSignError::UnsupportedChain(_) => {
                tonic::Status::unimplemented(err.to_string())
            }
            _ => tonic::Status::internal(err.to_string()),
        }
    }
}

pub type Result<T> = std::result::Result<T, LockSignError>;
