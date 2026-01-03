//! Security utilities for memory protection and secure handling
//!
//! This module provides:
//! - Memory zeroization to securely erase sensitive data
//! - Memory locking to prevent swap
//! - Secure memory allocation

pub mod mlock;
pub mod zeroize;

pub use mlock::{can_lock_memory, setup_memory_protection, LockedMemory};
pub use zeroize::{new_secret_key, SecretKey, SecureBytes, SecureString};
