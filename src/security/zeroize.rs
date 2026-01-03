//! Secure memory zeroization utilities
//!
//! This module provides utilities for securely zeroing memory containing
//! sensitive data like private keys. Uses the `zeroize` crate to ensure
//! compiler optimizations don't remove the zeroing operations.

use secrecy::{ExposeSecret, Secret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A wrapper for sensitive byte arrays that automatically zeros memory on drop
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecureBytes {
    inner: Vec<u8>,
}

impl SecureBytes {
    pub fn new(data: Vec<u8>) -> Self {
        Self { inner: data }
    }

    pub fn zeros(size: usize) -> Self {
        Self {
            inner: vec![0u8; size],
        }
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn expose(&self) -> &[u8] {
        &self.inner
    }

    pub fn expose_mut(&mut self) -> &mut [u8] {
        &mut self.inner
    }

    pub fn zeroize_now(&mut self) {
        self.inner.zeroize();
    }
}

impl From<Vec<u8>> for SecureBytes {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl From<&[u8]> for SecureBytes {
    fn from(data: &[u8]) -> Self {
        Self::new(data.to_vec())
    }
}

/// A secure string that zeros its memory on drop
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecureString {
    inner: String,
}

impl SecureString {
    pub fn new(s: String) -> Self {
        Self { inner: s }
    }

    pub fn expose(&self) -> &str {
        &self.inner
    }
}

impl From<String> for SecureString {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for SecureString {
    fn from(s: &str) -> Self {
        Self::new(s.to_string())
    }
}

/// Wrapper around secrecy::Secret for private keys
pub type SecretKey = Secret<Vec<u8>>;

pub fn new_secret_key(bytes: Vec<u8>) -> SecretKey {
    Secret::new(bytes)
}

pub fn secure_copy(src: &[u8], dst: &mut [u8]) {
    assert!(dst.len() >= src.len(), "Destination buffer too small");
    dst[..src.len()].copy_from_slice(src);
}

pub fn zeroize_slice(data: &mut [u8]) {
    data.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_bytes_zeroize() {
        let data = vec![1, 2, 3, 4, 5];
        let mut secure = SecureBytes::new(data);

        assert_eq!(secure.expose(), &[1, 2, 3, 4, 5]);

        secure.zeroize_now();
        // Vec::zeroize() clears the vector (sets len to 0) after zeroing memory
        assert!(secure.is_empty());
    }

    #[test]
    fn test_secure_bytes_manual_zeroize() {
        let mut secure = SecureBytes::zeros(5);
        secure.expose_mut().copy_from_slice(&[1, 2, 3, 4, 5]);
        assert_eq!(secure.expose(), &[1, 2, 3, 4, 5]);

        // Zero the contents manually using zeroize_slice
        zeroize_slice(secure.expose_mut());
        assert_eq!(secure.expose(), &[0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_secure_string() {
        let secret = SecureString::new("my_secret_password".to_string());
        assert_eq!(secret.expose(), "my_secret_password");
    }
}