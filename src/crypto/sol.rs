//! Solana cryptographic utilities
//!
//! Provides:
//! - Ed25519 key generation
//! - Message signing
//! - Public key derivation

use crate::errors::{LockSignError, Result};
use crate::security::SecureBytes;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;

/// Solana key pair (Ed25519)
pub struct SolKeyPair {
    signing_key: SigningKey,
}

impl SolKeyPair {
    /// Create a new random key pair
    pub fn generate() -> Result<Self> {
        let signing_key = SigningKey::generate(&mut OsRng);
        Ok(Self { signing_key })
    }

    /// Create from raw private key bytes (32 bytes seed)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(LockSignError::InvalidKeyFormat(format!(
                "Expected 32 bytes seed, got {}",
                bytes.len()
            )));
        }

        let mut seed = [0u8; 32];
        seed.copy_from_slice(bytes);

        let signing_key = SigningKey::from_bytes(&seed);
        Ok(Self { signing_key })
    }

    /// Create from full 64-byte keypair (as used by Solana CLI)
    pub fn from_keypair_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 64 {
            return Err(LockSignError::InvalidKeyFormat(format!(
                "Expected 64 bytes keypair, got {}",
                bytes.len()
            )));
        }

        // First 32 bytes are the seed
        Self::from_bytes(&bytes[..32])
    }

    /// Get the public key (32 bytes)
    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Get the public key as base58 string (Solana address format)
    pub fn public_key_base58(&self) -> String {
        bs58::encode(self.public_key()).into_string()
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Result<SolSignature> {
        let signature = self.signing_key.sign(message);
        Ok(SolSignature {
            bytes: signature.to_bytes(),
        })
    }

    /// Export the private key seed (32 bytes) - use with caution!
    pub fn seed_bytes(&self) -> SecureBytes {
        SecureBytes::new(self.signing_key.to_bytes().to_vec())
    }

    /// Export the full keypair bytes (64 bytes: seed || pubkey)
    pub fn keypair_bytes(&self) -> SecureBytes {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&self.signing_key.to_bytes());
        bytes.extend_from_slice(&self.public_key());
        SecureBytes::new(bytes)
    }

    /// Get the verifying key for signature verification
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

impl Drop for SolKeyPair {
    fn drop(&mut self) {
        // SigningKey uses zeroize internally
    }
}

/// Solana signature (64 bytes)
#[derive(Clone)]
pub struct SolSignature {
    pub bytes: [u8; 64],
}

impl SolSignature {
    /// Get the signature bytes
    pub fn to_bytes(&self) -> [u8; 64] {
        self.bytes
    }

    /// Get as base58 string
    pub fn to_base58(&self) -> String {
        bs58::encode(&self.bytes).into_string()
    }

    /// Get as hex string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.bytes)
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 64 {
            return Err(LockSignError::InvalidSignature(format!(
                "Expected 64 bytes, got {}",
                bytes.len()
            )));
        }

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(bytes);
        Ok(Self { bytes: sig_bytes })
    }
}

/// Parse a base58-encoded public key
pub fn parse_pubkey(s: &str) -> Result<[u8; 32]> {
    let bytes = bs58::decode(s)
        .into_vec()
        .map_err(|e| LockSignError::InvalidKeyFormat(format!("Invalid base58: {}", e)))?;

    if bytes.len() != 32 {
        return Err(LockSignError::InvalidKeyFormat(format!(
            "Public key must be 32 bytes, got {}",
            bytes.len()
        )));
    }

    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes);
    Ok(result)
}

/// Verify a signature
pub fn verify_signature(pubkey: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<bool> {
    let verifying_key = VerifyingKey::from_bytes(pubkey)
        .map_err(|e| LockSignError::InvalidKeyFormat(e.to_string()))?;

    let sig = Signature::from_bytes(signature);

    Ok(verifying_key.verify_strict(message, &sig).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let keypair = SolKeyPair::generate().unwrap();
        let pubkey = keypair.public_key();
        assert_eq!(pubkey.len(), 32);

        let base58 = keypair.public_key_base58();
        assert!(!base58.is_empty());
    }

    #[test]
    fn test_signing() {
        let keypair = SolKeyPair::generate().unwrap();
        let message = b"Hello, Solana!";

        let sig = keypair.sign(message).unwrap();
        assert_eq!(sig.bytes.len(), 64);

        // Verify the signature
        let is_valid = verify_signature(&keypair.public_key(), message, &sig.bytes).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_from_bytes() {
        let keypair1 = SolKeyPair::generate().unwrap();
        let seed = keypair1.seed_bytes();

        let keypair2 = SolKeyPair::from_bytes(seed.expose()).unwrap();

        assert_eq!(keypair1.public_key(), keypair2.public_key());
    }

    #[test]
    fn test_pubkey_parsing() {
        let keypair = SolKeyPair::generate().unwrap();
        let base58 = keypair.public_key_base58();

        let parsed = parse_pubkey(&base58).unwrap();
        assert_eq!(parsed, keypair.public_key());
    }

    #[test]
    fn test_signature_verification_fails_for_wrong_message() {
        let keypair = SolKeyPair::generate().unwrap();
        let message = b"Hello, Solana!";
        let wrong_message = b"Wrong message";

        let sig = keypair.sign(message).unwrap();

        let is_valid = verify_signature(&keypair.public_key(), wrong_message, &sig.bytes).unwrap();
        assert!(!is_valid);
    }
}
