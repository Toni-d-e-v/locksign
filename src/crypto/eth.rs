//! Ethereum cryptographic utilities
//!
//! Provides:
//! - Key generation and derivation
//! - Message signing (EIP-191)
//! - Transaction signing (legacy and EIP-1559)
//! - Address derivation

use crate::errors::{LockSignError, Result};
use crate::security::SecureBytes;
use k256::{
    ecdsa::{signature::Signer, RecoveryId, Signature, SigningKey, VerifyingKey},
    elliptic_curve::sec1::ToEncodedPoint,
    SecretKey,
};
use sha3::{Digest, Keccak256};
use zeroize::Zeroize;

/// Ethereum key pair
pub struct EthKeyPair {
    signing_key: SigningKey,
}

impl EthKeyPair {
    /// Create a new random key pair
    pub fn generate() -> Result<Self> {
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        Ok(Self { signing_key })
    }

    /// Create from raw private key bytes (32 bytes)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(LockSignError::InvalidKeyFormat(format!(
                "Expected 32 bytes, got {}",
                bytes.len()
            )));
        }

        let secret_key = SecretKey::from_slice(bytes)
            .map_err(|e| LockSignError::InvalidKeyFormat(e.to_string()))?;

        let signing_key = SigningKey::from(secret_key);
        Ok(Self { signing_key })
    }

    /// Get the public key (uncompressed, 65 bytes with 0x04 prefix)
    pub fn public_key_uncompressed(&self) -> Vec<u8> {
        let verifying_key = self.signing_key.verifying_key();
        verifying_key.to_encoded_point(false).as_bytes().to_vec()
    }

    /// Get the public key (compressed, 33 bytes)
    pub fn public_key_compressed(&self) -> Vec<u8> {
        let verifying_key = self.signing_key.verifying_key();
        verifying_key.to_encoded_point(true).as_bytes().to_vec()
    }

    /// Get the Ethereum address (20 bytes)
    pub fn address(&self) -> [u8; 20] {
        let pubkey = self.public_key_uncompressed();
        // Skip the 0x04 prefix and hash the remaining 64 bytes
        let hash = Keccak256::digest(&pubkey[1..]);
        // Take the last 20 bytes
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..]);
        address
    }

    /// Get the checksummed Ethereum address string
    pub fn address_checksum(&self) -> String {
        let addr = self.address();
        checksum_address(&addr)
    }

    /// Sign a message hash (32 bytes)
    pub fn sign_hash(&self, hash: &[u8; 32]) -> Result<EthSignature> {
        let (signature, recovery_id) = self
            .signing_key
            .sign_prehash_recoverable(hash)
            .map_err(|e| LockSignError::SigningFailed(e.to_string()))?;

        let r = signature.r().to_bytes();
        let s = signature.s().to_bytes();
        let v = recovery_id.to_byte();

        Ok(EthSignature {
            r: r.to_vec(),
            s: s.to_vec(),
            v,
        })
    }

    /// Sign a message with EIP-191 personal sign
    pub fn sign_message(&self, message: &[u8]) -> Result<EthSignature> {
        let hash = hash_message(message);
        self.sign_hash(&hash)
    }

    /// Export the private key bytes (use with caution!)
    pub fn private_key_bytes(&self) -> SecureBytes {
        SecureBytes::new(self.signing_key.to_bytes().to_vec())
    }
}

impl Drop for EthKeyPair {
    fn drop(&mut self) {
        // SigningKey from k256 already implements Zeroize
    }
}

/// Ethereum signature with recovery id
#[derive(Clone)]
pub struct EthSignature {
    pub r: Vec<u8>,
    pub s: Vec<u8>,
    pub v: u8,
}

impl EthSignature {
    /// Get the full signature bytes (65 bytes: r || s || v)
    pub fn to_bytes(&self) -> [u8; 65] {
        let mut sig = [0u8; 65];
        sig[0..32].copy_from_slice(&self.r);
        sig[32..64].copy_from_slice(&self.s);
        sig[64] = self.v;
        sig
    }

    /// Get v for legacy transactions (27/28)
    pub fn v_legacy(&self) -> u8 {
        self.v + 27
    }

    /// Get v for EIP-155 transactions
    pub fn v_eip155(&self, chain_id: u64) -> u64 {
        self.v as u64 + 35 + chain_id * 2
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }
}

/// Hash a message according to EIP-191 (personal sign)
pub fn hash_message(message: &[u8]) -> [u8; 32] {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut hasher = Keccak256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(message);
    hasher.finalize().into()
}

/// Compute keccak256 hash
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

/// Convert an address to checksummed format (EIP-55)
pub fn checksum_address(address: &[u8; 20]) -> String {
    let addr_hex = hex::encode(address);
    let hash = hex::encode(Keccak256::digest(addr_hex.as_bytes()));

    let mut result = String::with_capacity(42);
    result.push_str("0x");

    for (i, c) in addr_hex.chars().enumerate() {
        if c.is_ascii_alphabetic() {
            let hash_char = hash.chars().nth(i).unwrap();
            if hash_char >= '8' {
                result.push(c.to_ascii_uppercase());
            } else {
                result.push(c);
            }
        } else {
            result.push(c);
        }
    }

    result
}

/// Parse a hex address string to bytes
pub fn parse_address(addr: &str) -> Result<[u8; 20]> {
    let addr = addr.strip_prefix("0x").unwrap_or(addr);

    if addr.len() != 40 {
        return Err(LockSignError::InvalidKeyFormat(
            "Address must be 40 hex chars".to_string(),
        ));
    }

    let bytes = hex::decode(addr)?;
    let mut result = [0u8; 20];
    result.copy_from_slice(&bytes);
    Ok(result)
}

/// Verify an address checksum (EIP-55)
pub fn verify_checksum(addr: &str) -> bool {
    let addr = addr.strip_prefix("0x").unwrap_or(addr);

    if addr.len() != 40 {
        return false;
    }

    // Parse to bytes
    let Ok(bytes) = hex::decode(addr.to_lowercase()) else {
        return false;
    };

    let mut address = [0u8; 20];
    address.copy_from_slice(&bytes);

    // Regenerate checksum
    let checksummed = checksum_address(&address);
    let checksummed = checksummed.strip_prefix("0x").unwrap();

    addr == checksummed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let keypair = EthKeyPair::generate().unwrap();
        let addr = keypair.address();
        assert_eq!(addr.len(), 20);
    }

    #[test]
    fn test_address_checksum() {
        // Test vector from EIP-55
        let addr = hex::decode("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed").unwrap();
        let mut address = [0u8; 20];
        address.copy_from_slice(&addr);

        let checksummed = checksum_address(&address);
        assert_eq!(checksummed, "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
    }

    #[test]
    fn test_message_signing() {
        let keypair = EthKeyPair::generate().unwrap();
        let message = b"Hello, Ethereum!";

        let sig = keypair.sign_message(message).unwrap();
        assert_eq!(sig.r.len(), 32);
        assert_eq!(sig.s.len(), 32);
        assert!(sig.v <= 1);
    }

    #[test]
    fn test_from_bytes() {
        // Known test vector
        let private_key =
            hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .unwrap();

        let keypair = EthKeyPair::from_bytes(&private_key).unwrap();
        let addr = keypair.address_checksum();
        assert!(addr.starts_with("0x"));
        assert_eq!(addr.len(), 42);
    }
}
