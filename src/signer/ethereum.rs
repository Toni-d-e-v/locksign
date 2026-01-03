//! Ethereum signer service
//!
//! Handles Ethereum transaction and message signing with policy enforcement.

use crate::crypto::{hash_message, keccak256, EthSignature};
use crate::errors::{LockSignError, Result};
use crate::keystore::MemoryKeyStore;
use crate::policy::{PolicyEngine, SigningContext};
use std::sync::Arc;
use tracing::{debug, info};

/// Ethereum signer service
pub struct EthereumSigner {
    key_store: Arc<MemoryKeyStore>,
    policy_engine: Arc<PolicyEngine>,
}

impl EthereumSigner {
    /// Create a new Ethereum signer
    pub fn new(key_store: Arc<MemoryKeyStore>, policy_engine: Arc<PolicyEngine>) -> Self {
        Self {
            key_store,
            policy_engine,
        }
    }

    /// Sign an arbitrary message (EIP-191 personal sign)
    pub fn sign_message(
        &self,
        key_id: &str,
        request_id: &str,
        message: &[u8],
    ) -> Result<EthSignature> {
        // Create signing context
        let ctx = SigningContext::new(key_id, request_id, "ethereum");

        // Evaluate policy
        let result = self.policy_engine.evaluate(&ctx)?;
        if !result.allowed {
            return Err(LockSignError::PolicyViolation(
                result.violations.join(", "),
            ));
        }

        // Sign
        let signature = self.key_store.sign_ethereum_message(key_id, message)?;

        // Record signing
        self.policy_engine.record_signing(&ctx)?;

        info!(
            "Signed Ethereum message: key={}, request={}",
            key_id, request_id
        );
        Ok(signature)
    }

    /// Sign a hash (32 bytes)
    pub fn sign_hash(
        &self,
        key_id: &str,
        request_id: &str,
        hash: &[u8; 32],
    ) -> Result<EthSignature> {
        let ctx = SigningContext::new(key_id, request_id, "ethereum");

        let result = self.policy_engine.evaluate(&ctx)?;
        if !result.allowed {
            return Err(LockSignError::PolicyViolation(
                result.violations.join(", "),
            ));
        }

        let signature = self.key_store.sign_ethereum_hash(key_id, hash)?;

        self.policy_engine.record_signing(&ctx)?;

        debug!(
            "Signed Ethereum hash: key={}, request={}",
            key_id, request_id
        );
        Ok(signature)
    }

    /// Sign a legacy transaction
    pub fn sign_legacy_transaction(
        &self,
        key_id: &str,
        request_id: &str,
        tx: &LegacyTransaction,
    ) -> Result<SignedTransaction> {
        // Create context with transaction details
        let mut ctx = SigningContext::new(key_id, request_id, "ethereum");
        if let Some(to) = &tx.to {
            ctx = ctx.with_address(&hex::encode(to));
        }
        ctx = ctx.with_value(tx.value);

        // Evaluate policy
        let result = self.policy_engine.evaluate(&ctx)?;
        if !result.allowed {
            return Err(LockSignError::PolicyViolation(
                result.violations.join(", "),
            ));
        }

        // RLP encode transaction for signing
        let unsigned_rlp = tx.rlp_unsigned();
        let hash = keccak256(&unsigned_rlp);

        // Sign
        let signature = self.key_store.sign_ethereum_hash(key_id, &hash)?;

        // Create signed transaction
        let signed_tx = SignedTransaction {
            tx: tx.clone(),
            v: signature.v_eip155(tx.chain_id),
            r: signature.r.clone(),
            s: signature.s.clone(),
        };

        // Record signing
        self.policy_engine.record_signing(&ctx)?;

        info!(
            "Signed Ethereum legacy tx: key={}, request={}, to={:?}, value={}",
            key_id,
            request_id,
            tx.to.as_ref().map(hex::encode),
            tx.value
        );

        Ok(signed_tx)
    }

    /// Get the Ethereum address for a key
    pub fn get_address(&self, key_id: &str) -> Result<String> {
        self.key_store.get_ethereum_address(key_id)
    }
}

/// Legacy Ethereum transaction
#[derive(Debug, Clone)]
pub struct LegacyTransaction {
    pub nonce: u64,
    pub gas_price: u128,
    pub gas_limit: u64,
    pub to: Option<[u8; 20]>,
    pub value: u128,
    pub data: Vec<u8>,
    pub chain_id: u64,
}

impl LegacyTransaction {
    /// RLP encode for signing (EIP-155)
    pub fn rlp_unsigned(&self) -> Vec<u8> {
        let mut stream = rlp::RlpStream::new();
        stream.begin_unbounded_list();

        stream.append(&self.nonce);
        stream.append(&self.gas_price);
        stream.append(&self.gas_limit);

        if let Some(to) = &self.to {
            stream.append(&to.as_slice());
        } else {
            stream.append(&"");
        }

        stream.append(&self.value);
        stream.append(&self.data);

        // EIP-155: append chain_id, 0, 0
        stream.append(&self.chain_id);
        stream.append(&0u8);
        stream.append(&0u8);

        stream.finalize_unbounded_list();
        stream.out().to_vec()
    }
}

/// Signed Ethereum transaction
#[derive(Debug, Clone)]
pub struct SignedTransaction {
    pub tx: LegacyTransaction,
    pub v: u64,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
}

impl SignedTransaction {
    /// RLP encode signed transaction
    pub fn rlp_signed(&self) -> Vec<u8> {
        let mut stream = rlp::RlpStream::new();
        stream.begin_unbounded_list();

        stream.append(&self.tx.nonce);
        stream.append(&self.tx.gas_price);
        stream.append(&self.tx.gas_limit);

        if let Some(to) = &self.tx.to {
            stream.append(&to.as_slice());
        } else {
            stream.append(&"");
        }

        stream.append(&self.tx.value);
        stream.append(&self.tx.data);

        stream.append(&self.v);
        stream.append(&self.r.as_slice());
        stream.append(&self.s.as_slice());

        stream.finalize_unbounded_list();
        stream.out().to_vec()
    }

    /// Get transaction hash
    pub fn tx_hash(&self) -> [u8; 32] {
        keccak256(&self.rlp_signed())
    }

    /// Get transaction hash as hex string
    pub fn tx_hash_hex(&self) -> String {
        format!("0x{}", hex::encode(self.tx_hash()))
    }
}

// Note: We'll add RLP crate dependency
// For now, using a simple placeholder

mod rlp {
    pub struct RlpStream {
        buffer: Vec<u8>,
    }

    impl RlpStream {
        pub fn new() -> Self {
            Self { buffer: Vec::new() }
        }

        pub fn begin_unbounded_list(&mut self) {
            // Placeholder - in real impl, this would start RLP list encoding
        }

        pub fn append<T: Encodable>(&mut self, value: &T) -> &mut Self {
            value.rlp_append(&mut self.buffer);
            self
        }

        pub fn finalize_unbounded_list(&mut self) {
            // Placeholder - finalize RLP list
        }

        pub fn out(&self) -> &[u8] {
            &self.buffer
        }
    }

    pub trait Encodable {
        fn rlp_append(&self, buffer: &mut Vec<u8>);
    }

    impl Encodable for u64 {
        fn rlp_append(&self, buffer: &mut Vec<u8>) {
            // Simple RLP encoding for u64
            if *self == 0 {
                buffer.push(0x80);
            } else if *self < 128 {
                buffer.push(*self as u8);
            } else {
                let bytes = self.to_be_bytes();
                let start = bytes.iter().position(|&b| b != 0).unwrap_or(8);
                let len = 8 - start;
                buffer.push(0x80 + len as u8);
                buffer.extend_from_slice(&bytes[start..]);
            }
        }
    }

    impl Encodable for u128 {
        fn rlp_append(&self, buffer: &mut Vec<u8>) {
            if *self == 0 {
                buffer.push(0x80);
            } else if *self < 128 {
                buffer.push(*self as u8);
            } else {
                let bytes = self.to_be_bytes();
                let start = bytes.iter().position(|&b| b != 0).unwrap_or(16);
                let len = 16 - start;
                buffer.push(0x80 + len as u8);
                buffer.extend_from_slice(&bytes[start..]);
            }
        }
    }

    impl Encodable for u8 {
        fn rlp_append(&self, buffer: &mut Vec<u8>) {
            if *self == 0 {
                buffer.push(0x80);
            } else if *self < 128 {
                buffer.push(*self);
            } else {
                buffer.push(0x81);
                buffer.push(*self);
            }
        }
    }

    impl Encodable for &str {
        fn rlp_append(&self, buffer: &mut Vec<u8>) {
            let bytes = self.as_bytes();
            if bytes.is_empty() {
                buffer.push(0x80);
            } else if bytes.len() == 1 && bytes[0] < 128 {
                buffer.push(bytes[0]);
            } else if bytes.len() < 56 {
                buffer.push(0x80 + bytes.len() as u8);
                buffer.extend_from_slice(bytes);
            } else {
                // Long string encoding
                let len_bytes = bytes.len().to_be_bytes();
                let start = len_bytes.iter().position(|&b| b != 0).unwrap_or(8);
                buffer.push(0xb7 + (8 - start) as u8);
                buffer.extend_from_slice(&len_bytes[start..]);
                buffer.extend_from_slice(bytes);
            }
        }
    }

    impl Encodable for &[u8] {
        fn rlp_append(&self, buffer: &mut Vec<u8>) {
            if self.is_empty() {
                buffer.push(0x80);
            } else if self.len() == 1 && self[0] < 128 {
                buffer.push(self[0]);
            } else if self.len() < 56 {
                buffer.push(0x80 + self.len() as u8);
                buffer.extend_from_slice(self);
            } else {
                let len_bytes = self.len().to_be_bytes();
                let start = len_bytes.iter().position(|&b| b != 0).unwrap_or(8);
                buffer.push(0xb7 + (8 - start) as u8);
                buffer.extend_from_slice(&len_bytes[start..]);
                buffer.extend_from_slice(self);
            }
        }
    }

    impl Encodable for Vec<u8> {
        fn rlp_append(&self, buffer: &mut Vec<u8>) {
            self.as_slice().rlp_append(buffer);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::MemoryKeyStore;
    use crate::policy::PolicyEngine;

    #[test]
    fn test_sign_message() {
        let key_store = Arc::new(MemoryKeyStore::new());
        let policy_engine = Arc::new(PolicyEngine::new(false));

        // Load a test key
        let private_key = [1u8; 32];
        key_store
            .load_ethereum_key("test_key", &private_key, 0)
            .unwrap();

        let signer = EthereumSigner::new(key_store, policy_engine);

        let sig = signer
            .sign_message("test_key", "req1", b"Hello, Ethereum!")
            .unwrap();

        assert_eq!(sig.r.len(), 32);
        assert_eq!(sig.s.len(), 32);
    }

    #[test]
    fn test_get_address() {
        let key_store = Arc::new(MemoryKeyStore::new());
        let policy_engine = Arc::new(PolicyEngine::new(false));

        let private_key = [1u8; 32];
        key_store
            .load_ethereum_key("test_key", &private_key, 0)
            .unwrap();

        let signer = EthereumSigner::new(key_store, policy_engine);

        let address = signer.get_address("test_key").unwrap();
        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42);
    }
}
