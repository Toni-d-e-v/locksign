//! Solana signer service
//!
//! Handles Solana transaction and message signing with policy enforcement.

use crate::crypto::SolSignature;
use crate::errors::{LockSignError, Result};
use crate::keystore::MemoryKeyStore;
use crate::policy::{PolicyEngine, SigningContext};
use std::sync::Arc;
use tracing::{debug, info};

/// Solana signer service
pub struct SolanaSigner {
    key_store: Arc<MemoryKeyStore>,
    policy_engine: Arc<PolicyEngine>,
}

impl SolanaSigner {
    /// Create a new Solana signer
    pub fn new(key_store: Arc<MemoryKeyStore>, policy_engine: Arc<PolicyEngine>) -> Self {
        Self {
            key_store,
            policy_engine,
        }
    }

    /// Sign an arbitrary message
    pub fn sign_message(
        &self,
        key_id: &str,
        request_id: &str,
        message: &[u8],
    ) -> Result<SolSignature> {
        // Create signing context
        let ctx = SigningContext::new(key_id, request_id, "solana");

        // Evaluate policy
        let result = self.policy_engine.evaluate(&ctx)?;
        if !result.allowed {
            return Err(LockSignError::PolicyViolation(
                result.violations.join(", "),
            ));
        }

        // Sign
        let signature = self.key_store.sign_solana_message(key_id, message)?;

        // Record signing
        self.policy_engine.record_signing(&ctx)?;

        info!(
            "Signed Solana message: key={}, request={}",
            key_id, request_id
        );
        Ok(signature)
    }

    /// Sign a serialized transaction
    ///
    /// The transaction should be serialized without signatures.
    /// This method signs the message portion of the transaction.
    pub fn sign_transaction(
        &self,
        key_id: &str,
        request_id: &str,
        transaction_message: &[u8],
    ) -> Result<SolSignature> {
        // Create signing context
        // Note: In a full implementation, we'd parse the transaction to extract
        // destination addresses and amounts for policy evaluation
        let ctx = SigningContext::new(key_id, request_id, "solana");

        // Evaluate policy
        let result = self.policy_engine.evaluate(&ctx)?;
        if !result.allowed {
            return Err(LockSignError::PolicyViolation(
                result.violations.join(", "),
            ));
        }

        // Sign the transaction message
        let signature = self.key_store.sign_solana_message(key_id, transaction_message)?;

        // Record signing
        self.policy_engine.record_signing(&ctx)?;

        info!(
            "Signed Solana transaction: key={}, request={}",
            key_id, request_id
        );
        Ok(signature)
    }

    /// Partially sign a transaction (for multi-sig scenarios)
    ///
    /// This adds a signature to a transaction that may already have other signatures.
    pub fn partial_sign(
        &self,
        key_id: &str,
        request_id: &str,
        transaction_message: &[u8],
    ) -> Result<SolSignature> {
        // Same as sign_transaction for now
        // In a full implementation, this would handle multi-sig logic
        self.sign_transaction(key_id, request_id, transaction_message)
    }

    /// Get the public key for a key (base58 encoded)
    pub fn get_public_key(&self, key_id: &str) -> Result<String> {
        self.key_store.get_solana_pubkey(key_id)
    }

    /// Get the public key bytes for a key
    pub fn get_public_key_bytes(&self, key_id: &str) -> Result<[u8; 32]> {
        self.key_store.get_solana_pubkey_bytes(key_id)
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
        let private_key = [2u8; 32];
        key_store
            .load_solana_key("test_key", &private_key, 0)
            .unwrap();

        let signer = SolanaSigner::new(key_store, policy_engine);

        let sig = signer
            .sign_message("test_key", "req1", b"Hello, Solana!")
            .unwrap();

        assert_eq!(sig.bytes.len(), 64);
    }

    #[test]
    fn test_get_public_key() {
        let key_store = Arc::new(MemoryKeyStore::new());
        let policy_engine = Arc::new(PolicyEngine::new(false));

        let private_key = [2u8; 32];
        key_store
            .load_solana_key("test_key", &private_key, 0)
            .unwrap();

        let signer = SolanaSigner::new(key_store, policy_engine);

        let pubkey = signer.get_public_key("test_key").unwrap();
        assert!(!pubkey.is_empty());

        // Base58 pubkey should be around 32-44 characters
        assert!(pubkey.len() >= 32 && pubkey.len() <= 44);
    }

    #[test]
    fn test_sign_transaction() {
        let key_store = Arc::new(MemoryKeyStore::new());
        let policy_engine = Arc::new(PolicyEngine::new(false));

        let private_key = [3u8; 32];
        key_store
            .load_solana_key("test_key", &private_key, 0)
            .unwrap();

        let signer = SolanaSigner::new(key_store, policy_engine);

        // Simulate a transaction message (in reality this would be a serialized transaction)
        let tx_message = vec![0u8; 100];
        let sig = signer
            .sign_transaction("test_key", "req1", &tx_message)
            .unwrap();

        assert_eq!(sig.bytes.len(), 64);
    }
}
