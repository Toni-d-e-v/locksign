//! Ethereum signer service
//!
//! Handles Ethereum transaction and message signing with policy enforcement.

use crate::crypto::{keccak256, EthSignature};
use crate::errors::{LockSignError, Result};
use crate::keystore::MemoryKeyStore;
use crate::policy::{PolicyEngine, SigningContext};
use rlp::RlpStream;
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
        let ctx = SigningContext::new(key_id, request_id, "ethereum");

        let result = self.policy_engine.evaluate(&ctx)?;
        if !result.allowed {
            return Err(LockSignError::PolicyViolation(
                result.violations.join(", "),
            ));
        }

        let signature = self.key_store.sign_ethereum_message(key_id, message)?;
        self.policy_engine.record_signing(&ctx)?;

        info!("Signed Ethereum message: key={}, request={}", key_id, request_id);
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

        debug!("Signed Ethereum hash: key={}, request={}", key_id, request_id);
        Ok(signature)
    }

    /// Sign a legacy transaction
    pub fn sign_legacy_transaction(
        &self,
        key_id: &str,
        request_id: &str,
        tx: &LegacyTransaction,
    ) -> Result<SignedTransaction> {
        let mut ctx = SigningContext::new(key_id, request_id, "ethereum");
        if let Some(to) = &tx.to {
            ctx = ctx.with_address(&hex::encode(to));
        }
        ctx = ctx.with_value(tx.value);

        let result = self.policy_engine.evaluate(&ctx)?;
        if !result.allowed {
            return Err(LockSignError::PolicyViolation(
                result.violations.join(", "),
            ));
        }

        let unsigned_rlp = tx.rlp_unsigned();
        let hash = keccak256(&unsigned_rlp);
        let signature = self.key_store.sign_ethereum_hash(key_id, &hash)?;

        let signed_tx = SignedTransaction {
            tx: tx.clone(),
            v: signature.v_eip155(tx.chain_id),
            r: signature.r.clone(),
            s: signature.s.clone(),
        };

        self.policy_engine.record_signing(&ctx)?;

        info!(
            "Signed Ethereum legacy tx: key={}, request={}, to={:?}, value={}",
            key_id, request_id, tx.to.as_ref().map(hex::encode), tx.value
        );

        Ok(signed_tx)
    }

    /// Sign an EIP-1559 transaction
    pub fn sign_eip1559_transaction(
        &self,
        key_id: &str,
        request_id: &str,
        tx: &EIP1559Transaction,
    ) -> Result<SignedEIP1559Transaction> {
        let mut ctx = SigningContext::new(key_id, request_id, "ethereum");
        if let Some(to) = &tx.to {
            ctx = ctx.with_address(&hex::encode(to));
        }
        ctx = ctx.with_value(tx.value);

        let result = self.policy_engine.evaluate(&ctx)?;
        if !result.allowed {
            return Err(LockSignError::PolicyViolation(
                result.violations.join(", "),
            ));
        }

        let unsigned_rlp = tx.rlp_unsigned();
        let hash = keccak256(&unsigned_rlp);
        let signature = self.key_store.sign_ethereum_hash(key_id, &hash)?;

        let signed_tx = SignedEIP1559Transaction {
            tx: tx.clone(),
            v: signature.v,
            r: signature.r.clone(),
            s: signature.s.clone(),
        };

        self.policy_engine.record_signing(&ctx)?;

        info!(
            "Signed Ethereum EIP-1559 tx: key={}, request={}, to={:?}, value={}",
            key_id, request_id, tx.to.as_ref().map(hex::encode), tx.value
        );

        Ok(signed_tx)
    }

    /// Get the Ethereum address for a key
    pub fn get_address(&self, key_id: &str) -> Result<String> {
        self.key_store.get_ethereum_address(key_id)
    }
}

// Helper functions for RLP encoding
fn u128_to_be_bytes_trimmed(value: u128) -> Vec<u8> {
    if value == 0 {
        return vec![];
    }
    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(16);
    bytes[start..].to_vec()
}

fn u64_to_be_bytes_trimmed(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![];
    }
    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(8);
    bytes[start..].to_vec()
}

/// Legacy Ethereum transaction (pre-EIP-1559)
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
    pub fn new(
        nonce: u64,
        gas_price: u128,
        gas_limit: u64,
        to: Option<[u8; 20]>,
        value: u128,
        data: Vec<u8>,
        chain_id: u64,
    ) -> Self {
        Self { nonce, gas_price, gas_limit, to, value, data, chain_id }
    }

    /// RLP encode for signing (EIP-155)
    pub fn rlp_unsigned(&self) -> Vec<u8> {
        let mut stream = RlpStream::new_list(9);
        
        stream.append(&u64_to_be_bytes_trimmed(self.nonce).as_slice());
        stream.append(&u128_to_be_bytes_trimmed(self.gas_price).as_slice());
        stream.append(&u64_to_be_bytes_trimmed(self.gas_limit).as_slice());
        
        match &self.to {
            Some(addr) => stream.append(&addr.as_slice()),
            None => stream.append_empty_data(),
        };
        
        stream.append(&u128_to_be_bytes_trimmed(self.value).as_slice());
        stream.append(&self.data);
        stream.append(&u64_to_be_bytes_trimmed(self.chain_id).as_slice());
        stream.append_empty_data();
        stream.append_empty_data();
        
        stream.out().to_vec()
    }
}

/// Signed legacy Ethereum transaction
#[derive(Debug, Clone)]
pub struct SignedTransaction {
    pub tx: LegacyTransaction,
    pub v: u64,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
}

impl SignedTransaction {
    pub fn rlp_signed(&self) -> Vec<u8> {
        let mut stream = RlpStream::new_list(9);
        
        stream.append(&u64_to_be_bytes_trimmed(self.tx.nonce).as_slice());
        stream.append(&u128_to_be_bytes_trimmed(self.tx.gas_price).as_slice());
        stream.append(&u64_to_be_bytes_trimmed(self.tx.gas_limit).as_slice());
        
        match &self.tx.to {
            Some(addr) => stream.append(&addr.as_slice()),
            None => stream.append_empty_data(),
        };
        
        stream.append(&u128_to_be_bytes_trimmed(self.tx.value).as_slice());
        stream.append(&self.tx.data);
        stream.append(&u64_to_be_bytes_trimmed(self.v).as_slice());
        stream.append(&self.r.as_slice());
        stream.append(&self.s.as_slice());
        
        stream.out().to_vec()
    }

    pub fn tx_hash(&self) -> [u8; 32] {
        keccak256(&self.rlp_signed())
    }

    pub fn tx_hash_hex(&self) -> String {
        format!("0x{}", hex::encode(self.tx_hash()))
    }

    pub fn raw_tx_hex(&self) -> String {
        format!("0x{}", hex::encode(self.rlp_signed()))
    }
}

/// EIP-1559 transaction
#[derive(Debug, Clone)]
pub struct EIP1559Transaction {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    pub to: Option<[u8; 20]>,
    pub value: u128,
    pub data: Vec<u8>,
    pub access_list: Vec<AccessListItem>,
}

#[derive(Debug, Clone)]
pub struct AccessListItem {
    pub address: [u8; 20],
    pub storage_keys: Vec<[u8; 32]>,
}

impl EIP1559Transaction {
    pub fn rlp_unsigned(&self) -> Vec<u8> {
        let mut stream = RlpStream::new_list(9);
        
        stream.append(&u64_to_be_bytes_trimmed(self.chain_id).as_slice());
        stream.append(&u64_to_be_bytes_trimmed(self.nonce).as_slice());
        stream.append(&u128_to_be_bytes_trimmed(self.max_priority_fee_per_gas).as_slice());
        stream.append(&u128_to_be_bytes_trimmed(self.max_fee_per_gas).as_slice());
        stream.append(&u64_to_be_bytes_trimmed(self.gas_limit).as_slice());
        
        match &self.to {
            Some(addr) => stream.append(&addr.as_slice()),
            None => stream.append_empty_data(),
        };
        
        stream.append(&u128_to_be_bytes_trimmed(self.value).as_slice());
        stream.append(&self.data);
        
        // Access list
        stream.begin_list(self.access_list.len());
        for item in &self.access_list {
            stream.begin_list(2);
            stream.append(&item.address.as_slice());
            stream.begin_list(item.storage_keys.len());
            for key in &item.storage_keys {
                stream.append(&key.as_slice());
            }
        }
        
        let mut result = vec![0x02];
        result.extend(stream.out());
        result
    }
}

/// Signed EIP-1559 transaction
#[derive(Debug, Clone)]
pub struct SignedEIP1559Transaction {
    pub tx: EIP1559Transaction,
    pub v: u8,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
}

impl SignedEIP1559Transaction {
    pub fn rlp_signed(&self) -> Vec<u8> {
        let mut stream = RlpStream::new_list(12);
        
        stream.append(&u64_to_be_bytes_trimmed(self.tx.chain_id).as_slice());
        stream.append(&u64_to_be_bytes_trimmed(self.tx.nonce).as_slice());
        stream.append(&u128_to_be_bytes_trimmed(self.tx.max_priority_fee_per_gas).as_slice());
        stream.append(&u128_to_be_bytes_trimmed(self.tx.max_fee_per_gas).as_slice());
        stream.append(&u64_to_be_bytes_trimmed(self.tx.gas_limit).as_slice());
        
        match &self.tx.to {
            Some(addr) => stream.append(&addr.as_slice()),
            None => stream.append_empty_data(),
        };
        
        stream.append(&u128_to_be_bytes_trimmed(self.tx.value).as_slice());
        stream.append(&self.tx.data);
        
        stream.begin_list(self.tx.access_list.len());
        for item in &self.tx.access_list {
            stream.begin_list(2);
            stream.append(&item.address.as_slice());
            stream.begin_list(item.storage_keys.len());
            for key in &item.storage_keys {
                stream.append(&key.as_slice());
            }
        }
        
        stream.append(&vec![self.v].as_slice());
        stream.append(&self.r.as_slice());
        stream.append(&self.s.as_slice());
        
        let mut result = vec![0x02];
        result.extend(stream.out());
        result
    }

    pub fn tx_hash(&self) -> [u8; 32] {
        keccak256(&self.rlp_signed())
    }

    pub fn tx_hash_hex(&self) -> String {
        format!("0x{}", hex::encode(self.tx_hash()))
    }

    pub fn raw_tx_hex(&self) -> String {
        format!("0x{}", hex::encode(self.rlp_signed()))
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

        let private_key = [1u8; 32];
        key_store.load_ethereum_key("test_key", &private_key, 0).unwrap();

        let signer = EthereumSigner::new(key_store, policy_engine);
        let sig = signer.sign_message("test_key", "req1", b"Hello, Ethereum!").unwrap();

        assert_eq!(sig.r.len(), 32);
        assert_eq!(sig.s.len(), 32);
    }

    #[test]
    fn test_legacy_transaction_rlp() {
        let tx = LegacyTransaction {
            nonce: 0,
            gas_price: 20_000_000_000,
            gas_limit: 21000,
            to: Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]),
            value: 1_000_000_000_000_000_000,
            data: vec![],
            chain_id: 1,
        };

        let rlp = tx.rlp_unsigned();
        assert!(!rlp.is_empty());
        assert!(rlp[0] >= 0xc0); // RLP list prefix
    }

    #[test]
    fn test_eip1559_transaction_rlp() {
        let tx = EIP1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 2_000_000_000,
            max_fee_per_gas: 100_000_000_000,
            gas_limit: 21000,
            to: Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]),
            value: 1_000_000_000_000_000_000,
            data: vec![],
            access_list: vec![],
        };

        let rlp = tx.rlp_unsigned();
        assert_eq!(rlp[0], 0x02); // EIP-1559 type prefix
    }
}