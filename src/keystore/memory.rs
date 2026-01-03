//! In-memory key store
//!
//! Holds decrypted keys in memory for signing operations.
//! Keys are stored in locked memory to prevent swapping.

use crate::crypto::{EthKeyPair, SolKeyPair};
use crate::errors::{LockSignError, Result};
use crate::security::{LockedMemory, SecureBytes};
use std::collections::HashMap;
use std::sync::RwLock;
use tracing::{debug, info};

/// Chain type for a key
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChainType {
    Ethereum,
    Solana,
}

impl ChainType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChainType::Ethereum => "ethereum",
            ChainType::Solana => "solana",
        }
    }

    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "ethereum" | "eth" => Ok(ChainType::Ethereum),
            "solana" | "sol" => Ok(ChainType::Solana),
            _ => Err(LockSignError::UnsupportedChain(s.to_string())),
        }
    }
}

/// Metadata about a loaded key
#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub key_id: String,
    pub chain: ChainType,
    pub public_key: String,
    pub created_at: i64,
    pub enabled: bool,
}

/// A loaded key in memory
enum LoadedKey {
    Ethereum(EthKeyPair),
    Solana(SolKeyPair),
}

/// In-memory key store
pub struct MemoryKeyStore {
    /// Map of key_id -> loaded key
    keys: RwLock<HashMap<String, LoadedKey>>,
    /// Map of key_id -> key info
    info: RwLock<HashMap<String, KeyInfo>>,
}

impl MemoryKeyStore {
    /// Create a new empty key store
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
            info: RwLock::new(HashMap::new()),
        }
    }

    /// Load an Ethereum key into memory
    pub fn load_ethereum_key(
        &self,
        key_id: &str,
        private_key: &[u8],
        created_at: i64,
    ) -> Result<KeyInfo> {
        let keypair = EthKeyPair::from_bytes(private_key)?;
        let public_key = keypair.address_checksum();

        let info = KeyInfo {
            key_id: key_id.to_string(),
            chain: ChainType::Ethereum,
            public_key: public_key.clone(),
            created_at,
            enabled: true,
        };

        {
            let mut keys = self.keys.write().unwrap();
            keys.insert(key_id.to_string(), LoadedKey::Ethereum(keypair));
        }

        {
            let mut infos = self.info.write().unwrap();
            infos.insert(key_id.to_string(), info.clone());
        }

        debug!("Loaded Ethereum key: {} ({})", key_id, public_key);
        Ok(info)
    }

    /// Load a Solana key into memory
    pub fn load_solana_key(
        &self,
        key_id: &str,
        private_key: &[u8],
        created_at: i64,
    ) -> Result<KeyInfo> {
        let keypair = SolKeyPair::from_bytes(private_key)?;
        let public_key = keypair.public_key_base58();

        let info = KeyInfo {
            key_id: key_id.to_string(),
            chain: ChainType::Solana,
            public_key: public_key.clone(),
            created_at,
            enabled: true,
        };

        {
            let mut keys = self.keys.write().unwrap();
            keys.insert(key_id.to_string(), LoadedKey::Solana(keypair));
        }

        {
            let mut infos = self.info.write().unwrap();
            infos.insert(key_id.to_string(), info.clone());
        }

        debug!("Loaded Solana key: {} ({})", key_id, public_key);
        Ok(info)
    }

    /// Unload a key from memory
    pub fn unload_key(&self, key_id: &str) -> Result<()> {
        {
            let mut keys = self.keys.write().unwrap();
            keys.remove(key_id);
        }

        {
            let mut infos = self.info.write().unwrap();
            infos.remove(key_id);
        }

        debug!("Unloaded key: {}", key_id);
        Ok(())
    }

    /// Get key info
    pub fn get_key_info(&self, key_id: &str) -> Result<KeyInfo> {
        let infos = self.info.read().unwrap();
        infos
            .get(key_id)
            .cloned()
            .ok_or_else(|| LockSignError::KeyNotFound(key_id.to_string()))
    }

    /// List all loaded keys
    pub fn list_keys(&self) -> Vec<KeyInfo> {
        let infos = self.info.read().unwrap();
        infos.values().cloned().collect()
    }

    /// Check if a key is loaded
    pub fn has_key(&self, key_id: &str) -> bool {
        let keys = self.keys.read().unwrap();
        keys.contains_key(key_id)
    }

    /// Get the number of loaded keys
    pub fn key_count(&self) -> usize {
        let keys = self.keys.read().unwrap();
        keys.len()
    }

    /// Enable or disable a key
    pub fn set_key_enabled(&self, key_id: &str, enabled: bool) -> Result<()> {
        let mut infos = self.info.write().unwrap();
        let info = infos
            .get_mut(key_id)
            .ok_or_else(|| LockSignError::KeyNotFound(key_id.to_string()))?;
        info.enabled = enabled;
        Ok(())
    }

    /// Sign with an Ethereum key
    pub fn sign_ethereum_message(&self, key_id: &str, message: &[u8]) -> Result<crate::crypto::EthSignature> {
        let keys = self.keys.read().unwrap();
        let key = keys
            .get(key_id)
            .ok_or_else(|| LockSignError::KeyNotFound(key_id.to_string()))?;

        match key {
            LoadedKey::Ethereum(keypair) => {
                // Check if enabled
                let infos = self.info.read().unwrap();
                let info = infos.get(key_id).unwrap();
                if !info.enabled {
                    return Err(LockSignError::KeyDisabled(key_id.to_string()));
                }
                drop(infos);

                keypair.sign_message(message)
            }
            LoadedKey::Solana(_) => Err(LockSignError::InvalidKeyFormat(
                "Expected Ethereum key, got Solana".to_string(),
            )),
        }
    }

    /// Sign a hash with an Ethereum key
    pub fn sign_ethereum_hash(&self, key_id: &str, hash: &[u8; 32]) -> Result<crate::crypto::EthSignature> {
        let keys = self.keys.read().unwrap();
        let key = keys
            .get(key_id)
            .ok_or_else(|| LockSignError::KeyNotFound(key_id.to_string()))?;

        match key {
            LoadedKey::Ethereum(keypair) => {
                let infos = self.info.read().unwrap();
                let info = infos.get(key_id).unwrap();
                if !info.enabled {
                    return Err(LockSignError::KeyDisabled(key_id.to_string()));
                }
                drop(infos);

                keypair.sign_hash(hash)
            }
            LoadedKey::Solana(_) => Err(LockSignError::InvalidKeyFormat(
                "Expected Ethereum key, got Solana".to_string(),
            )),
        }
    }

    /// Get Ethereum address for a key
    pub fn get_ethereum_address(&self, key_id: &str) -> Result<String> {
        let keys = self.keys.read().unwrap();
        let key = keys
            .get(key_id)
            .ok_or_else(|| LockSignError::KeyNotFound(key_id.to_string()))?;

        match key {
            LoadedKey::Ethereum(keypair) => Ok(keypair.address_checksum()),
            LoadedKey::Solana(_) => Err(LockSignError::InvalidKeyFormat(
                "Expected Ethereum key, got Solana".to_string(),
            )),
        }
    }

    /// Sign with a Solana key
    pub fn sign_solana_message(&self, key_id: &str, message: &[u8]) -> Result<crate::crypto::SolSignature> {
        let keys = self.keys.read().unwrap();
        let key = keys
            .get(key_id)
            .ok_or_else(|| LockSignError::KeyNotFound(key_id.to_string()))?;

        match key {
            LoadedKey::Solana(keypair) => {
                let infos = self.info.read().unwrap();
                let info = infos.get(key_id).unwrap();
                if !info.enabled {
                    return Err(LockSignError::KeyDisabled(key_id.to_string()));
                }
                drop(infos);

                keypair.sign(message)
            }
            LoadedKey::Ethereum(_) => Err(LockSignError::InvalidKeyFormat(
                "Expected Solana key, got Ethereum".to_string(),
            )),
        }
    }

    /// Get Solana public key for a key
    pub fn get_solana_pubkey(&self, key_id: &str) -> Result<String> {
        let keys = self.keys.read().unwrap();
        let key = keys
            .get(key_id)
            .ok_or_else(|| LockSignError::KeyNotFound(key_id.to_string()))?;

        match key {
            LoadedKey::Solana(keypair) => Ok(keypair.public_key_base58()),
            LoadedKey::Ethereum(_) => Err(LockSignError::InvalidKeyFormat(
                "Expected Solana key, got Ethereum".to_string(),
            )),
        }
    }

    /// Get Solana public key bytes
    pub fn get_solana_pubkey_bytes(&self, key_id: &str) -> Result<[u8; 32]> {
        let keys = self.keys.read().unwrap();
        let key = keys
            .get(key_id)
            .ok_or_else(|| LockSignError::KeyNotFound(key_id.to_string()))?;

        match key {
            LoadedKey::Solana(keypair) => Ok(keypair.public_key()),
            LoadedKey::Ethereum(_) => Err(LockSignError::InvalidKeyFormat(
                "Expected Solana key, got Ethereum".to_string(),
            )),
        }
    }
}

impl Default for MemoryKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_ethereum_key() {
        let store = MemoryKeyStore::new();

        // 32 bytes private key
        let private_key = [1u8; 32];

        let info = store
            .load_ethereum_key("test_eth_key", &private_key, 1234567890)
            .unwrap();

        assert_eq!(info.key_id, "test_eth_key");
        assert_eq!(info.chain, ChainType::Ethereum);
        assert!(info.public_key.starts_with("0x"));
    }

    #[test]
    fn test_load_solana_key() {
        let store = MemoryKeyStore::new();

        // 32 bytes seed
        let private_key = [2u8; 32];

        let info = store
            .load_solana_key("test_sol_key", &private_key, 1234567890)
            .unwrap();

        assert_eq!(info.key_id, "test_sol_key");
        assert_eq!(info.chain, ChainType::Solana);
    }

    #[test]
    fn test_signing() {
        let store = MemoryKeyStore::new();

        let eth_key = [1u8; 32];
        let sol_key = [2u8; 32];

        store
            .load_ethereum_key("eth1", &eth_key, 0)
            .unwrap();
        store
            .load_solana_key("sol1", &sol_key, 0)
            .unwrap();

        // Sign with Ethereum
        let eth_sig = store.sign_ethereum_message("eth1", b"test message").unwrap();
        assert_eq!(eth_sig.r.len(), 32);

        // Sign with Solana
        let sol_sig = store.sign_solana_message("sol1", b"test message").unwrap();
        assert_eq!(sol_sig.bytes.len(), 64);
    }

    #[test]
    fn test_disabled_key() {
        let store = MemoryKeyStore::new();

        let private_key = [1u8; 32];
        store
            .load_ethereum_key("eth1", &private_key, 0)
            .unwrap();

        // Disable the key
        store.set_key_enabled("eth1", false).unwrap();

        // Signing should fail
        let result = store.sign_ethereum_message("eth1", b"test");
        assert!(matches!(result, Err(LockSignError::KeyDisabled(_))));
    }
}
