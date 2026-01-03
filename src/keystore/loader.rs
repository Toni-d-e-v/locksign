//! Key loader
//!
//! Loads encrypted keys from disk into the in-memory store at startup.

use crate::errors::{LockSignError, Result};
use crate::keystore::encrypted::{EncryptedKeyFile, EncryptedStorage};
use crate::keystore::memory::{ChainType, KeyInfo, MemoryKeyStore};
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// Key loader that manages loading keys from encrypted storage to memory
pub struct KeyLoader {
    storage: EncryptedStorage,
    memory_store: Arc<MemoryKeyStore>,
}

impl KeyLoader {
    /// Create a new key loader
    pub fn new(storage_path: impl AsRef<Path>, memory_store: Arc<MemoryKeyStore>) -> Result<Self> {
        let storage = EncryptedStorage::new(storage_path)?;
        Ok(Self {
            storage,
            memory_store,
        })
    }

    /// Load all keys from storage using the provided password
    pub fn load_all_keys(&self, password: &str) -> Result<Vec<KeyInfo>> {
        let key_ids = self.storage.list_keys()?;
        let mut loaded = Vec::new();
        let mut failed = Vec::new();

        info!("Found {} encrypted keys to load", key_ids.len());

        for key_id in &key_ids {
            match self.load_key(key_id, password) {
                Ok(info) => {
                    loaded.push(info);
                }
                Err(e) => {
                    error!("Failed to load key {}: {}", key_id, e);
                    failed.push(key_id.clone());
                }
            }
        }

        if !failed.is_empty() {
            warn!("Failed to load {} keys: {:?}", failed.len(), failed);
        }

        info!(
            "Successfully loaded {}/{} keys",
            loaded.len(),
            key_ids.len()
        );
        Ok(loaded)
    }

    /// Load a single key from storage
    pub fn load_key(&self, key_id: &str, password: &str) -> Result<KeyInfo> {
        debug!("Loading key: {}", key_id);

        // Load encrypted file
        let encrypted = self.storage.load(key_id)?;

        // Decrypt private key
        let private_key = encrypted.decrypt(password)?;

        // Determine chain type and load into memory store
        let chain = ChainType::from_str(&encrypted.chain)?;
        let info = match chain {
            ChainType::Ethereum => {
                self.memory_store
                    .load_ethereum_key(key_id, &private_key, encrypted.created_at)?
            }
            ChainType::Solana => {
                self.memory_store
                    .load_solana_key(key_id, &private_key, encrypted.created_at)?
            }
        };

        // Verify public key matches
        if info.public_key != encrypted.public_key {
            warn!(
                "Public key mismatch for {}: expected {}, got {}",
                key_id, encrypted.public_key, info.public_key
            );
        }

        Ok(info)
    }

    /// Import a new key (generate encrypted file and load into memory)
    pub fn import_key(
        &self,
        key_id: &str,
        private_key: &[u8],
        chain: &str,
        password: &str,
    ) -> Result<KeyInfo> {
        // Check if key already exists
        if self.storage.exists(key_id) {
            return Err(LockSignError::KeyAlreadyExists(key_id.to_string()));
        }

        let chain_type = ChainType::from_str(chain)?;

        // Derive public key based on chain
        let public_key = match chain_type {
            ChainType::Ethereum => {
                let keypair = crate::crypto::EthKeyPair::from_bytes(private_key)?;
                keypair.address_checksum()
            }
            ChainType::Solana => {
                let keypair = crate::crypto::SolKeyPair::from_bytes(private_key)?;
                keypair.public_key_base58()
            }
        };

        // Create encrypted file
        let encrypted = EncryptedKeyFile::new(
            key_id.to_string(),
            chain.to_string(),
            private_key,
            public_key,
            password,
        )?;

        // Save to storage
        self.storage.store(&encrypted)?;

        // Load into memory
        let info = match chain_type {
            ChainType::Ethereum => {
                self.memory_store
                    .load_ethereum_key(key_id, private_key, encrypted.created_at)?
            }
            ChainType::Solana => {
                self.memory_store
                    .load_solana_key(key_id, private_key, encrypted.created_at)?
            }
        };

        info!("Imported and loaded key: {} ({})", key_id, chain);
        Ok(info)
    }

    /// Generate a new key
    pub fn generate_key(&self, key_id: &str, chain: &str, password: &str) -> Result<KeyInfo> {
        let chain_type = ChainType::from_str(chain)?;

        let (private_key_bytes, public_key) = match chain_type {
            ChainType::Ethereum => {
                let keypair = crate::crypto::EthKeyPair::generate()?;
                let privkey = keypair.private_key_bytes();
                let pubkey = keypair.address_checksum();
                (privkey.expose().to_vec(), pubkey)
            }
            ChainType::Solana => {
                let keypair = crate::crypto::SolKeyPair::generate()?;
                let privkey = keypair.seed_bytes();
                let pubkey = keypair.public_key_base58();
                (privkey.expose().to_vec(), pubkey)
            }
        };

        // Import the generated key
        self.import_key(key_id, &private_key_bytes, chain, password)
    }

    /// Delete a key from both storage and memory
    pub fn delete_key(&self, key_id: &str) -> Result<()> {
        // Remove from memory first
        self.memory_store.unload_key(key_id)?;

        // Remove from storage
        self.storage.delete(key_id)?;

        info!("Deleted key: {}", key_id);
        Ok(())
    }

    /// Get key info (from memory store)
    pub fn get_key_info(&self, key_id: &str) -> Result<KeyInfo> {
        self.memory_store.get_key_info(key_id)
    }

    /// List all loaded keys
    pub fn list_loaded_keys(&self) -> Vec<KeyInfo> {
        self.memory_store.list_keys()
    }

    /// List all stored key IDs (including unloaded)
    pub fn list_stored_keys(&self) -> Result<Vec<String>> {
        self.storage.list_keys()
    }

    /// Check if a key exists in storage
    pub fn key_exists(&self, key_id: &str) -> bool {
        self.storage.exists(key_id)
    }

    /// Get reference to the memory store
    pub fn memory_store(&self) -> &Arc<MemoryKeyStore> {
        &self.memory_store
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_generate_and_load() {
        let dir = tempdir().unwrap();
        let memory_store = Arc::new(MemoryKeyStore::new());
        let loader = KeyLoader::new(dir.path(), memory_store.clone()).unwrap();

        // Generate an Ethereum key
        let info = loader
            .generate_key("eth_key_1", "ethereum", "test_password")
            .unwrap();
        assert!(info.public_key.starts_with("0x"));

        // Generate a Solana key
        let info = loader
            .generate_key("sol_key_1", "solana", "test_password")
            .unwrap();
        assert!(!info.public_key.starts_with("0x"));

        // List keys
        let keys = loader.list_loaded_keys();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn test_reload_keys() {
        let dir = tempdir().unwrap();
        let password = "secure_password_123";

        // Generate keys with first loader
        {
            let memory_store = Arc::new(MemoryKeyStore::new());
            let loader = KeyLoader::new(dir.path(), memory_store).unwrap();
            loader.generate_key("key1", "ethereum", password).unwrap();
            loader.generate_key("key2", "solana", password).unwrap();
        }

        // Load with second loader (simulating restart)
        {
            let memory_store = Arc::new(MemoryKeyStore::new());
            let loader = KeyLoader::new(dir.path(), memory_store.clone()).unwrap();

            let loaded = loader.load_all_keys(password).unwrap();
            assert_eq!(loaded.len(), 2);
            assert_eq!(memory_store.key_count(), 2);
        }
    }
}
