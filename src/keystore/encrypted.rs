//! Encrypted key storage
//!
//! Handles encryption/decryption of private keys using AES-256-GCM
//! with Argon2id key derivation.

use crate::errors::{LockSignError, Result};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Salt size for Argon2
const SALT_SIZE: usize = 16;

/// Nonce size for AES-GCM
const NONCE_SIZE: usize = 12;

/// Encrypted key file format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedKeyFile {
    /// Version of the encryption format
    pub version: u32,

    /// Key identifier
    pub key_id: String,

    /// Chain type ("ethereum" or "solana")
    pub chain: String,

    /// Salt for key derivation (base64)
    pub salt: String,

    /// Nonce for AES-GCM (base64)
    pub nonce: String,

    /// Encrypted private key (base64)
    pub ciphertext: String,

    /// Public key (hex for ETH, base58 for SOL)
    pub public_key: String,

    /// Creation timestamp
    pub created_at: i64,

    /// Optional metadata
    #[serde(default)]
    pub metadata: std::collections::HashMap<String, String>,
}

impl EncryptedKeyFile {
    /// Create a new encrypted key file
    pub fn new(
        key_id: String,
        chain: String,
        private_key: &[u8],
        public_key: String,
        password: &str,
    ) -> Result<Self> {
        // Generate random salt
        let mut salt_bytes = [0u8; SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut salt_bytes);
        let salt = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, salt_bytes);

        // Derive encryption key using Argon2id
        let encryption_key = derive_key(password, &salt_bytes)?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce_bytes);

        // Encrypt the private key
        let cipher = Aes256Gcm::new_from_slice(&encryption_key)
            .map_err(|e| LockSignError::EncryptionFailed(e.to_string()))?;

        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), private_key)
            .map_err(|e| LockSignError::EncryptionFailed(e.to_string()))?;

        let ciphertext_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &ciphertext);

        Ok(Self {
            version: 1,
            key_id,
            chain,
            salt,
            nonce,
            ciphertext: ciphertext_b64,
            public_key,
            created_at: chrono::Utc::now().timestamp(),
            metadata: std::collections::HashMap::new(),
        })
    }

    /// Decrypt the private key
    pub fn decrypt(&self, password: &str) -> Result<Vec<u8>> {
        // Decode salt
        let salt_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &self.salt)
            .map_err(|e| LockSignError::DecryptionFailed(format!("Invalid salt: {}", e)))?;

        // Derive decryption key
        let decryption_key = derive_key(password, &salt_bytes)?;

        // Decode nonce
        let nonce_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &self.nonce)
                .map_err(|e| LockSignError::DecryptionFailed(format!("Invalid nonce: {}", e)))?;

        // Decode ciphertext
        let ciphertext =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &self.ciphertext)
                .map_err(|e| {
                    LockSignError::DecryptionFailed(format!("Invalid ciphertext: {}", e))
                })?;

        // Decrypt
        let cipher = Aes256Gcm::new_from_slice(&decryption_key)
            .map_err(|e| LockSignError::DecryptionFailed(e.to_string()))?;

        let plaintext = cipher
            .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_slice())
            .map_err(|_| {
                LockSignError::DecryptionFailed("Decryption failed - wrong password?".to_string())
            })?;

        Ok(plaintext)
    }

    /// Save to a file
    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Load from a file
    pub fn load(path: &Path) -> Result<Self> {
        let json = fs::read_to_string(path)?;
        let file: Self = serde_json::from_str(&json)?;
        Ok(file)
    }
}

/// Derive an encryption key from a password using Argon2id
fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    use argon2::{Algorithm, Params, Version};

    // Use Argon2id with recommended parameters
    let params = Params::new(
        65536,  // 64 MB memory
        3,      // 3 iterations
        4,      // 4 parallel lanes
        Some(32),
    )
    .map_err(|e| LockSignError::EncryptionFailed(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut output)
        .map_err(|e| LockSignError::EncryptionFailed(e.to_string()))?;

    Ok(output)
}

/// Encrypted key storage manager
pub struct EncryptedStorage {
    base_path: std::path::PathBuf,
}

impl EncryptedStorage {
    /// Create a new encrypted storage at the given path
    pub fn new(base_path: impl AsRef<Path>) -> Result<Self> {
        let base_path = base_path.as_ref().to_path_buf();

        // Create directory if it doesn't exist
        if !base_path.exists() {
            fs::create_dir_all(&base_path)?;
        }

        Ok(Self { base_path })
    }

    /// Get the path for a key file
    fn key_path(&self, key_id: &str) -> std::path::PathBuf {
        self.base_path.join(format!("{}.json", key_id))
    }

    /// Store an encrypted key
    pub fn store(&self, file: &EncryptedKeyFile) -> Result<()> {
        let path = self.key_path(&file.key_id);
        file.save(&path)
    }

    /// Load an encrypted key
    pub fn load(&self, key_id: &str) -> Result<EncryptedKeyFile> {
        let path = self.key_path(key_id);
        if !path.exists() {
            return Err(LockSignError::KeyNotFound(key_id.to_string()));
        }
        EncryptedKeyFile::load(&path)
    }

    /// Delete a key
    pub fn delete(&self, key_id: &str) -> Result<()> {
        let path = self.key_path(key_id);
        if !path.exists() {
            return Err(LockSignError::KeyNotFound(key_id.to_string()));
        }
        fs::remove_file(path)?;
        Ok(())
    }

    /// List all key IDs
    pub fn list_keys(&self) -> Result<Vec<String>> {
        let mut keys = Vec::new();

        for entry in fs::read_dir(&self.base_path)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().map_or(false, |ext| ext == "json") {
                if let Some(stem) = path.file_stem() {
                    keys.push(stem.to_string_lossy().to_string());
                }
            }
        }

        Ok(keys)
    }

    /// Check if a key exists
    pub fn exists(&self, key_id: &str) -> bool {
        self.key_path(key_id).exists()
    }
}

// Add base64 encoding trait usage
use base64::Engine as _;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_encrypt_decrypt() {
        let private_key = vec![1u8; 32];
        let password = "test_password_123";

        let encrypted = EncryptedKeyFile::new(
            "test_key".to_string(),
            "ethereum".to_string(),
            &private_key,
            "0x123...".to_string(),
            password,
        )
        .unwrap();

        let decrypted = encrypted.decrypt(password).unwrap();
        assert_eq!(decrypted, private_key);
    }

    #[test]
    fn test_wrong_password() {
        let private_key = vec![1u8; 32];
        let password = "correct_password";

        let encrypted = EncryptedKeyFile::new(
            "test_key".to_string(),
            "ethereum".to_string(),
            &private_key,
            "0x123...".to_string(),
            password,
        )
        .unwrap();

        let result = encrypted.decrypt("wrong_password");
        assert!(result.is_err());
    }

    #[test]
    fn test_storage() {
        let dir = tempdir().unwrap();
        let storage = EncryptedStorage::new(dir.path()).unwrap();

        let private_key = vec![1u8; 32];
        let password = "test_password";

        let encrypted = EncryptedKeyFile::new(
            "my_key".to_string(),
            "solana".to_string(),
            &private_key,
            "ABC123...".to_string(),
            password,
        )
        .unwrap();

        storage.store(&encrypted).unwrap();

        let loaded = storage.load("my_key").unwrap();
        assert_eq!(loaded.key_id, "my_key");
        assert_eq!(loaded.chain, "solana");

        let decrypted = loaded.decrypt(password).unwrap();
        assert_eq!(decrypted, private_key);
    }
}
