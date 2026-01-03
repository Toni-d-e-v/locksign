//! Authentication and authorization for gRPC
//!
//! Provides:
//! - API key authentication
//! - Token validation
//! - Request authorization

use crate::errors::{LockSignError, Result};
use std::collections::HashMap;
use std::sync::RwLock;
use tonic::{Request, Status};
use tracing::debug;

/// API key entry
#[derive(Debug, Clone)]
pub struct ApiKey {
    pub key_id: String,
    pub key_hash: String,
    pub name: String,
    pub permissions: Vec<String>,
    pub enabled: bool,
    pub created_at: i64,
}

/// Authentication service
pub struct AuthService {
    /// Map of key_id -> ApiKey
    api_keys: RwLock<HashMap<String, ApiKey>>,
    /// Whether auth is required
    require_auth: bool,
}

impl AuthService {
    /// Create a new auth service
    pub fn new(require_auth: bool) -> Self {
        Self {
            api_keys: RwLock::new(HashMap::new()),
            require_auth,
        }
    }

    /// Add an API key
    pub fn add_api_key(&self, key: ApiKey) {
        let mut keys = self.api_keys.write().unwrap();
        keys.insert(key.key_id.clone(), key);
    }

    /// Remove an API key
    pub fn remove_api_key(&self, key_id: &str) {
        let mut keys = self.api_keys.write().unwrap();
        keys.remove(key_id);
    }

    /// Validate an API key from request metadata
    pub fn validate_request<T>(&self, request: &Request<T>) -> Result<Option<String>> {
        if !self.require_auth {
            return Ok(None);
        }

        // Get authorization header
        let auth_header = request
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok());

        let api_key = match auth_header {
            Some(header) if header.starts_with("Bearer ") => &header[7..],
            Some(header) if header.starts_with("ApiKey ") => &header[7..],
            Some(key) => key,
            None => {
                return Err(LockSignError::SecurityViolation(
                    "Missing authorization header".to_string(),
                ))
            }
        };

        // Look up the key
        let keys = self.api_keys.read().unwrap();

        // In a real implementation, we'd hash the provided key and compare
        // For now, we're using the key_id directly (NOT SECURE - just for demo)
        let key_entry = keys.get(api_key);

        match key_entry {
            Some(entry) if entry.enabled => {
                debug!("Authenticated request with key: {}", entry.name);
                Ok(Some(entry.key_id.clone()))
            }
            Some(_) => Err(LockSignError::SecurityViolation(
                "API key is disabled".to_string(),
            )),
            None => Err(LockSignError::SecurityViolation(
                "Invalid API key".to_string(),
            )),
        }
    }

    /// Check if a key has a specific permission
    pub fn check_permission(&self, key_id: &str, permission: &str) -> Result<()> {
        if !self.require_auth {
            return Ok(());
        }

        let keys = self.api_keys.read().unwrap();
        let key = keys
            .get(key_id)
            .ok_or_else(|| LockSignError::SecurityViolation("Key not found".to_string()))?;

        // Check for wildcard or specific permission
        if key.permissions.contains(&"*".to_string())
            || key.permissions.contains(&permission.to_string())
        {
            Ok(())
        } else {
            Err(LockSignError::SecurityViolation(format!(
                "Missing permission: {}",
                permission
            )))
        }
    }

    /// Is auth required?
    pub fn is_auth_required(&self) -> bool {
        self.require_auth
    }
}

impl Default for AuthService {
    fn default() -> Self {
        Self::new(false)
    }
}

/// Convert auth errors to tonic Status
pub fn auth_error_to_status(err: LockSignError) -> Status {
    match err {
        LockSignError::SecurityViolation(msg) => Status::unauthenticated(msg),
        _ => Status::internal(err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_disabled() {
        let auth = AuthService::new(false);

        // Should succeed without any key
        let request: Request<()> = Request::new(());
        let result = auth.validate_request(&request);
        assert!(result.is_ok());
    }

    #[test]
    fn test_add_and_validate_key() {
        let auth = AuthService::new(true);

        auth.add_api_key(ApiKey {
            key_id: "test_key_123".to_string(),
            key_hash: "hash".to_string(),
            name: "Test Key".to_string(),
            permissions: vec!["sign:ethereum".to_string()],
            enabled: true,
            created_at: 0,
        });

        // Create a request with the auth header
        let mut request: Request<()> = Request::new(());
        request
            .metadata_mut()
            .insert("authorization", "Bearer test_key_123".parse().unwrap());

        let result = auth.validate_request(&request);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some("test_key_123".to_string()));
    }

    #[test]
    fn test_permission_check() {
        let auth = AuthService::new(true);

        auth.add_api_key(ApiKey {
            key_id: "limited_key".to_string(),
            key_hash: "hash".to_string(),
            name: "Limited Key".to_string(),
            permissions: vec!["sign:ethereum".to_string()],
            enabled: true,
            created_at: 0,
        });

        // Should have ethereum permission
        assert!(auth.check_permission("limited_key", "sign:ethereum").is_ok());

        // Should not have solana permission
        assert!(auth.check_permission("limited_key", "sign:solana").is_err());
    }
}
