//! Policy engine
//!
//! Evaluates signing requests against configured policy rules.

use crate::errors::{LockSignError, Result};
use crate::policy::rules::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::RwLock;
use tracing::{debug, info, warn};

/// Context for a signing request
#[derive(Debug, Clone)]
pub struct SigningContext {
    /// Key ID being used
    pub key_id: String,
    /// Request ID for audit
    pub request_id: String,
    /// Target address (if applicable)
    pub to_address: Option<String>,
    /// Value being transferred (if applicable)
    pub value: Option<u128>,
    /// Chain type
    pub chain: String,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
    /// 2FA token (if provided)
    pub two_factor_token: Option<String>,
}

impl SigningContext {
    pub fn new(key_id: &str, request_id: &str, chain: &str) -> Self {
        Self {
            key_id: key_id.to_string(),
            request_id: request_id.to_string(),
            to_address: None,
            value: None,
            chain: chain.to_string(),
            metadata: HashMap::new(),
            two_factor_token: None,
        }
    }

    pub fn with_address(mut self, addr: &str) -> Self {
        self.to_address = Some(addr.to_string());
        self
    }

    pub fn with_value(mut self, value: u128) -> Self {
        self.value = Some(value);
        self
    }

    pub fn with_2fa(mut self, token: &str) -> Self {
        self.two_factor_token = Some(token.to_string());
        self
    }
}

/// Result of policy evaluation
#[derive(Debug, Clone)]
pub struct PolicyResult {
    pub allowed: bool,
    pub violations: Vec<String>,
    pub warnings: Vec<String>,
    pub requires_2fa: bool,
}

impl PolicyResult {
    pub fn allow() -> Self {
        Self {
            allowed: true,
            violations: vec![],
            warnings: vec![],
            requires_2fa: false,
        }
    }

    pub fn deny(reason: &str) -> Self {
        Self {
            allowed: false,
            violations: vec![reason.to_string()],
            warnings: vec![],
            requires_2fa: false,
        }
    }

    pub fn add_violation(&mut self, reason: &str) {
        self.allowed = false;
        self.violations.push(reason.to_string());
    }

    pub fn add_warning(&mut self, warning: &str) {
        self.warnings.push(warning.to_string());
    }
}

/// Policy configuration for a key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPolicy {
    /// Key ID this policy applies to
    pub key_id: String,
    /// Whether the key is enabled
    pub enabled: bool,
    /// Policy rules
    pub rules: Vec<PolicyRule>,
}

impl KeyPolicy {
    pub fn new(key_id: &str) -> Self {
        Self {
            key_id: key_id.to_string(),
            enabled: true,
            rules: vec![],
        }
    }

    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
    }
}

/// Policy configuration file format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Version
    pub version: u32,
    /// Global rules (apply to all keys)
    #[serde(default)]
    pub global_rules: Vec<PolicyRule>,
    /// Per-key policies
    #[serde(default)]
    pub key_policies: HashMap<String, KeyPolicy>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            version: 1,
            global_rules: vec![],
            key_policies: HashMap::new(),
        }
    }
}

impl PolicyConfig {
    /// Load from file
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let json = fs::read_to_string(path)?;
        serde_json::from_str(&json).map_err(|e| LockSignError::ConfigError(e.to_string()))
    }

    /// Save to file
    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }
}

/// Policy engine for evaluating signing requests
pub struct PolicyEngine {
    /// Whether policy enforcement is enabled
    enabled: bool,
    /// Policy configuration
    config: RwLock<PolicyConfig>,
    /// Path to policy file
    config_path: Option<std::path::PathBuf>,
}

impl PolicyEngine {
    /// Create a new policy engine
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            config: RwLock::new(PolicyConfig::default()),
            config_path: None,
        }
    }

    /// Load policy from file
    pub fn load_from_file(&mut self, path: &Path) -> Result<()> {
        let config = PolicyConfig::load(path)?;
        *self.config.write().unwrap() = config;
        self.config_path = Some(path.to_path_buf());
        info!("Loaded policy from {:?}", path);
        Ok(())
    }

    /// Save current policy to file
    pub fn save(&self) -> Result<()> {
        if let Some(path) = &self.config_path {
            let config = self.config.read().unwrap();
            config.save(path)?;
        }
        Ok(())
    }

    /// Evaluate a signing request against policy
    pub fn evaluate(&self, ctx: &SigningContext) -> Result<PolicyResult> {
        if !self.enabled {
            return Ok(PolicyResult::allow());
        }

        let mut result = PolicyResult::allow();
        let mut config = self.config.write().unwrap();

        // Check global rules
        for rule in &mut config.global_rules {
            self.evaluate_rule(rule, ctx, &mut result)?;
        }

        // Check key-specific rules
        if let Some(key_policy) = config.key_policies.get_mut(&ctx.key_id) {
            if !key_policy.enabled {
                result.add_violation(&format!("Key {} is disabled by policy", ctx.key_id));
                return Ok(result);
            }

            for rule in &mut key_policy.rules {
                self.evaluate_rule(rule, ctx, &mut result)?;
            }
        }

        // Check if 2FA is required but not provided
        if result.requires_2fa && ctx.two_factor_token.is_none() {
            return Err(LockSignError::TwoFactorRequired);
        }

        if !result.allowed {
            debug!(
                "Policy denied request {}: {:?}",
                ctx.request_id, result.violations
            );
        }

        Ok(result)
    }

    /// Evaluate a single rule
    fn evaluate_rule(
        &self,
        rule: &mut PolicyRule,
        ctx: &SigningContext,
        result: &mut PolicyResult,
    ) -> Result<()> {
        match rule {
            PolicyRule::AddressAllowlist(r) => {
                if let Some(addr) = &ctx.to_address {
                    if !r.is_allowed(addr) {
                        result.add_violation(&format!(
                            "Address {} not in allowlist (rule: {})",
                            addr, r.id
                        ));
                    }
                }
            }

            PolicyRule::ValueLimit(r) => {
                if let Some(value) = ctx.value {
                    if let Err(e) = r.check_value(value) {
                        result.add_violation(&format!("{} (rule: {})", e, r.id));
                    }
                }
            }

            PolicyRule::RateLimit(r) => {
                if let Err(e) = r.check() {
                    result.add_violation(&format!("{} (rule: {})", e, r.id));
                }
            }

            PolicyRule::Require2FA(r) => {
                if let Some(value) = ctx.value {
                    if r.requires_2fa(value) {
                        result.requires_2fa = true;
                    }
                }
            }

            PolicyRule::TimeWindow(r) => {
                if !r.is_allowed_now() {
                    result.add_violation(&format!(
                        "Outside allowed time window (rule: {})",
                        r.id
                    ));
                }
            }
        }

        Ok(())
    }

    /// Record a successful signing (update rate limits, value tracking)
    pub fn record_signing(&self, ctx: &SigningContext) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let mut config = self.config.write().unwrap();

        // Update global rules
        for rule in &mut config.global_rules {
            self.record_for_rule(rule, ctx);
        }

        // Update key-specific rules
        if let Some(key_policy) = config.key_policies.get_mut(&ctx.key_id) {
            for rule in &mut key_policy.rules {
                self.record_for_rule(rule, ctx);
            }
        }

        Ok(())
    }

    fn record_for_rule(&self, rule: &mut PolicyRule, ctx: &SigningContext) {
        match rule {
            PolicyRule::ValueLimit(r) => {
                if let Some(value) = ctx.value {
                    r.record_value(value);
                }
            }
            PolicyRule::RateLimit(r) => {
                r.record();
            }
            _ => {}
        }
    }

    /// Add a global rule
    pub fn add_global_rule(&self, rule: PolicyRule) {
        let mut config = self.config.write().unwrap();
        config.global_rules.push(rule);
    }

    /// Set policy for a key
    pub fn set_key_policy(&self, policy: KeyPolicy) {
        let mut config = self.config.write().unwrap();
        config.key_policies.insert(policy.key_id.clone(), policy);
    }

    /// Get policy for a key
    pub fn get_key_policy(&self, key_id: &str) -> Option<KeyPolicy> {
        let config = self.config.read().unwrap();
        config.key_policies.get(key_id).cloned()
    }

    /// Check if policy enforcement is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allow_when_disabled() {
        let engine = PolicyEngine::new(false);
        let ctx = SigningContext::new("key1", "req1", "ethereum");
        let result = engine.evaluate(&ctx).unwrap();
        assert!(result.allowed);
    }

    #[test]
    fn test_address_allowlist_check() {
        let engine = PolicyEngine::new(true);

        let mut allowlist = AddressAllowlistRule::new("allowlist1");
        allowlist.add_address("0x742d35Cc6634C0532925a3b844Bc9e7595f12345");
        engine.add_global_rule(PolicyRule::AddressAllowlist(allowlist));

        // Allowed address
        let ctx = SigningContext::new("key1", "req1", "ethereum")
            .with_address("0x742d35Cc6634C0532925a3b844Bc9e7595f12345");
        let result = engine.evaluate(&ctx).unwrap();
        assert!(result.allowed);

        // Disallowed address
        let ctx = SigningContext::new("key1", "req2", "ethereum")
            .with_address("0x0000000000000000000000000000000000000000");
        let result = engine.evaluate(&ctx).unwrap();
        assert!(!result.allowed);
    }

    #[test]
    fn test_value_limit() {
        let engine = PolicyEngine::new(true);

        let limit = ValueLimitRule::new("limit1", 1_000_000, 0);
        engine.add_global_rule(PolicyRule::ValueLimit(limit));

        // Under limit
        let ctx = SigningContext::new("key1", "req1", "ethereum").with_value(500_000);
        let result = engine.evaluate(&ctx).unwrap();
        assert!(result.allowed);

        // Over limit
        let ctx = SigningContext::new("key1", "req2", "ethereum").with_value(2_000_000);
        let result = engine.evaluate(&ctx).unwrap();
        assert!(!result.allowed);
    }
}
