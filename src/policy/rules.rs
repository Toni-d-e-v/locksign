//! Policy rules for signing operations
//!
//! Defines the rules that can be applied to signing requests:
//! - Address allowlists
//! - Value limits
//! - Rate limits
//! - 2FA requirements

use crate::errors::{LockSignError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// A policy rule that can be applied to signing requests
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum PolicyRule {
    /// Only allow transactions to specific addresses
    #[serde(rename = "allowlist")]
    AddressAllowlist(AddressAllowlistRule),

    /// Limit the maximum value per transaction
    #[serde(rename = "value_limit")]
    ValueLimit(ValueLimitRule),

    /// Limit the number of transactions per time period
    #[serde(rename = "rate_limit")]
    RateLimit(RateLimitRule),

    /// Require 2FA for transactions above a threshold
    #[serde(rename = "require_2fa")]
    Require2FA(Require2FARule),

    /// Time-based restrictions
    #[serde(rename = "time_window")]
    TimeWindow(TimeWindowRule),
}

impl PolicyRule {
    /// Get a human-readable description of the rule
    pub fn description(&self) -> String {
        match self {
            PolicyRule::AddressAllowlist(r) => {
                format!("Allow only {} addresses", r.addresses.len())
            }
            PolicyRule::ValueLimit(r) => {
                format!("Max value: {} per {}", r.max_value, r.period_description())
            }
            PolicyRule::RateLimit(r) => {
                format!("Max {} txs per {} seconds", r.max_count, r.period_seconds)
            }
            PolicyRule::Require2FA(r) => {
                format!("Require 2FA for values > {}", r.threshold)
            }
            PolicyRule::TimeWindow(r) => {
                format!(
                    "Allow only {}:{:02} - {}:{:02} UTC",
                    r.start_hour, r.start_minute, r.end_hour, r.end_minute
                )
            }
        }
    }
}

/// Address allowlist rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressAllowlistRule {
    /// Rule ID
    pub id: String,
    /// Allowed addresses (lowercase, without 0x prefix for comparison)
    pub addresses: HashSet<String>,
    /// Whether to allow any address if list is empty
    pub allow_empty: bool,
}

impl AddressAllowlistRule {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            addresses: HashSet::new(),
            allow_empty: false,
        }
    }

    /// Add an address to the allowlist
    pub fn add_address(&mut self, addr: &str) {
        let normalized = Self::normalize_address(addr);
        self.addresses.insert(normalized);
    }

    /// Check if an address is allowed
    pub fn is_allowed(&self, addr: &str) -> bool {
        if self.addresses.is_empty() {
            return self.allow_empty;
        }
        let normalized = Self::normalize_address(addr);
        self.addresses.contains(&normalized)
    }

    /// Normalize an address for comparison
    fn normalize_address(addr: &str) -> String {
        addr.to_lowercase()
            .strip_prefix("0x")
            .unwrap_or(addr)
            .to_string()
    }
}

/// Value limit rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueLimitRule {
    /// Rule ID
    pub id: String,
    /// Maximum value (in smallest unit, e.g., wei for ETH, lamports for SOL)
    pub max_value: u128,
    /// Time period in seconds (0 = per transaction)
    pub period_seconds: u64,
    /// Current accumulated value in this period
    #[serde(skip)]
    pub current_value: u128,
    /// Period start timestamp
    #[serde(skip)]
    pub period_start: i64,
}

impl ValueLimitRule {
    pub fn new(id: &str, max_value: u128, period_seconds: u64) -> Self {
        Self {
            id: id.to_string(),
            max_value,
            period_seconds,
            current_value: 0,
            period_start: 0,
        }
    }

    /// Check if a value is allowed
    pub fn check_value(&mut self, value: u128) -> Result<()> {
        let now = chrono::Utc::now().timestamp();

        // Reset if period has elapsed
        if self.period_seconds > 0 && now - self.period_start > self.period_seconds as i64 {
            self.current_value = 0;
            self.period_start = now;
        }

        // Check per-transaction limit
        if self.period_seconds == 0 {
            if value > self.max_value {
                return Err(LockSignError::ValueLimitExceeded {
                    requested: value.to_string(),
                    max: self.max_value.to_string(),
                });
            }
        } else {
            // Check period limit
            if self.current_value + value > self.max_value {
                return Err(LockSignError::ValueLimitExceeded {
                    requested: (self.current_value + value).to_string(),
                    max: self.max_value.to_string(),
                });
            }
        }

        Ok(())
    }

    /// Record a value after successful signing
    pub fn record_value(&mut self, value: u128) {
        self.current_value += value;
    }

    fn period_description(&self) -> &str {
        match self.period_seconds {
            0 => "transaction",
            3600 => "hour",
            86400 => "day",
            604800 => "week",
            _ => "period",
        }
    }
}

/// Rate limit rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitRule {
    /// Rule ID
    pub id: String,
    /// Maximum number of transactions
    pub max_count: u32,
    /// Time period in seconds
    pub period_seconds: u64,
    /// Current count in this period
    #[serde(skip)]
    pub current_count: u32,
    /// Period start timestamp
    #[serde(skip)]
    pub period_start: i64,
}

impl RateLimitRule {
    pub fn new(id: &str, max_count: u32, period_seconds: u64) -> Self {
        Self {
            id: id.to_string(),
            max_count,
            period_seconds,
            current_count: 0,
            period_start: 0,
        }
    }

    /// Check if a request is allowed
    pub fn check(&mut self) -> Result<()> {
        let now = chrono::Utc::now().timestamp();

        // Reset if period has elapsed
        if now - self.period_start > self.period_seconds as i64 {
            self.current_count = 0;
            self.period_start = now;
        }

        if self.current_count >= self.max_count {
            return Err(LockSignError::RateLimitExceeded(format!(
                "Max {} per {} seconds",
                self.max_count, self.period_seconds
            )));
        }

        Ok(())
    }

    /// Record a request after successful signing
    pub fn record(&mut self) {
        self.current_count += 1;
    }
}

/// Require 2FA rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Require2FARule {
    /// Rule ID
    pub id: String,
    /// Value threshold above which 2FA is required
    pub threshold: u128,
    /// 2FA method (totp, webauthn, etc.)
    pub method: String,
}

impl Require2FARule {
    pub fn new(id: &str, threshold: u128, method: &str) -> Self {
        Self {
            id: id.to_string(),
            threshold,
            method: method.to_string(),
        }
    }

    /// Check if 2FA is required for this value
    pub fn requires_2fa(&self, value: u128) -> bool {
        value > self.threshold
    }
}

/// Time window rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindowRule {
    /// Rule ID
    pub id: String,
    /// Start hour (0-23 UTC)
    pub start_hour: u8,
    /// Start minute (0-59)
    pub start_minute: u8,
    /// End hour (0-23 UTC)
    pub end_hour: u8,
    /// End minute (0-59)
    pub end_minute: u8,
    /// Days of week (0=Sunday, 6=Saturday). Empty = all days
    pub days: Vec<u8>,
}

impl TimeWindowRule {
    pub fn new(id: &str, start_hour: u8, start_minute: u8, end_hour: u8, end_minute: u8) -> Self {
        Self {
            id: id.to_string(),
            start_hour,
            start_minute,
            end_hour,
            end_minute,
            days: vec![],
        }
    }

    /// Check if current time is within the allowed window
    pub fn is_allowed_now(&self) -> bool {
        use chrono::{Datelike, Timelike, Utc};

        let now = Utc::now();
        let current_minutes = now.hour() * 60 + now.minute();
        let start_minutes = self.start_hour as u32 * 60 + self.start_minute as u32;
        let end_minutes = self.end_hour as u32 * 60 + self.end_minute as u32;

        // Check day of week if specified
        if !self.days.is_empty() {
            let weekday = now.weekday().num_days_from_sunday() as u8;
            if !self.days.contains(&weekday) {
                return false;
            }
        }

        // Handle time window (including overnight windows)
        if start_minutes <= end_minutes {
            current_minutes >= start_minutes && current_minutes < end_minutes
        } else {
            // Window spans midnight
            current_minutes >= start_minutes || current_minutes < end_minutes
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_allowlist() {
        let mut rule = AddressAllowlistRule::new("test");
        rule.add_address("0x742d35Cc6634C0532925a3b844Bc9e7595f1234");
        rule.add_address("0xABCdef1234567890abcdef1234567890abcdef12");

        // Should match (case insensitive)
        assert!(rule.is_allowed("0x742d35Cc6634C0532925a3b844Bc9e7595f1234"));
        assert!(rule.is_allowed("0x742d35cc6634c0532925a3b844bc9e7595f1234"));

        // Should not match
        assert!(!rule.is_allowed("0x000000000000000000000000000000000000dead"));
    }

    #[test]
    fn test_value_limit() {
        let mut rule = ValueLimitRule::new("test", 1000, 0);

        // Should pass
        assert!(rule.check_value(500).is_ok());
        assert!(rule.check_value(1000).is_ok());

        // Should fail
        assert!(rule.check_value(1001).is_err());
    }

    #[test]
    fn test_rate_limit() {
        let mut rule = RateLimitRule::new("test", 3, 3600);

        // First three should pass
        assert!(rule.check().is_ok());
        rule.record();
        assert!(rule.check().is_ok());
        rule.record();
        assert!(rule.check().is_ok());
        rule.record();

        // Fourth should fail
        assert!(rule.check().is_err());
    }

    #[test]
    fn test_require_2fa() {
        let rule = Require2FARule::new("test", 1000, "totp");

        assert!(!rule.requires_2fa(500));
        assert!(!rule.requires_2fa(1000));
        assert!(rule.requires_2fa(1001));
    }
}
