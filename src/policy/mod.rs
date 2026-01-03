//! Policy enforcement for signing operations
//!
//! This module provides:
//! - Policy rules (allowlists, limits, rate limits, 2FA)
//! - Policy engine for evaluation
//! - Policy configuration

pub mod engine;
pub mod rules;

pub use engine::{KeyPolicy, PolicyConfig, PolicyEngine, PolicyResult, SigningContext};
pub use rules::{
    AddressAllowlistRule, PolicyRule, RateLimitRule, Require2FARule, TimeWindowRule,
    ValueLimitRule,
};
