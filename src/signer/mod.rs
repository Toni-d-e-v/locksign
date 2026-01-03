//! Chain-specific signing services
//!
//! This module provides high-level signing services for different blockchains,
//! integrating key management and policy enforcement.

pub mod ethereum;
pub mod solana;

pub use ethereum::{
    AccessListItem, EIP1559Transaction, EthereumSigner, LegacyTransaction,
    SignedEIP1559Transaction, SignedTransaction,
};
pub use solana::SolanaSigner;