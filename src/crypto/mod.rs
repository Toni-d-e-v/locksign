//! Cryptographic utilities for Ethereum and Solana

pub mod eth;
pub mod sol;

pub use eth::{checksum_address, hash_message, keccak256, EthKeyPair, EthSignature};
pub use sol::{parse_pubkey, verify_signature, SolKeyPair, SolSignature};
