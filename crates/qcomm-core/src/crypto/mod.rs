//! Cryptographic primitives for Quantum Communicator
//!
//! This module provides post-quantum cryptographic operations:
//! - **PQ-Triple-Ratchet**: Forward-secure messaging with ML-KEM and SPHINCS+
//! - **QRNG**: Hardware quantum random number generation
//! - **QKD**: Quantum key distribution integration
//! - **Noise**: BitChat-compatible Noise Protocol fallback
//! - **STARK**: Post-quantum event authentication via zero-knowledge proofs

// Native crypto (C bindings - not WASM compatible)
#[cfg(feature = "native-crypto")]
pub mod pq;
#[cfg(feature = "native-crypto")]
pub mod ratchet;
#[cfg(feature = "native-crypto")]
pub mod qkd;
#[cfg(feature = "native-crypto")]
pub mod noise;

// WASM-compatible crypto (pure Rust)
#[cfg(feature = "wasm-crypto")]
pub mod pq_wasm;
#[cfg(feature = "wasm-crypto")]
pub mod ratchet_wasm;

// Always available
pub mod qrng;
pub mod aead;
pub mod stark;

// Re-exports for native
#[cfg(feature = "native-crypto")]
pub use pq::{MlKemKeyPair, MlKemPublicKey, MlKemCiphertext, SharedSecret, SphincsKeyPair};
#[cfg(feature = "native-crypto")]
pub use ratchet::{PqTripleRatchet, RatchetHeader};

// Re-exports for WASM
#[cfg(feature = "wasm-crypto")]
pub use pq_wasm::{MlKemKeyPair, MlKemPublicKey, MlKemCiphertext, SharedSecret};
#[cfg(feature = "wasm-crypto")]
pub use ratchet_wasm::{PqTripleRatchet, RatchetHeader};

pub use aead::{encrypt, decrypt};
pub use stark::{StarkIdentity, EventProof, StarkError, prove_event, verify_event};
