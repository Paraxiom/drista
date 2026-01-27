//! Cryptographic primitives for Quantum Communicator
//!
//! This module provides post-quantum cryptographic operations:
//! - **PQ-Triple-Ratchet**: Forward-secure messaging with ML-KEM and SPHINCS+
//! - **QRNG**: Hardware quantum random number generation
//! - **QKD**: Quantum key distribution integration
//! - **Noise**: BitChat-compatible Noise Protocol fallback
//! - **STARK**: Post-quantum event authentication via zero-knowledge proofs

#[cfg(feature = "native-crypto")]
pub mod pq;
#[cfg(feature = "native-crypto")]
pub mod ratchet;
pub mod qrng;
#[cfg(feature = "native-crypto")]
pub mod qkd;
#[cfg(feature = "native-crypto")]
pub mod noise;
pub mod aead;
pub mod stark;

#[cfg(feature = "native-crypto")]
pub use pq::{MlKemKeyPair, SphincsKeyPair};
#[cfg(feature = "native-crypto")]
pub use ratchet::PqTripleRatchet;
pub use aead::{encrypt, decrypt};
pub use stark::{StarkIdentity, EventProof, StarkError, prove_event, verify_event};
