//! Post-quantum cryptography extensions for Drista CLI
//!
//! This module will add ML-KEM encryption on top of NIP-04
//! for post-quantum security.

// PQ encryption is implemented via PqSessionManager in pq_dm.rs using
// qcomm-core's ML-KEM-1024 + AES-256-GCM. Standard NIP-04 remains as fallback.
