# qcomm-core

Post-quantum cryptographic primitives for secure communication.

[![Crates.io](https://img.shields.io/crates/v/qcomm-core.svg)](https://crates.io/crates/qcomm-core)
[![Documentation](https://docs.rs/qcomm-core/badge.svg)](https://docs.rs/qcomm-core)
[![License](https://img.shields.io/crates/l/qcomm-core.svg)](LICENSE)

## Features

- **ML-KEM-1024** - NIST FIPS 203 post-quantum key encapsulation
- **SPHINCS+-SHA2-256f** - NIST FIPS 205 post-quantum signatures
- **PQ Triple Ratchet** - Forward-secure messaging protocol using ML-KEM
- **AES-256-GCM** - Authenticated symmetric encryption
- **STARK Proofs** - Zero-knowledge event authentication via Winterfell

## Installation

```toml
[dependencies]
qcomm-core = { version = "0.1", features = ["native-crypto"] }
```

## Quick Start

### Key Exchange with ML-KEM-1024

```rust
use qcomm_core::crypto::{MlKemKeyPair, SharedSecret};

// Bob generates a keypair
let bob_keypair = MlKemKeyPair::generate()?;

// Alice encapsulates a shared secret to Bob's public key
let (ciphertext, alice_secret) = bob_keypair.public_key().encapsulate()?;

// Bob decapsulates to get the same shared secret
let bob_secret = bob_keypair.decapsulate(&ciphertext)?;

assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes());
```

### Digital Signatures with SPHINCS+

```rust
use qcomm_core::crypto::SphincsKeyPair;

let keypair = SphincsKeyPair::generate()?;
let message = b"Hello, post-quantum world!";

// Sign
let signature = keypair.sign(message)?;

// Verify
assert!(keypair.public_key().verify(message, &signature)?);
```

### Forward-Secure Messaging with Triple Ratchet

```rust
use qcomm_core::crypto::{PqTripleRatchet, MlKemKeyPair};

// Initial key exchange (e.g., via PQXDH)
let bob_keypair = MlKemKeyPair::generate()?;
let (_, shared_secret) = bob_keypair.public_key().encapsulate()?;

// Alice initiates
let mut alice = PqTripleRatchet::init_initiator(
    shared_secret.clone(),
    bob_keypair.public_key().clone(),
)?;

// Bob responds
let mut bob = PqTripleRatchet::init_responder(
    shared_secret,
    bob_keypair,
)?;

// Alice encrypts
let (header, ciphertext) = alice.encrypt(b"Secret message")?;

// Bob decrypts
let plaintext = bob.decrypt(&header, &ciphertext)?;
```

## Security Properties

| Property | Algorithm | NIST Standard |
|----------|-----------|---------------|
| Key Encapsulation | ML-KEM-1024 | FIPS 203 |
| Digital Signatures | SPHINCS+-SHA2-256f | FIPS 205 |
| Symmetric Encryption | AES-256-GCM | FIPS 197 |
| Key Derivation | HKDF-SHA256 | RFC 5869 |

### Forward Secrecy

The Triple Ratchet protocol provides:
- **Forward secrecy**: Compromise of current keys doesn't expose past messages
- **Post-compromise security**: Future messages secure after recovery
- **Post-quantum resistance**: All key exchanges use ML-KEM

## Feature Flags

| Feature | Description |
|---------|-------------|
| `native-crypto` | Full PQ crypto (ML-KEM, SPHINCS+, networking) |
| `ble` | Bluetooth Low Energy transport |
| `qrng` | Hardware quantum random number generator support |
| `qkd` | Quantum Key Distribution integration |

## Part of QuantumHarmony

This crate is part of the [QuantumHarmony](https://github.com/Paraxiom/drista) ecosystem:

- **qcomm-core** - This crate: PQ crypto primitives
- **qcomm-wasm** - WebAssembly bindings for browsers
- **qcomm-ffi** - FFI bindings for mobile (Swift/Kotlin)

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
