# Security Model

Threat model and security analysis for Drista - Post-Quantum Secure Messaging.

## Full PQC Architecture (v0.1.0)

Drista implements end-to-end post-quantum cryptography at every layer:

| Layer | Algorithm | Standard | Security Level |
|-------|-----------|----------|----------------|
| **DM Encryption** | ML-KEM-1024 + AES-256-GCM | FIPS 203 | NIST Level 5 |
| **Signatures** | SLH-DSA-SHAKE-128s + Schnorr | FIPS 205 + BIP-340 | NIST Level 1 + Classical |
| **Message Auth** | STARK Proofs | Winterfell ZK | Post-Quantum (hash-based) |
| **Key Exchange** | ML-KEM-1024 | FIPS 203 | NIST Level 5 |
| **Transport** | TLS 1.3 (QSSL client ready) | RFC 8446 | Classical (PQ pending) |

### Why Dual Signatures?

Events include both SLH-DSA (post-quantum) and Schnorr (classical) signatures:

- **Schnorr (secp256k1)**: Required for Nostr relay compatibility. Standard relays only accept NIP-01 events with Schnorr signatures.
- **SLH-DSA (FIPS 205)**: Post-quantum signature stored in event metadata. Drista clients verify this signature for quantum resistance.

This hybrid approach ensures:
1. Interoperability with existing Nostr infrastructure
2. Post-quantum security for Drista-to-Drista communication
3. Forward compatibility as relays adopt PQ signatures

## Defense in Depth

Security is layered — compromise of any single layer does not break confidentiality:

```
┌─────────────────────────────────────────────────────────────┐
│                     APPLICATION LAYER                        │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ DM Content: ML-KEM-1024 + AES-256-GCM               │    │
│  │ - Recipient's ML-KEM public key used for KEM        │    │
│  │ - Shared secret derived via HKDF                    │    │
│  │ - Message encrypted with AES-256-GCM                │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ Authentication: STARK Proofs + SLH-DSA              │    │
│  │ - STARK proof embedded in message                   │    │
│  │ - SLH-DSA signature on event ID                     │    │
│  │ - Schnorr signature for relay compatibility         │    │
│  └─────────────────────────────────────────────────────┘    │
├─────────────────────────────────────────────────────────────┤
│                     TRANSPORT LAYER                          │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ Current: TLS 1.3 WebSocket                          │    │
│  │ Future:  QSSL (ML-KEM-768 + SPHINCS+)               │    │
│  └─────────────────────────────────────────────────────┘    │
├─────────────────────────────────────────────────────────────┤
│                     PERSISTENCE LAYER                        │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ Nostr Relays: Distributed storage                   │    │
│  │ IPFS: Content-addressed message storage             │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

## Cryptographic Algorithms

### ML-KEM-1024 (FIPS 203)
- **Purpose**: Key encapsulation for DM encryption
- **Security**: NIST Level 5 (256-bit classical / 128-bit quantum)
- **Key sizes**: Public key 1568 bytes, ciphertext 1568 bytes
- **Implementation**: `ml-kem` crate (pure Rust, WASM-compatible)

### SLH-DSA-SHAKE-128s (FIPS 205)
- **Purpose**: Post-quantum digital signatures
- **Security**: NIST Level 1 (128-bit classical / 64-bit quantum)
- **Signature size**: ~7,856 bytes
- **Public key**: 32 bytes
- **Implementation**: `fips205` crate (pure Rust, WASM-compatible)

### STARK Proofs (Winterfell)
- **Purpose**: Zero-knowledge message authentication
- **Security**: Post-quantum (hash-based)
- **Proof size**: Variable (~10-50 KB)
- **Implementation**: `winterfell` crate (pure Rust, WASM-compatible)

### AES-256-GCM
- **Purpose**: Symmetric encryption of message content
- **Security**: 256-bit (128-bit quantum due to Grover's algorithm)
- **Implementation**: `aes-gcm` crate

## Threat Model

### Adversary Capabilities

| Adversary | Can do | Cannot do |
|-----------|--------|-----------|
| Network observer | See encrypted traffic, connection timing, IP addresses | Read message content (ML-KEM + AES-256-GCM encrypted) |
| Quantum adversary | Break TLS 1.3, break Schnorr signatures | Break ML-KEM-1024, break SLH-DSA, break AES-256 |
| Compromised relay | See encrypted ciphertext, connection metadata | Decrypt messages (no access to ML-KEM private keys) |
| Malicious sender | Send spam, impersonate (without keys) | Forge STARK proofs or SLH-DSA signatures |

### Attack Scenarios

**1. Harvest Now, Decrypt Later (HNDL)**

A quantum adversary records encrypted traffic today and decrypts it when quantum computers are available.

| Layer | Protection |
|-------|------------|
| DM Encryption | **Protected.** ML-KEM-1024 is quantum-resistant. |
| Signatures | **Protected.** SLH-DSA is quantum-resistant. |
| Transport | **Exposed (current).** TLS 1.3 uses classical key exchange. |

**Mitigation**: QSSL transport (client ready, server pending) will provide full quantum-resistant transport.

**2. Man-in-the-Middle (MITM)**

| Layer | Protection |
|-------|------------|
| Transport | TLS certificate verification |
| Application | ML-KEM encapsulation to recipient's public key - only they can decrypt |
| Identity | STARK proofs + SLH-DSA verify sender authenticity |

**3. Key Compromise**

If a user's ML-KEM private key is compromised:
- Past messages remain secure (no forward secrecy in current design)
- Future messages can be decrypted
- **Mitigation**: Key rotation via PQ key publication (Kind 30078 events)

## QSSL Transport (Phase 3 - Client Ready)

QSSL provides post-quantum encrypted WebSocket transport:

| Component | Algorithm |
|-----------|-----------|
| Key Exchange | ML-KEM-768 |
| Authentication | SPHINCS+-SHA2-128f |
| Symmetric | AES-256-GCM |

**Current Status**:
- Client WASM module ready
- Identity generation and persistence working
- Server-side endpoint pending deployment

**When QSSL is active**:
- Full quantum resistance at transport layer
- Connection metadata protected
- IP address privacy (encrypted tunnel)

## Key Management

### Identity Keys

| Key Type | Storage | Purpose |
|----------|---------|---------|
| Nostr (secp256k1) | localStorage | Relay authentication, DM addressing |
| STARK | localStorage | Zero-knowledge message proofs |
| ML-KEM-1024 | localStorage | DM encryption key exchange |
| SLH-DSA | localStorage | Post-quantum event signatures |
| QSSL | localStorage | Transport encryption (when enabled) |

### Key Publication

- ML-KEM public keys are published as Kind 30078 events (NIP-33 replaceable)
- Tag format: `["ek", "<base64-ml-kem-public-key>"]`, `["d", "ml-kem-1024"]`
- Other users discover keys by subscribing to Kind 30078 with `#d: ["ml-kem-1024"]`

## Comparison with Classical Nostr

| Property | Classical Nostr (NIP-04) | Drista (Full PQC) |
|----------|-------------------------|-------------------|
| DM Encryption | ECDH (secp256k1) + AES-256-CBC | ML-KEM-1024 + AES-256-GCM |
| Signatures | Schnorr only | SLH-DSA + Schnorr |
| Message Auth | Schnorr signature | STARK proof + SLH-DSA |
| Quantum Resistance | None | Full (except transport) |
| Key Exchange | ECDH (vulnerable) | ML-KEM-1024 (resistant) |

## Security Considerations

### What is Protected

- **Message content**: End-to-end encrypted with ML-KEM-1024 + AES-256-GCM
- **Sender authenticity**: Verified via STARK proofs and SLH-DSA signatures
- **Key exchange**: Quantum-resistant via ML-KEM-1024

### What is Exposed (Current)

- **Transport metadata**: Connection timing, IP addresses (TLS protects content)
- **Relay visibility**: Relays see encrypted ciphertext and event metadata
- **Public keys**: ML-KEM public keys are published for discovery

### Future Improvements

1. **QSSL Server Deployment**: Enable full PQ transport
2. **Forward Secrecy**: Implement PQ Triple Ratchet for session key rotation
3. **Metadata Privacy**: Onion routing or mix networks for IP privacy
4. **Key Rotation**: Automated ML-KEM key rotation schedule
