# Drista Requirements & Status

## Project Goal
Build a **post-quantum secure, decentralized chat application** for Paraxiom collaborators.

---

## Requirements Matrix

### 1. Core Cryptography

| Requirement | Status | Implementation | Notes |
|-------------|--------|----------------|-------|
| ML-KEM-1024 key encapsulation | ✅ Done | `qcomm-core/crypto/pq.rs` | NIST FIPS 203 |
| SPHINCS+ signatures | ✅ Done | `qcomm-core/crypto/pq.rs` | NIST FIPS 205 |
| AES-256-GCM symmetric encryption | ✅ Done | CLI + Web | Authenticated encryption |
| HKDF-SHA256 key derivation | ✅ Done | CLI + Web | RFC 5869 |
| NIP-04 (ECDH + AES-CBC) | ✅ Done | CLI + Web | Legacy fallback |
| Triple Ratchet (forward secrecy) | ✅ Done | Web (WASM) | `qcomm-core/crypto/ratchet.rs` |
| STARK zero-knowledge proofs | ✅ Done | Web + WASM | Winterfell library |

### 2. Messaging Protocol

| Requirement | Status | Implementation | Notes |
|-------------|--------|----------------|-------|
| Nostr NIP-01 (basic protocol) | ✅ Done | CLI + Web | Event signing, relay comm |
| Nostr NIP-04 (encrypted DM) | ✅ Done | CLI + Web | Kind 4 |
| PQ-DM (Kind 20004) | ✅ Done | CLI + Web | ML-KEM + AES-GCM |
| PQ key publication (Kind 30078) | 🔶 Partial | Defined | Auto-publish not implemented |
| PQ key discovery | 🔶 Partial | Manual | Auto-discovery not implemented |
| Message persistence | ✅ Done | localStorage + Nostr | IPFS optional |

### 3. Transport Layer

| Requirement | Status | Implementation | Notes |
|-------------|--------|----------------|-------|
| WebSocket to Nostr relays | ✅ Done | CLI + Web | Multiple relay support |
| Relay reconnection | ✅ Done | Web (10 attempts) | Exponential backoff |
| Fallback relays | ✅ Done | relay.damus.io, nos.lol | Public fallbacks |
| BLE mesh transport | 🔶 Partial | `qcomm-core/transport/ble.rs` | Code exists, not integrated |
| QSSL (PQ TLS) | 🔶 Partial | `web/src/lib/qssl-transport.js` | Code exists, not default |

### 4. User Interface

| Requirement | Status | Implementation | Notes |
|-------------|--------|----------------|-------|
| Web app (Preact) | ✅ Done | `web/src/` | LCARS-inspired design |
| Channel list | ✅ Done | `ChannelList.jsx` | Forums + DMs |
| Chat view | ✅ Done | `ChatView.jsx` | Messages + input |
| DM creation modal | ✅ Done | `Modal.jsx` | Enter pubkey |
| Send status feedback | ✅ Done | `store.js` | Error/success indicators |
| Desktop app (Tauri) | ✅ Done | `desktop/src-tauri/` | macOS/Linux/Windows |
| CLI | ✅ Done | `drista-cli/` | Interactive + batch mode |

### 5. Identity & Authentication

| Requirement | Status | Implementation | Notes |
|-------------|--------|----------------|-------|
| Nostr keypair generation | ✅ Done | CLI + Web | secp256k1 Schnorr |
| ML-KEM keypair generation | ✅ Done | CLI + Web | 1568-byte public key |
| STARK identity | ✅ Done | Web (WASM) | ZK proof signing |
| Key persistence | ✅ Done | localStorage | ⚠️ Not encrypted |
| Key export/import | ❌ Not done | - | Needed for backup |

### 6. Testing

| Requirement | Status | Implementation | Notes |
|-------------|--------|----------------|-------|
| Unit tests (Rust) | ✅ Done | `cargo test` | 7 CLI tests, qcomm-core tests |
| Unit tests (JS) | ✅ Done | `test-pq-dm.mjs` | Crypto compatibility tests |
| Integration tests | ✅ Done | `tests/windmill/` | CLI ↔ Web crypto verified |
| E2E tests | ✅ Done | Windmill | `tests/windmill/workflow.yaml` |
| CI/CD pipeline | ❌ Not done | - | GitHub Actions needed |

### 7. Deployment

| Requirement | Status | Implementation | Notes |
|-------------|--------|----------------|-------|
| Web hosting | ✅ Done | drista.paraxiom.org | Nginx |
| Nostr relay bridge | ✅ Done | `web/bridge/` | Connects to validators |
| PWA support | ✅ Done | manifest.json | Mobile install |
| Desktop builds | ✅ Done | Tauri | macOS tested |

---

## Current Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         DRISTA                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐        │
│  │   Web App   │    │  Desktop    │    │    CLI      │        │
│  │  (Preact)   │    │  (Tauri)    │    │   (Rust)    │        │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘        │
│         │                  │                  │                │
│         ▼                  ▼                  ▼                │
│  ┌─────────────────────────────────────────────────────┐      │
│  │              Nostr Protocol Layer                    │      │
│  │  • NIP-04 (Kind 4) - Classical DM                   │      │
│  │  • PQ-DM (Kind 20004) - Post-Quantum DM             │      │
│  └──────────────────────┬──────────────────────────────┘      │
│                         │                                      │
│  ┌──────────────────────▼──────────────────────────────┐      │
│  │              Cryptography Layer                      │      │
│  │  ┌──────────────┐  ┌──────────────┐  ┌───────────┐ │      │
│  │  │  ML-KEM-1024 │  │   SPHINCS+   │  │  AES-GCM  │ │      │
│  │  │  (FIPS 203)  │  │  (FIPS 205)  │  │  (FIPS197)│ │      │
│  │  └──────────────┘  └──────────────┘  └───────────┘ │      │
│  │  ┌──────────────┐  ┌──────────────┐  ┌───────────┐ │      │
│  │  │Triple Ratchet│  │    STARK     │  │   HKDF    │ │      │
│  │  │(fwd secrecy) │  │  (ZK proofs) │  │ (SHA-256) │ │      │
│  │  └──────────────┘  └──────────────┘  └───────────┘ │      │
│  └─────────────────────────────────────────────────────┘      │
│                                                                 │
│  ┌─────────────────────────────────────────────────────┐      │
│  │              Transport Layer                         │      │
│  │  • WebSocket (Nostr relays)                         │      │
│  │  • QSSL (optional PQ transport)                     │      │
│  │  • BLE Mesh (future)                                │      │
│  └─────────────────────────────────────────────────────┘      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │        Nostr Relays           │
              │  • relay.damus.io (public)    │
              │  • drista.paraxiom.org (own)  │
              │  • nos.lol (public)           │
              └───────────────────────────────┘
```

---

## Progress Summary

### Completed (✅)
- [x] ML-KEM-1024 integration in CLI and Web
- [x] NIP-04 encrypted DMs (classical)
- [x] PQ-DM (Kind 20004) with ML-KEM + AES-GCM
- [x] CLI with keygen, send, send-pq commands
- [x] Web app with real-time messaging
- [x] Format compatibility between CLI and Web
- [x] Multiple relay support with fallbacks
- [x] Error feedback in UI

### In Progress (🔶)
- [ ] PQ key auto-discovery
- [ ] BLE mesh integration

### Not Started (❌)
- [ ] Key export/import (backup)
- [ ] CI/CD pipeline
- [ ] Mobile apps (iOS/Android)
- [ ] Group encrypted channels

### Recently Completed
- [x] Windmill E2E test automation (`tests/windmill/`)

---

## Test Coverage

### Rust (CLI + qcomm-core)
```
drista-cli:     7 tests (NIP-04, PQ-DM, event signing)
qcomm-core:    15 tests (ML-KEM, SPHINCS+, ratchet)
```

### JavaScript (Web)
```
test-pq-dm.mjs: 4 tests (format, HKDF, AES-GCM)
```

### Manual Tests Performed
- [x] CLI keygen
- [x] CLI send (NIP-04)
- [x] CLI send-pq (ML-KEM)
- [x] Web app connect to relay
- [x] Web app receive NIP-04 DM
- [x] CLI → Web PQ-DM (format compatible)

---

## Next Steps (Priority Order)

1. **Windmill E2E Tests** - Automate CLI ↔ Web testing
2. **PQ Key Discovery** - Auto-fetch peer PQ keys from Nostr
3. **CI/CD Pipeline** - GitHub Actions for builds + tests
4. **Key Backup** - Export/import identity keys
5. **BLE Mesh** - Enable offline P2P messaging

---

## Dependencies

### Rust
- `pqcrypto-mlkem` - ML-KEM-1024
- `pqcrypto-sphincsplus` - SPHINCS+ signatures
- `aes-gcm` - Authenticated encryption
- `secp256k1` - Nostr signatures
- `tokio-tungstenite` - WebSocket

### JavaScript
- `@noble/secp256k1` - Nostr signatures
- `@noble/hashes` - SHA-256, HKDF
- `preact` - UI framework
- `ml-kem` (WASM) - ML-KEM-1024

---

*Last updated: 2026-02-04*
