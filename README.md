# Drista — दृष्टा

**Post-quantum secure chat for Paraxiom collaborators.**

Messages are end-to-end encrypted, authenticated with zero-knowledge proofs, and stored on the QuantumHarmony blockchain. No central server has access to your messages.

---

## Quick Install

### Web (Fastest)

Open in your browser — no installation required:

```
https://drista.paraxiom.org
```

### Desktop (macOS/Linux/Windows)

```bash
# One-line install
curl -fsSL https://drista.paraxiom.org/install.sh | sh

# Or with Homebrew (macOS)
brew install paraxiom/tap/drista
```

### From Source

```bash
git clone https://github.com/Paraxiom/drista.git
cd drista

# Web version
cd web && npm install && npm run dev

# Desktop version
cd desktop/src-tauri && cargo tauri build
```

---

## Getting Started

### 1. Create Your Identity

When you first open Drista, you'll generate a cryptographic identity:
- **Public key** — Share this with collaborators
- **Private key** — Keep this secret (stored locally, encrypted)

Your identity is verified with STARK zero-knowledge proofs — you prove you authored a message without revealing your private key.

### 2. Join Channels

Default channels for Paraxiom collaborators:
- `#general` — General discussion
- `#dev` — Development coordination
- `#kirq` — KIRQ network operations
- `#research` — Papers and publications

### 3. Direct Messages

Click any username to start an encrypted DM. Messages are encrypted with **ML-KEM-1024 + AES-256-GCM** — post-quantum secure encryption that protects against both classical and quantum computers.

- **PQC badge** — Messages show a cyan "PQC" badge when using post-quantum encryption
- **Automatic upgrade** — Falls back to NIP-04 for contacts without PQ keys
- **Key discovery** — PQ public keys are automatically published and discovered via Nostr

---

## Why Drista?

| Feature | Drista | Signal | Telegram | Slack |
|---------|--------|--------|----------|-------|
| Post-quantum encryption | ✅ ML-KEM-1024 | ❌ | ❌ | ❌ |
| Zero-knowledge identity | ✅ STARK proofs | ❌ | ❌ | ❌ |
| Decentralized | ✅ Nostr + IPFS | ❌ | ❌ | ❌ |
| No phone number required | ✅ | ❌ | ❌ | ✅ |
| Message persistence | ✅ On-chain + IPFS | ❌ | ✅ | ✅ |
| Open source | ✅ | ✅ | ❌ | ❌ |

---

## Network Status

Three validators run the chat infrastructure:

| Node | Location | Status |
|------|----------|--------|
| Alice | Montreal | `wss://51.79.26.123:7778` |
| Bob | Beauharnois | `wss://51.79.26.168:7778` |
| Charlie | Frankfurt | `wss://209.38.225.4:7778` |

Check network health: `https://status.paraxiom.org`

---

## Security Model

```
Your Device                          Nostr Relays / IPFS
┌──────────────┐                    ┌──────────────────────┐
│  Drista App  │                    │  Relay Nodes         │
│              │   E2E Encrypted    │                      │
│  ML-KEM Key  ├───────────────────►│  Encrypted blobs     │
│  STARK ID    │   (ML-KEM + AES)   │  (can't decrypt)     │
│  (local)     │                    │                      │
└──────────────┘                    └──────────────────────┘
```

**What relays see:** Encrypted ciphertext, sender pubkey, timestamp, KEM ciphertext
**What relays can't see:** Message content, shared secrets, plaintext

### Encryption Stack

| Layer | Algorithm | Protection Against |
|-------|-----------|-------------------|
| DM Encryption | ML-KEM-1024 + AES-256-GCM | Quantum computers, MITM |
| Key Derivation | HKDF-SHA256 | Key reuse attacks |
| Identity | STARK proofs | Impersonation |
| Storage | IPFS + content hashing | Data loss, tampering |
| Fallback | NIP-04 (ECDH + AES-256) | Legacy compatibility |

Full security analysis: [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md)

### PQ-DM Protocol

Post-quantum encrypted direct messages use ML-KEM-1024 (FIPS 203) for key encapsulation:

```
Sender                              Recipient
   |                                    |
   |-- Fetch recipient's EK (1568 B) -->|
   |                                    |
   |-- Encapsulate(EK) ---------------> |
   |   -> ciphertext (1568 B)           |
   |   -> shared_secret (32 B)          |
   |                                    |
   |-- HKDF(shared_secret) -----------> |
   |   -> AES key (32 B)                |
   |                                    |
   |-- AES-256-GCM(message) ----------> |
   |                                    |
   |-- Send kind 20004 event ---------->|
   |   content: KEM_CT + nonce + AES_CT |
   |                                    |
   |                   Decapsulate(CT) -|
   |                   -> shared_secret |
   |                   HKDF -> AES key  |
   |                   AES decrypt      |
```

**Nostr Event Kinds:**
- `30078` — PQ key publication (encapsulation key, replaceable)
- `20004` — PQ encrypted DM

---

## For Developers

### Project Structure

```
drista/
├── crates/
│   ├── qcomm-core/     # Rust crypto: ML-KEM, SPHINCS+, STARK
│   ├── qcomm-wasm/     # Browser WASM bindings
│   └── qcomm-ffi/      # Mobile/desktop bindings
├── web/
│   ├── bridge/         # NIP-01 relay bridge
│   ├── src/
│   │   ├── lib/
│   │   │   ├── pq-dm.js      # PQ-DM encryption (ML-KEM-1024)
│   │   │   ├── nostr.js      # Nostr protocol client
│   │   │   └── ipfs.js       # IPFS hybrid storage
│   │   └── components/       # Preact UI
│   └── tests/                # Test suites (43 tests)
├── desktop/
│   └── src-tauri/      # Tauri shell
└── deploy/
    └── scripts/        # Deployment scripts
```

### Run Locally

```bash
# Start the bridge (connects to production validators)
cd web
npm install
npm run bridge &

# Start web UI
npm run dev
# Open http://localhost:5173
```

### Run Tests

```bash
cd web

# PQ Crypto tests (21 tests)
node --experimental-wasm-modules tests/pq-crypto.test.js

# PQ-DM tests (11 tests)
node --experimental-wasm-modules tests/pq-dm.test.js

# Extended tests (11 tests)
node --experimental-wasm-modules tests/pq-dm-extended.test.js
```

### Build Desktop App

```bash
cd desktop/src-tauri
cargo tauri build
# Binary in target/release/bundle/
```

### Run Your Own Validator

See [docs/QSSH_BRIDGE_TRANSPORT.md](docs/QSSH_BRIDGE_TRANSPORT.md)

---

## Troubleshooting

### Can't connect to network

```bash
# Check if validators are reachable
curl -I https://51.79.26.123:7778
```

If all validators are down, check `#status` on the backup channel or contact sylvain@paraxiom.org

### Messages not sending

1. Check your internet connection
2. Refresh the page / restart the app
3. Your identity may have expired — regenerate it

### Lost private key

Your messages are E2E encrypted with your private key. If you lose it:
- You cannot decrypt old messages
- Generate a new identity and notify collaborators

---

## Contact

- **Issues:** https://github.com/Paraxiom/drista/issues
- **Email:** sylvain@paraxiom.org
- **Backup channel:** Signal group (ask for invite)

---

## License

MIT OR Apache-2.0

---

*Drista (दृष्टा) — Sanskrit for "the seer" or "witness"*
