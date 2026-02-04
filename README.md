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
- **Full PQC required** — Recipients must have published their PQ key (shown as "AWAITING PQ KEY" if not)
- **Key discovery** — PQ public keys are automatically published and discovered via Nostr
- **Dual signatures** — Events are signed with both SLH-DSA (post-quantum) and Schnorr (relay compatibility)

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

### What's Protected vs. What's Not

| Layer | Protection | Quantum-Safe? |
|-------|------------|---------------|
| Message content | ML-KEM-1024 + AES-256-GCM | ✅ Yes |
| Message relay | Multiple Nostr relays | ✅ Decentralized |
| Message storage | IPFS content-addressed | ✅ Decentralized |
| **Web app delivery** | Standard HTTPS/TLS | ❌ Classical crypto |
| **DNS lookup** | ISP sees domain | ❌ Metadata exposed |
| **Your IP address** | Server/relays see it | ❌ Not anonymous |

```
Your Browser
     │
     │ ← Standard HTTPS (NOT quantum-safe)
     ▼
drista.paraxiom.org  ← Centralized server, sees your IP
     │
     │ Downloads JavaScript
     ▼
┌─────────────────┐
│  Drista App     │
│  (in browser)   │
└────────┬────────┘
         │
         │ ← ML-KEM-1024 (quantum-safe) ← ONLY THIS IS PQC
         ▼
   Nostr Relays / IPFS
```

**What relays see:** Encrypted ciphertext, sender pubkey, timestamp, KEM ciphertext
**What relays can't see:** Message content, shared secrets, plaintext

### Privacy Levels

| Method | Content Security | IP Privacy | Metadata Privacy |
|--------|-----------------|------------|------------------|
| Web app (drista.paraxiom.org) | ✅ PQC | ❌ Exposed | ❌ Exposed |
| Web app + Tor | ✅ PQC | ✅ Hidden | ⚠️ Timing attacks |
| Desktop app | ✅ PQC | ❌ Exposed | ❌ Exposed |
| Desktop app + Tor | ✅ PQC | ✅ Hidden | ⚠️ Timing attacks |
| Self-hosted + Tor | ✅ PQC | ✅ Hidden | ✅ Better |

**Important:** Tor uses classical cryptography. A "harvest now, decrypt later" attacker could correlate your traffic in the future. See [Achieving Full PQC Privacy](#achieving-full-pqc-privacy) below.

### Achieving Full PQC Privacy

**The problem:** Tor, VPNs, and mixnets all use classical cryptography (RSA, Curve25519). An adversary can:
1. Capture your encrypted traffic today
2. Wait for quantum computers
3. Decrypt the *transport layer* to see metadata (who talked to whom, when)

**Your message content is safe** (ML-KEM-1024), but **metadata is not**.

**Current options (none are perfect):**

| Approach | Pros | Cons |
|----------|------|------|
| Tor + Drista | Hides IP today | Tor crypto is classical, metadata harvestable |
| VPN + Drista | Easy setup | VPN provider sees everything, classical crypto |
| Self-host relay on .onion | No central server | Still classical Tor crypto |
| Desktop app (no web) | No JS trust issues | IP still exposed without Tor |

**Future solutions being developed:**

1. **Tor Project** — Researching PQC integration ([blog post](https://blog.torproject.org/))
2. **Nym mixnet** — Planning PQC upgrade
3. **PQTLS** — Chrome/Cloudflare testing Kyber in TLS 1.3

**For maximum privacy today:**

```bash
# 1. Build from source (don't trust web delivery)
git clone https://github.com/Paraxiom/drista.git
cd drista/web && npm install && npm run build

# 2. Verify the build matches release hashes
sha256sum dist/assets/*.js

# 3. Run behind Tor (hides IP, classical crypto for transport)
torsocks npm run dev
# Or access via Tor Browser

# 4. Use multiple identities across sessions (limits correlation)
```

**Do we need to write a PQC Tor?**

Yes, eventually. The components needed:
- PQC key exchange for circuit establishment (ML-KEM)
- PQC signatures for relay authentication (SPHINCS+, Dilithium)
- PQC onion encryption layers

This is a massive undertaking. In the meantime, Drista's approach is:
- **Defense in depth**: Even if Tor transport is broken later, message content remains PQC-protected
- **Metadata minimization**: Nostr's design doesn't require account registration
- **Relay diversity**: Messages go through multiple independent relays

### Encryption Stack (Full PQC - v0.1.0)

| Layer | Algorithm | Standard | Protection Against |
|-------|-----------|----------|-------------------|
| DM Encryption | ML-KEM-1024 + AES-256-GCM | FIPS 203 | Quantum computers, MITM |
| Signatures | SLH-DSA + Schnorr | FIPS 205 + BIP-340 | Forgery (PQ + relay compat) |
| Message Auth | STARK Proofs | Winterfell ZK | Impersonation |
| Key Derivation | HKDF-SHA256 | RFC 5869 | Key reuse attacks |
| Storage | IPFS + content hashing | - | Data loss, tampering |
| Transport | TLS 1.3 (QSSL ready) | RFC 8446 | Eavesdropping |

**Note:** No classical fallback (NIP-04 removed). Recipients must have a PQ key published.

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

We need help building for different platforms! If you can build on your machine, please contribute.

#### Prerequisites (All Platforms)

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install Tauri CLI
cargo install tauri-cli

# Clone and prep
git clone https://github.com/Paraxiom/drista.git
cd drista/web && npm install && npm run build
```

#### macOS (Apple Silicon)

```bash
# No extra deps needed
cd desktop/src-tauri
cargo tauri build

# Output: target/release/bundle/macos/Drista.app
# Package: zip -r Drista-macos-arm64.zip target/release/bundle/macos/Drista.app
```

#### macOS (Intel)

```bash
# Add Intel target
rustup target add x86_64-apple-darwin

cd desktop/src-tauri
cargo tauri build --target x86_64-apple-darwin

# Output: target/x86_64-apple-darwin/release/bundle/macos/Drista.app
# Package: zip -r Drista-macos-x64.zip target/x86_64-apple-darwin/release/bundle/macos/Drista.app
```

#### Linux (Ubuntu/Debian)

```bash
# Install dependencies
sudo apt update
sudo apt install -y libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf

cd desktop/src-tauri
cargo tauri build

# Output: target/release/bundle/appimage/Drista_*.AppImage
# Package: mv target/release/bundle/appimage/*.AppImage Drista-linux-x64.AppImage
```

#### Windows

```powershell
# Install Visual Studio Build Tools with C++ workload
# https://visualstudio.microsoft.com/visual-cpp-build-tools/

cd desktop\src-tauri
cargo tauri build

# Output: target\release\bundle\msi\Drista_*.msi
# Package: copy target\release\bundle\msi\*.msi Drista-windows-x64.msi
```

#### Contributing Builds

Built for your platform? Help us out:

1. Open an issue with your platform details
2. Attach the packaged binary (zip/AppImage/msi)
3. We'll verify and add it to https://drista.paraxiom.org/downloads

Or email directly: sylvain@paraxiom.org

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
