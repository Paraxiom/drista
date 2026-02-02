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

Click any username to start an encrypted DM. Messages are E2E encrypted with NIP-04 — even validators can't read them.

---

## Why Drista?

| Feature | Drista | Signal | Telegram | Slack |
|---------|--------|--------|----------|-------|
| Post-quantum encryption | ✅ Falcon-512 | ❌ | ❌ | ❌ |
| Zero-knowledge identity | ✅ STARK proofs | ❌ | ❌ | ❌ |
| Decentralized | ✅ Blockchain | ❌ | ❌ | ❌ |
| No phone number required | ✅ | ❌ | ❌ | ✅ |
| Message persistence | ✅ On-chain | ❌ | ✅ | ✅ |
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
Your Device                          QuantumHarmony Network
┌──────────────┐                    ┌──────────────────────┐
│  Drista App  │                    │  Validator Nodes     │
│              │   E2E Encrypted    │                      │
│  Private Key ├───────────────────►│  Encrypted blobs     │
│  (local)     │   (NIP-04 + QSSH)  │  (can't decrypt)     │
└──────────────┘                    └──────────────────────┘
```

**What validators see:** Encrypted message blobs, sender public key, timestamp
**What validators can't see:** Message content, recipient identity (for DMs)

### Encryption Stack

| Layer | Algorithm | Protection Against |
|-------|-----------|-------------------|
| Transport | Falcon-512 + AES-256-GCM | Quantum computers, MITM |
| Messages | NIP-04 (ECDH + AES-256) | Server compromise |
| Identity | STARK proofs | Impersonation |

Full security analysis: [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md)

---

## For Developers

### Project Structure

```
drista/
├── crates/
│   ├── qcomm-core/     # Rust crypto: Falcon, SPHINCS+, STARK
│   ├── qcomm-wasm/     # Browser bindings
│   └── qcomm-ffi/      # Mobile/desktop bindings
├── web/
│   ├── bridge/         # NIP-01 relay ↔ Substrate
│   └── src/            # Preact UI
├── desktop/
│   └── src-tauri/      # Tauri shell
└── deploy/
    └── scripts/        # Validator setup
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
