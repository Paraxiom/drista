# Drista — दृष्टा

Post-quantum encrypted chat over a Substrate blockchain.

Messages are end-to-end encrypted (NIP-04), authenticated with STARK zero-knowledge proofs (Winterfell), and persisted on-chain through the Mesh Forum pallet. Transport is secured by QSSH (Falcon-512 lattice-based tunnels) for native clients, with TLS 1.3 fallback for browsers.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Drista App (Preact / Tauri)                            │
│  NIP-04 E2E encryption · STARK identity proofs          │
└──────────────┬──────────────────────┬───────────────────┘
               │                      │
     ┌─────────▼─────────┐  ┌────────▼────────┐
     │  QSSH Tunnel      │  │  TLS 1.3 Proxy  │
     │  Falcon-512        │  │  nginx :7778    │
     │  AES-256-GCM       │  │  (browsers)     │
     │  :4242             │  │                 │
     └─────────┬─────────┘  └────────┬────────┘
               │                      │
         ┌─────▼──────────────────────▼──────┐
         │  NIP-01 Bridge (127.0.0.1:7777)   │
         │  WebSocket relay · chunking        │
         └──────────────┬────────────────────┘
                        │
              ┌─────────▼─────────┐
              │  Substrate Node   │
              │  Mesh Forum pallet│
              │  :9944            │
              └───────────────────┘
```

The bridge only listens on localhost. The blockchain is the persistence and consensus layer — users just see a chat app.

## Quick Start

```bash
# Web UI + bridge
cd web
npm install
npm run bridge &    # NIP-01 relay on localhost:7777
npm run dev         # Vite dev server

# Desktop (Tauri)
cd desktop/src-tauri
cargo tauri dev
```

## Project Structure

```
crates/
  qcomm-core/       Rust core: crypto (Falcon, SPHINCS+, AES-GCM), transport, STARK proofs
  qcomm-wasm/       WASM bindings for browser
  qcomm-ffi/        UniFFI bindings for mobile/desktop
web/
  bridge/            NIP-01 WebSocket relay ↔ Substrate Mesh Forum
  relay/             Standalone Nostr relay
  src/
    components/      Preact UI (LCARS theme)
    lib/             Nostr client, STARK identity, WASM loader
desktop/
  src-tauri/         Tauri desktop shell
deploy/
  qsshd/             Dockerfile, compose, config for PQ tunnel server
  nginx/             TLS WebSocket proxy config
  qssh-client/       Client tunnel config template
  scripts/           Validator and client setup automation
docs/
  QSSH_BRIDGE_TRANSPORT.md   Architecture and deployment guide
  SECURITY_MODEL.md           Threat model and security analysis
```

## Security Layers

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Transport | Falcon-512 + AES-256-GCM (QSSH) | Post-quantum tunnel encryption |
| Transport (fallback) | TLS 1.3 (nginx) | Classical encryption for browsers |
| Application | NIP-04 ECDH + AES-256-CBC | End-to-end message encryption |
| Identity | STARK proofs (Winterfell) | Zero-knowledge authorship verification |
| Persistence | Substrate consensus | Tamper-proof on-chain message storage |

Even over the classical TLS fallback, message content is E2E encrypted via NIP-04. See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) for the full threat model.

## Transport Paths

**Native/Desktop** — Full post-quantum:
```
App → qssh tunnel (:4242) [Falcon-512] → Bridge (localhost:7777) → Substrate
```

**Browser** — TLS fallback:
```
Browser → wss://:7778 [TLS 1.3] → Bridge (localhost:7777) → Substrate
```

## Validators

Three QuantumHarmony validators run the Mesh Forum pallet and bridge:

| Name | Location | QSSH | WSS |
|------|----------|------|-----|
| Alice | Montreal | 51.79.26.123:4242 | 51.79.26.123:7778 |
| Bob | Beauharnois | 51.79.26.168:4242 | 51.79.26.168:7778 |
| Charlie | Frankfurt | 209.38.225.4:4242 | 209.38.225.4:7778 |

## Deployment

```bash
# Validator setup (builds qsshd, generates keys, configures nginx)
./deploy/scripts/setup-validator.sh

# Client setup (builds qssh, generates keypair, installs config)
./deploy/scripts/setup-client.sh

# Connect via PQ tunnel
qssh qh-alice
```

See [docs/QSSH_BRIDGE_TRANSPORT.md](docs/QSSH_BRIDGE_TRANSPORT.md) for full deployment instructions.

## Tech Stack

- **Rust** — qcomm-core (crypto, transport, STARK proofs), qssh, Substrate runtime
- **Preact + Signals** — Reactive web UI with LCARS theme
- **Tauri** — Desktop shell
- **Substrate** — Mesh Forum pallet for on-chain message persistence
- **Winterfell** — STARK zero-knowledge proofs
- **Falcon-512** — Post-quantum signatures (NIST PQC)
- **Nostr NIP-01/NIP-04** — Relay protocol and E2E encryption

## License

MIT OR Apache-2.0
