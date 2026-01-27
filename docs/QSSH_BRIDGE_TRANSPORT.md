# QSSH Bridge Transport

Post-quantum secured transport for the QuantumHarmony NIP-01 bridge using QSSH (Falcon-512 encrypted tunnels).

## Architecture Overview

The bridge no longer listens on public interfaces. All external access goes through one of two paths:

```
PATH A — Native/Desktop (Full Post-Quantum):
  App → qssh -L 7777:localhost:7777 → qsshd:4242 [Falcon-512 + AES-256-GCM] → Bridge 127.0.0.1:7777

PATH B — Browser (Classical TLS fallback):
  Browser → wss://validator:7778 → nginx [TLS 1.3] → Bridge 127.0.0.1:7777

Both paths:
  Bridge 127.0.0.1:7777 → ws://127.0.0.1:9944 → Substrate Mesh Forum pallet → chain consensus
```

The bridge binds **only** to `127.0.0.1`. Port 7777 is never exposed externally.

### Components

| Component | Port | Protocol | Purpose |
|-----------|------|----------|---------|
| Bridge | 127.0.0.1:7777 | ws:// | NIP-01 relay (localhost only) |
| qsshd | 0.0.0.0:4242 | QSSH | Falcon-512 PQ tunnel server |
| nginx | 0.0.0.0:7778 | wss:// | TLS 1.3 WebSocket proxy |
| Substrate | 127.0.0.1:9944 | ws:// | JSON-RPC (Mesh Forum pallet) |

### Message Flow

1. Client sends NIP-01 `EVENT` via WebSocket (through QSSH tunnel or TLS proxy)
2. Bridge receives on `127.0.0.1:7777`, stores in-memory, broadcasts to local subscribers
3. Bridge posts event to Substrate Mesh Forum pallet via `forum_postMessage` RPC
4. Other validators pick up the event through chain consensus
5. Other bridges deliver to their local subscribers

## Transport Security Tiers

The app detects which transport path is active and displays it in the InfoPanel:

| Tier | Meaning | When |
|------|---------|------|
| `PQ-SECURED` | All connections via QSSH Falcon-512 tunnel | Only `ws://localhost` relays connected |
| `HYBRID` | Mix of QSSH and TLS connections | Both local and `wss://` relays connected |
| `TLS` | All connections via classical TLS | Only `wss://` relays connected |
| `NONE` | No transport encryption | No relays connected |

Even at `TLS` tier, message **content** is E2E encrypted via NIP-04 (ECDH + AES-CBC). TLS fallback only leaks metadata (who talks to whom), not message content.

## Deployment

### Validator Setup

Run on each validator node:

```bash
./deploy/scripts/setup-validator.sh --qssh-src ~/qssh --bridge-dir ~/quantum-communicator
```

This will:
1. Build qsshd from source
2. Generate Falcon-512 host keys
3. Generate self-signed TLS cert for nginx
4. Install configs for qsshd and nginx
5. Set bridge to bind `127.0.0.1` only
6. Start qsshd (port 4242) and nginx (port 7778)
7. Verify services are running

**Firewall:** Open ports 4242 (QSSH) and 7778 (WSS). Do NOT expose port 7777.

### Client Setup

Run on native/desktop clients:

```bash
./deploy/scripts/setup-client.sh --qssh-src ~/qssh
```

This will:
1. Build the qssh client
2. Generate Falcon-512 client keypair
3. Install `~/.qssh/config` with validator entries
4. Print the public key (give to validator admin)
5. Test connectivity to each validator

### Adding Client Keys to Validators

After client setup, the validator admin adds the client's public key:

```bash
# On the validator
cat >> /etc/qssh/authorized_keys <<< "falcon512 <client-public-key> user@host"
```

### Connecting

```bash
# Native client — establishes PQ-secured tunnel
qssh qh-alice

# Browser — uses wss://51.79.26.123:7778 (TLS fallback, auto-configured in relay list)
```

Once the QSSH tunnel is active, the app connects via `ws://localhost:7777` and shows `TRANSPORT: PQ-SECURED` in the InfoPanel.

## Docker Deployment

For containerized deployments:

```bash
cd deploy/qsshd
# Generate host keys first
mkdir -p keys
qssh-keygen --host-key -f keys/host_key

# Generate TLS cert
mkdir -p ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout ssl/bridge.key -out ssl/bridge.crt \
  -subj "/CN=quantumharmony-bridge"

# Start qsshd + nginx
docker compose -f docker-compose.qssh.yml up -d
```

Both containers use `network_mode: host` so they can reach the bridge on `127.0.0.1:7777`.

## Local Development

For local development without QSSH:

```bash
# Start bridge (defaults to 127.0.0.1)
cd web/bridge && node index.js

# Start dev server
cd web && npm run dev
```

The app connects to `ws://localhost:7777` directly. The InfoPanel shows `PQ-SECURED` because it detects a localhost connection (in dev this is technically unencrypted, but the detection logic treats localhost as PQ-secured since in production it would be a QSSH tunnel endpoint).

### Local Verification with QSSH

```bash
# 1. Build qssh
cd ~/qssh && cargo build --release

# 2. Generate test keys
mkdir -p /tmp/qssh-test
./target/release/qssh-keygen --host-key -f /tmp/qssh-test/host_key
./target/release/qssh-keygen -f /tmp/qssh-test/client_key

# 3. Start qsshd
./target/release/qsshd --listen 127.0.0.1:4242 --host-key /tmp/qssh-test/host_key

# 4. Start bridge
BRIDGE_HOST=127.0.0.1 node ~/quantum-communicator/web/bridge/index.js

# 5. Establish tunnel
./target/release/qssh -L 7777:localhost:7777 localhost -p 4242

# 6. Test NIP-01
node -e "new (require('ws'))('ws://localhost:7777').on('open', function(){this.send(JSON.stringify(['REQ','t',[{kinds:[1],limit:1}]]));}).on('message',d=>{console.log(''+d);process.exit()})"

# 7. Start app
cd ~/quantum-communicator/web && npm run dev
# → InfoPanel shows TRANSPORT: PQ-SECURED
```

## Configuration Reference

### Environment Variables (Bridge)

| Variable | Default | Description |
|----------|---------|-------------|
| `BRIDGE_HOST` | `127.0.0.1` | Bind address. Use `0.0.0.0` in Docker (container isolation). |
| `BRIDGE_PORT` | `7777` | WebSocket listen port |
| `RPC_URL` | `ws://127.0.0.1:9944` | Substrate JSON-RPC endpoint |

### Relay List (`web/src/lib/nostr.js`)

```js
export const DEFAULT_RELAYS = [
  'ws://localhost:7777',             // QSSH tunnel endpoint
  'wss://51.79.26.123:7778',        // Alice — TLS fallback
  'wss://51.79.26.168:7778',        // Bob — TLS fallback
  'wss://209.38.225.4:7778',        // Charlie — TLS fallback
];
```

## Future: Full PQ Browser Path

When Falcon-512 WASM bindings are available, browsers can perform the PQ key exchange directly, eliminating the TLS fallback entirely. The upgrade path:

1. Compile Falcon-512 to WASM
2. Implement QSSH handshake in JavaScript
3. Browser connects directly to qsshd on port 4242
4. Remove nginx TLS proxy
5. All paths become PQ-secured
