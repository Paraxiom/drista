# Drista Windmill E2E Tests

Automated end-to-end tests for the Drista post-quantum messaging application using [Windmill](https://windmill.dev).

## Quick Start

### Local Testing (without Windmill)

Run tests locally using the shell scripts directly:

```bash
# Build CLI first
./scripts/build-cli.sh

# Run individual tests
./scripts/test-cli-keygen.sh
./scripts/test-cli-pq-keygen.sh
./scripts/test-nip04-roundtrip.sh
./scripts/test-pqdm-roundtrip.sh

# Run TypeScript tests with Deno
deno run --allow-net --allow-read --allow-env scripts/test-crypto-primitives.ts
deno run --allow-net --allow-env scripts/test-web-integration.ts
deno run --allow-net --allow-read --allow-env --allow-run scripts/test-cli-web-e2e.ts

# Generate report
./scripts/generate-report.sh
```

### With Windmill

1. Install Windmill CLI:
   ```bash
   npm install -g windmill-cli
   ```

2. Login to your Windmill workspace:
   ```bash
   wmill workspace add
   ```

3. Push the workflow:
   ```bash
   wmill flow push ./workflow.yaml
   ```

4. Run the workflow:
   ```bash
   wmill flow run drista/e2e-tests
   ```

## Test Structure

```
tests/windmill/
├── workflow.yaml          # Windmill workflow definition
├── README.md              # This file
├── scripts/
│   ├── build-cli.sh           # Build Drista CLI
│   ├── test-cli-keygen.sh     # Test Nostr keygen
│   ├── test-cli-pq-keygen.sh  # Test ML-KEM-1024 keygen
│   ├── test-nip04-roundtrip.sh    # Test NIP-04 encryption
│   ├── test-pqdm-roundtrip.sh     # Test PQ-DM encryption
│   ├── test-crypto-primitives.ts  # Crypto compatibility tests
│   ├── test-web-integration.ts    # Web app tests
│   ├── test-cli-web-e2e.ts        # Full E2E tests
│   └── generate-report.sh         # Report generation
└── reports/               # Generated test reports
```

## Test Coverage

### CLI Tests
- **Keygen**: Validates Nostr keypair generation (64-char hex keys)
- **PQ Keygen**: Validates ML-KEM-1024 keypair generation (1568-byte public key)
- **NIP-04**: Tests AES-256-CBC encryption roundtrip
- **PQ-DM**: Tests ML-KEM + AES-256-GCM encryption roundtrip

### Crypto Compatibility Tests
- HKDF-SHA256 key derivation (info="pq-dm-v1")
- AES-256-GCM encrypt/decrypt
- PQ-DM message format parsing
- Nonce size detection (CLI vs Triple Ratchet)
- NIP-04 format validation

### Web Integration Tests
- Web app accessibility
- Static asset loading
- WASM module availability
- Crypto library dependencies
- Relay configuration

### E2E Tests
- CLI Nostr keygen → validates output format
- CLI PQ keygen → validates ML-KEM-1024 key size
- Crypto parameter alignment between CLI and Web
- Rust unit test execution
- JavaScript integration test execution

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DRISTA_ROOT` | `/Users/sylvaincormier/QuantumVerseProtocols/drista` | Project root |
| `DRISTA_CLI_PATH` | `$DRISTA_ROOT/target/release/drista` | CLI binary path |
| `DRISTA_RELAY` | `wss://relay.damus.io` | Default Nostr relay |
| `DRISTA_WEB_URL` | `http://localhost:3004` | Web app URL |
| `TEST_TIMEOUT` | `30000` | Test timeout in ms |

## Manual E2E Testing

For full relay integration testing:

1. **Start Web App**:
   ```bash
   cd web && npm run dev
   ```

2. **Get Web App's PQ Public Key**:
   Open browser console and run:
   ```javascript
   localStorage.getItem('pq_identity_keypair')
   ```

3. **Send PQ-DM from CLI**:
   ```bash
   drista send-pq \
     --to <nostr_pubkey> \
     --to-pq <pq_pubkey_base64> \
     --privkey <your_privkey> \
     "Hello from CLI with ML-KEM-1024!"
   ```

4. **Verify in Web App**:
   - Check browser console for `[PQ] Detected simple PQ-DM format`
   - Message should appear decrypted in the chat view

## Scheduled Runs

The workflow is configured to run daily at 6 AM UTC. Configure notifications in `workflow.yaml`:

```yaml
on_failure:
  - type: webhook
    url: ${SLACK_WEBHOOK_URL}
    payload:
      text: "Drista E2E tests failed"
```

## Troubleshooting

### CLI Build Fails
```bash
cd /Users/sylvaincormier/QuantumVerseProtocols/drista
cargo build --release -p drista-cli
```

### Web App Not Running
```bash
cd web && npm install && npm run dev
```

### WASM Not Found
Rebuild WASM module:
```bash
cd crates/qcomm-core
wasm-pack build --target web
```

### Relay Connection Issues
Test relay connectivity:
```bash
websocat wss://relay.damus.io
```
