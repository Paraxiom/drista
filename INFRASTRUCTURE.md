# Drista Infrastructure

## Validators

| Name    | IP            | Location    | SSH User | SSH Key           |
|---------|---------------|-------------|----------|-------------------|
| Alice   | 51.79.26.123  | Montreal    | ubuntu   | ~/.ssh/ovh_simple |
| Bob     | 51.79.26.168  | Montreal    | ubuntu   | ~/.ssh/ovh_simple |
| Charlie | 209.38.225.4  | Toronto     | root     | ~/.ssh/ovh_simple |

## Architecture

```
Browser
   │
   ├── wss://drista.paraxiom.org/ws          → Alice:7777 → Alice:9944 (blockchain)
   ├── wss://drista.paraxiom.org/ws-bob      → Bob:7778   → Bob:9944   (blockchain)
   ├── wss://drista.paraxiom.org/ws-charlie  → Charlie:7778 → Charlie:9944 (blockchain)
   └── wss://drista.paraxiom.org/qssl        → Alice:7779 (QSSL encrypted)
                                                    ↓
                                              Alice:7777 → blockchain
```

## Services

### Alice (51.79.26.123)
- **nginx** (443, 7778): TLS termination, WebSocket proxy
- **drista-bridge** (7777): NIP-01 bridge to blockchain
- **qssl-server** (7779): QSSL encrypted WebSocket proxy

### Bob (51.79.26.168)
- **nginx** (7778): WebSocket proxy (no TLS, ports 80/443 used by Docker)
- **drista-bridge** (7777): NIP-01 bridge to blockchain

### Charlie (209.38.225.4)
- **nginx** (7778): WebSocket proxy (no TLS, ports 80/443 used by Docker)
- **drista-bridge** (7777): NIP-01 bridge to blockchain

## Commands

### SSH Access
```bash
# Alice
ssh -i ~/.ssh/ovh_simple ubuntu@51.79.26.123

# Bob
ssh -i ~/.ssh/ovh_simple ubuntu@51.79.26.168

# Charlie (uses root!)
ssh -i ~/.ssh/ovh_simple root@209.38.225.4
```

### Service Management
```bash
# Check bridge status
sudo systemctl status drista-bridge

# Restart bridge
sudo systemctl restart drista-bridge

# View bridge logs
sudo journalctl -u drista-bridge -f

# Check QSSL server (Alice only)
sudo systemctl status qssl-server
```

### Check Blockchain Sync
```bash
# Get message count (should be same on all validators)
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"forum_getMessageCount","params":[]}' \
  http://127.0.0.1:9944
```

## Relay Endpoints

| Endpoint                                  | Validator | Status |
|-------------------------------------------|-----------|--------|
| wss://drista.paraxiom.org/ws              | Alice     | TLS    |
| wss://drista.paraxiom.org/ws-bob          | Bob       | TLS*   |
| wss://drista.paraxiom.org/ws-charlie      | Charlie   | TLS*   |
| wss://drista.paraxiom.org/qssl            | Alice     | QSSL   |

*TLS terminated at Alice, proxied to validator over internal network

## DNS (TODO)
- bob.drista.paraxiom.org → 51.79.26.168 (currently points to Alice)
- charlie.drista.paraxiom.org → 209.38.225.4 (not set)
