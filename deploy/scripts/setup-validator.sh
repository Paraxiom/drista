#!/usr/bin/env bash
# setup-validator.sh — Per-validator deployment for QSSH + TLS bridge transport
#
# Installs and configures:
#   1. qsshd (Falcon-512 PQ tunnel server, port 4242)
#   2. nginx (TLS 1.3 WebSocket proxy, port 7778)
#   3. Bridge localhost restriction (BRIDGE_HOST=127.0.0.1)
#
# Usage:
#   ./setup-validator.sh [--qssh-src /path/to/qssh] [--bridge-dir /path/to/quantum-communicator]
#
# Prerequisites:
#   - Rust toolchain (for building qsshd)
#   - nginx installed or Docker available
#   - OpenSSL (for self-signed cert generation)

set -euo pipefail

QSSH_SRC="${QSSH_SRC:-$HOME/qssh}"
BRIDGE_DIR="${BRIDGE_DIR:-$HOME/quantum-communicator}"
QSSH_KEYS_DIR="/etc/qssh"
SSL_DIR="/etc/nginx/ssl"
QSSHD_PORT=4242
NGINX_PORT=7778

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --qssh-src) QSSH_SRC="$2"; shift 2 ;;
        --bridge-dir) BRIDGE_DIR="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

echo "=== QuantumHarmony Validator Setup ==="
echo "QSSH source:  $QSSH_SRC"
echo "Bridge dir:    $BRIDGE_DIR"
echo ""

# ── Step 1: Build qsshd ──────────────────────────────────────
echo "[1/8] Building qsshd from source..."
if [ ! -d "$QSSH_SRC" ]; then
    echo "ERROR: QSSH source directory not found at $QSSH_SRC"
    exit 1
fi

cd "$QSSH_SRC"
cargo build --release --bin qsshd --bin qssh-keygen
sudo cp target/release/qsshd /usr/local/bin/
sudo cp target/release/qssh-keygen /usr/local/bin/
echo "  qsshd and qssh-keygen installed to /usr/local/bin/"

# ── Step 2: Generate host keys ────────────────────────────────
echo "[2/8] Generating QSSH host keys..."
sudo mkdir -p "$QSSH_KEYS_DIR"
if [ ! -f "$QSSH_KEYS_DIR/host_key" ]; then
    sudo qssh-keygen --host-key -f "$QSSH_KEYS_DIR/host_key"
    echo "  Host key generated at $QSSH_KEYS_DIR/host_key"
else
    echo "  Host key already exists, skipping"
fi

# ── Step 3: Install qsshd config ─────────────────────────────
echo "[3/8] Installing qsshd config..."
sudo cp "$BRIDGE_DIR/deploy/qsshd/qsshd.conf" "$QSSH_KEYS_DIR/qsshd.conf"

# Create empty authorized_keys if missing
sudo touch "$QSSH_KEYS_DIR/authorized_keys"
echo "  Config installed at $QSSH_KEYS_DIR/qsshd.conf"

# ── Step 4: Generate self-signed TLS cert ─────────────────────
echo "[4/8] Generating self-signed TLS certificate for nginx..."
sudo mkdir -p "$SSL_DIR"
if [ ! -f "$SSL_DIR/bridge.crt" ]; then
    sudo openssl req -x509 -nodes -days 365 \
        -newkey rsa:2048 \
        -keyout "$SSL_DIR/bridge.key" \
        -out "$SSL_DIR/bridge.crt" \
        -subj "/CN=quantumharmony-bridge/O=QuantumHarmony"
    echo "  Self-signed cert generated at $SSL_DIR/bridge.crt"
else
    echo "  TLS cert already exists, skipping"
fi

# ── Step 5: Install nginx configs ─────────────────────────────
echo "[5/8] Installing nginx configs (bridge WS + notarial RPC)..."
sudo cp "$BRIDGE_DIR/deploy/nginx/nginx-bridge-ws.conf" /etc/nginx/conf.d/bridge-ws.conf
sudo cp "$BRIDGE_DIR/deploy/nginx/nginx-notarial-rpc.conf" /etc/nginx/conf.d/notarial-rpc.conf
echo "  nginx configs installed (bridge-ws + notarial-rpc with PQ TLS)"

# ── Step 6: Configure bridge for localhost ────────────────────
echo "[6/8] Setting bridge to localhost-only..."
# Create/update .env for bridge
BRIDGE_ENV="$BRIDGE_DIR/web/bridge/.env"
if grep -q "BRIDGE_HOST" "$BRIDGE_ENV" 2>/dev/null; then
    sed -i 's/^BRIDGE_HOST=.*/BRIDGE_HOST=127.0.0.1/' "$BRIDGE_ENV"
else
    echo "BRIDGE_HOST=127.0.0.1" >> "$BRIDGE_ENV"
fi
echo "  Bridge will bind to 127.0.0.1:7777"

# ── Step 7: Start services ───────────────────────────────────
echo "[7/8] Starting services..."

# Start qsshd
echo "  Starting qsshd on port $QSSHD_PORT..."
if command -v systemctl &>/dev/null; then
    # Create systemd unit if it doesn't exist
    if [ ! -f /etc/systemd/system/qsshd.service ]; then
        sudo tee /etc/systemd/system/qsshd.service > /dev/null <<UNIT
[Unit]
Description=QSSH Daemon (Falcon-512 PQ Tunnel)
After=network.target

[Service]
ExecStart=/usr/local/bin/qsshd --config /etc/qssh/qsshd.conf
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
        sudo systemctl daemon-reload
    fi
    sudo systemctl enable --now qsshd
else
    # Fallback: run in background
    sudo qsshd --config "$QSSH_KEYS_DIR/qsshd.conf" &
fi

# Restart nginx
echo "  Restarting nginx..."
sudo systemctl reload nginx 2>/dev/null || sudo nginx -s reload 2>/dev/null || true

# ── Step 8: Verify ────────────────────────────────────────────
echo "[8/8] Verifying deployment..."
echo ""

# Check qsshd is listening
if ss -tlnp | grep -q ":$QSSHD_PORT"; then
    echo "  [OK] qsshd listening on port $QSSHD_PORT"
else
    echo "  [WARN] qsshd not detected on port $QSSHD_PORT"
fi

# Check nginx is listening
if ss -tlnp | grep -q ":$NGINX_PORT"; then
    echo "  [OK] nginx listening on port $NGINX_PORT"
else
    echo "  [WARN] nginx not detected on port $NGINX_PORT"
fi

echo ""
echo "=== Validator setup complete ==="
echo ""
echo "Next steps:"
echo "  1. Add client public keys to $QSSH_KEYS_DIR/authorized_keys"
echo "  2. Restart bridge with: BRIDGE_HOST=127.0.0.1 node $BRIDGE_DIR/web/bridge/index.js"
echo "  3. Replace self-signed cert with Let's Encrypt for production"
echo "  4. Open firewall ports: 4242 (QSSH), 7778 (TLS/WSS), 443 (PQ TLS RPC)"
echo "  5. Ensure port 9944 is NOT open externally (bound to localhost only)"
echo ""
echo "Notarial RPC:"
echo "  External access via https://<validator-ip>/rpc (PQ TLS 1.3 + X25519MLKEM768)"
echo "  Faucet via https://<validator-ip>/faucet/"
echo "  Direct :9944 access blocked — use QSSH tunnel for native clients"
