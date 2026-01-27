#!/usr/bin/env bash
# setup-client.sh — Native client setup for QSSH tunnel access
#
# Installs QSSH client, generates keypair, installs config template.
# After running, give your public key to the validator admin.
#
# Usage:
#   ./setup-client.sh [--qssh-src /path/to/qssh]

set -euo pipefail

QSSH_SRC="${QSSH_SRC:-$HOME/qssh}"
QSSH_DIR="$HOME/.qssh"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_TEMPLATE="$SCRIPT_DIR/../qssh-client/config"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --qssh-src) QSSH_SRC="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

echo "=== QSSH Client Setup ==="
echo ""

# ── Step 1: Build qssh client ────────────────────────────────
echo "[1/5] Building qssh client from source..."
if [ ! -d "$QSSH_SRC" ]; then
    echo "ERROR: QSSH source directory not found at $QSSH_SRC"
    echo "  Set QSSH_SRC or use --qssh-src /path/to/qssh"
    exit 1
fi

cd "$QSSH_SRC"
cargo build --release --bin qssh --bin qssh-keygen

# Install to user's local bin
mkdir -p "$HOME/.local/bin"
cp target/release/qssh "$HOME/.local/bin/"
cp target/release/qssh-keygen "$HOME/.local/bin/"
echo "  Installed qssh and qssh-keygen to ~/.local/bin/"

# ── Step 2: Generate client keypair ──────────────────────────
echo "[2/5] Generating client keypair..."
mkdir -p "$QSSH_DIR"
chmod 700 "$QSSH_DIR"

if [ ! -f "$QSSH_DIR/id_falcon" ]; then
    "$HOME/.local/bin/qssh-keygen" -f "$QSSH_DIR/id_falcon"
    chmod 600 "$QSSH_DIR/id_falcon"
    chmod 644 "$QSSH_DIR/id_falcon.pub"
    echo "  Keypair generated at $QSSH_DIR/id_falcon"
else
    echo "  Keypair already exists, skipping"
fi

# ── Step 3: Install config ────────────────────────────────────
echo "[3/5] Installing QSSH config..."
if [ -f "$CONFIG_TEMPLATE" ]; then
    cp "$CONFIG_TEMPLATE" "$QSSH_DIR/config"
    echo "  Config installed from template"
else
    # Create inline if template not found
    cat > "$QSSH_DIR/config" <<'CONF'
PqAlgorithm falcon512
Port 4242

Host qh-alice
    HostName 51.79.26.123
    LocalForward 7777:localhost:7777
    LocalForward 9944:localhost:9944

Host qh-bob
    HostName 51.79.26.168
    LocalForward 7777:localhost:7777
    LocalForward 9944:localhost:9944

Host qh-charlie
    HostName 209.38.225.4
    LocalForward 7777:localhost:7777
    LocalForward 9944:localhost:9944
CONF
    echo "  Config generated inline"
fi

# ── Step 4: Print public key ─────────────────────────────────
echo "[4/5] Your public key:"
echo ""
echo "────────────────────────────────────────"
cat "$QSSH_DIR/id_falcon.pub"
echo "────────────────────────────────────────"
echo ""
echo "Send this to the validator admin to add to authorized_keys."

# ── Step 5: Test connections ──────────────────────────────────
echo "[5/5] Testing connections..."
echo ""

for host in qh-alice qh-bob qh-charlie; do
    ip=$(grep -A1 "Host $host" "$QSSH_DIR/config" | grep HostName | awk '{print $2}')
    if [ -n "$ip" ]; then
        if timeout 5 bash -c "echo >/dev/tcp/$ip/4242" 2>/dev/null; then
            echo "  [OK] $host ($ip:4242) — reachable"
        else
            echo "  [--] $host ($ip:4242) — not reachable (firewall or qsshd not running)"
        fi
    fi
done

echo ""
echo "=== Client setup complete ==="
echo ""
echo "Usage:"
echo "  qssh qh-alice          # Connect to Alice (Montreal)"
echo "  qssh qh-bob            # Connect to Bob (Beauharnois)"
echo "  qssh qh-charlie        # Connect to Charlie (Frankfurt)"
echo ""
echo "Once connected, the tunnel forwards:"
echo "  localhost:7777 → validator bridge (Drista messaging)"
echo "  localhost:9944 → Substrate RPC (notarial service)"
echo ""
echo "Both tunnels use Falcon-512 post-quantum encryption."
echo "Open the notarial UI — it auto-detects the QSSH tunnel (PQ-SECURED badge)."
echo "Without a tunnel, it falls back to PQ TLS via nginx (PQ-TLS badge)."
