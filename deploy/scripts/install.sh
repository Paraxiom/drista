#!/bin/bash
# Drista Installer
# Post-quantum secure chat for Paraxiom collaborators
# https://drista.paraxiom.org

set -e

BASE_URL="https://drista.paraxiom.org/releases"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════╗"
echo "║     Drista — दृष्टा Installer             ║"
echo "║     Post-Quantum Secure Chat              ║"
echo "╚═══════════════════════════════════════════╝"
echo -e "${NC}"

# Detect OS and architecture
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Darwin)
        case "$ARCH" in
            arm64) ASSET="Drista-macos-arm64.zip" ;;
            x86_64) ASSET="Drista-macos-x64.zip" ;;
            *) echo -e "${RED}Unsupported architecture: $ARCH${NC}"; exit 1 ;;
        esac
        ;;
    Linux)
        case "$ARCH" in
            x86_64) ASSET="Drista-linux-x64.AppImage" ;;
            *) echo -e "${RED}Unsupported architecture: $ARCH${NC}"; exit 1 ;;
        esac
        ;;
    MINGW*|MSYS*|CYGWIN*)
        ASSET="Drista-windows-x64.msi"
        ;;
    *)
        echo -e "${RED}Unsupported OS: $OS${NC}"
        exit 1
        ;;
esac

echo "Detected: $OS $ARCH"
echo "Downloading: $ASSET"
echo ""

# Download URL
RELEASE_URL="$BASE_URL/$ASSET"

# Create temp directory
TMP_DIR=$(mktemp -d)
trap "rm -rf $TMP_DIR" EXIT

cd "$TMP_DIR"

# Download
echo "Downloading from GitHub..."
if command -v curl &> /dev/null; then
    curl -fsSL -o "$ASSET" "$RELEASE_URL"
elif command -v wget &> /dev/null; then
    wget -q -O "$ASSET" "$RELEASE_URL"
else
    echo -e "${RED}Error: curl or wget required${NC}"
    exit 1
fi

# Install based on OS
case "$OS" in
    Darwin)
        echo "Extracting..."
        unzip -q "$ASSET"

        echo "Installing to /Applications..."
        if [ -d "/Applications/Drista.app" ]; then
            rm -rf "/Applications/Drista.app"
        fi
        mv "Drista.app" "/Applications/"

        # Remove quarantine attribute
        xattr -rd com.apple.quarantine "/Applications/Drista.app" 2>/dev/null || true

        echo -e "${GREEN}Installed to /Applications/Drista.app${NC}"
        echo ""
        echo "Launch with: open /Applications/Drista.app"
        ;;

    Linux)
        mkdir -p "$INSTALL_DIR"
        chmod +x "$ASSET"
        mv "$ASSET" "$INSTALL_DIR/drista"

        echo -e "${GREEN}Installed to $INSTALL_DIR/drista${NC}"
        echo ""
        echo "Launch with: drista"
        echo "(Make sure $INSTALL_DIR is in your PATH)"
        ;;

    MINGW*|MSYS*|CYGWIN*)
        echo "Running MSI installer..."
        msiexec /i "$ASSET"
        ;;
esac

echo ""
echo -e "${CYAN}Web version: https://drista.paraxiom.org${NC}"
echo -e "${CYAN}Source code: https://github.com/Paraxiom/drista${NC}"
echo ""
echo -e "${GREEN}Installation complete!${NC}"
