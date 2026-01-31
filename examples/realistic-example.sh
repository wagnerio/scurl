#!/bin/bash
# Realistic installer (like many real-world scripts)

set -euo pipefail

INSTALL_DIR="/usr/local/bin"
REPO="example/myapp"
VERSION="latest"

echo "Installing myapp..."

# Detect OS
OS="$(uname -s)"
case "$OS" in
  Linux*)  PLATFORM=linux;;
  Darwin*) PLATFORM=darwin;;
  *)       echo "Unsupported OS: $OS"; exit 1;;
esac

# Download from GitHub releases
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/myapp-${PLATFORM}-amd64"

# Download binary
TMP_FILE=$(mktemp)
curl -fsSL "$DOWNLOAD_URL" -o "$TMP_FILE"

# Install (requires sudo)
sudo install -m 755 "$TMP_FILE" "${INSTALL_DIR}/myapp"
rm "$TMP_FILE"

echo "myapp installed successfully!"
myapp --version
