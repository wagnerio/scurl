#!/bin/bash
# Simple safe installation script example

set -e

echo "Installing example application..."

# Check if running as root
if [ "$EUID" -eq 0 ]; then
  echo "Please don't run as root"
  exit 1
fi

# Create a simple directory and file
mkdir -p ~/.local/share/example-app
echo "version=1.0.0" > ~/.local/share/example-app/config

echo "Installation complete!"
