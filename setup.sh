#!/bin/bash

# Portable Security Auditor - Setup & Installation Script
# This script initializes the virtual environment and installs dependencies.

echo "==================================="
echo "Portable Security Auditor Setup"
echo "==================================="
echo ""

# Check for root privileges for apt-get
if [ "$EUID" -ne 0 ]; then
  echo "Please run the setup script with sudo for system dependencies:"
  echo "sudo ./setup.sh"
  exit 1
fi

# 1. Update system and install binary dependencies
echo "[1/4] Installing system dependencies for PDF generation..."
apt-get update -qq
apt-get install -y python3-dev libjpeg-dev zlib1g-dev libfreetype6-dev python3-venv

# 2. Create virtual environment
echo "[2/4] Initializing virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "✓ Virtual environment created."
fi

# 3. Install Python dependencies
echo "[3/4] Installing Python requirements..."
venv/bin/pip install -q --upgrade pip
venv/bin/pip install -q -r requirements.txt
echo "✓ Python dependencies installed."

# 4. Finalizing directories
echo "[4/4] Creating data directories..."
mkdir -p uploads
chmod 777 uploads
echo "✓ Workspace prepared."

echo ""
echo "Setup complete. You can now start the application with:"
echo "./run.sh"
echo ""
