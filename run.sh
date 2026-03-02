#!/bin/bash

# Portable Security Auditor - Startup Script
# Run this script to start the Flask application

echo "==================================="
echo "Portable Security Auditor"
echo "Raspberry Pi Zero 2 W"
echo "==================================="
echo ""

# Check if venv exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate venv
echo "Activating virtual environment..."
source venv/bin/activate

# Install/update dependencies
echo "Installing dependencies..."
pip install -q -r requirements.txt

# Create uploads directory
echo "Creating uploads directory..."
mkdir -p uploads

# Check HID device
echo ""
echo "Checking HID device..."
if [ -e "/dev/hidg0" ]; then
    echo "✓ HID device found: /dev/hidg0"
else
    echo "✗ HID device not found: /dev/hidg0"
    echo "  Run: sudo modprobe g_hid"
fi

# Test imports
echo ""
echo "Testing component integration..."
python3 << EOF
try:
    from hid import HIDController
    print("✓ HID module loaded")
except Exception as e:
    print(f"✗ HID error: {e}")
    exit(1)

try:
    from portal import start_background
    print("✓ Portal module loaded")
except Exception as e:
    print(f"✗ Portal error: {e}")
    exit(1)

try:
    from parser import AuditParser, ReportGenerator
    print("✓ Parser module loaded")
except Exception as e:
    print(f"⚠ Parser unavailable (optional): {e}")

print("✓ Core components integrated successfully")
EOF

if [ $? -ne 0 ]; then
    echo "Component integration failed. Exiting."
    exit 1
fi

# Start the application
echo ""
echo "Starting Flask application on port 80..."
echo "Dashboard: http://172.16.0.1 or http://raspberrypi.local"
echo "Upload server: port 8000 (auto-started)"
echo "Uploads directory: ./uploads/"
echo ""
echo "Press Ctrl+C to stop"
echo ""

sudo venv/bin/python3 app.py
