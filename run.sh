#!/bin/bash

# Portable Security Auditor - Execution Script
# Focuses on health checks and starting the application.

echo "==================================="
echo "Portable Security Auditor"
echo "Raspberry Pi Zero 2 W"
echo "==================================="
echo ""

# 1. Environment Verification
if [ ! -d "venv" ]; then
    echo "✗ Virtual environment not found. Please run setup first:"
    echo "  sudo ./setup.sh"
    exit 1
fi

# 2. HID Device Health Check
echo "Checking HID device..."
if [ -e "/dev/hidg0" ]; then
    echo "✓ HID device found: /dev/hidg0"
else
    echo "✗ HID device not found: /dev/hidg0"
    echo "  Run: sudo modprobe g_hid"
fi

# 3. Component Integration Check
echo "Testing component integration..."
venv/bin/python3 << EOF
try:
    from hid import HIDController
    from portal import start_background
    from parser import AuditParser, ReportGenerator
    print("✓ All system modules loaded successfully.")
except Exception as e:
    print(f"✗ Integration error: {e}")
    exit(1)
EOF

if [ $? -ne 0 ]; then
    echo "Component integration failed. Run ./setup.sh to fix dependencies."
    exit 1
fi

# 4. Start Application
echo ""
echo "Starting Flask application on port 80..."
echo "Dashboard: http://172.16.0.1 or http://raspberrypi.local"
echo ""
echo "Press Ctrl+C to stop"
echo ""

# Run as sudo to allow binding to port 80 and HID access
sudo venv/bin/python3 app.py
