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

# Start the application
echo ""
echo "Starting Flask application on port 80..."
echo "Dashboard: http://raspberrypi.local or http://192.168.7.1"
echo "Upload server: port 8000"
echo ""
echo "Press Ctrl+C to stop"
echo ""

sudo venv/bin/python3 app.py
