# Portable Security Auditor using Raspberry Pi Zero 2 W

USB HID gadget for security testing with Raspberry Pi Zero 2 W.

## Components

- **hid/** - USB HID keyboard emulation
  - `hidtest.py` - Script executor for automated keystrokes
  - `script.txt` - Command script (opens notepad with test message)

- **portal/** - File upload server
  - `upload_server.py` - HTTP server for receiving files on port 8000

- **index.html** - WiFi configuration interface

## Usage

Run HID script:
```bash
python3 hid/hidtest.py
```

Start upload server:
```bash
python3 portal/upload_server.py
```
