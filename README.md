# Portable Security Auditor using Raspberry Pi Zero 2 W

USB HID gadget for automated Windows security auditing with Raspberry Pi Zero 2 W.

## Features

- **USB HID Keyboard Emulation** - Automated keystroke injection
- **20 Security Audit Payloads** - Registry, firewall, defender, drivers, devices, RSOP, secedit, auditpol
- **Auto-Upload to Pi** - Files automatically sent to Pi via HTTP
- **Web Dashboard** - Control and monitor from browser
- **Live Execution Logs** - Real-time command feedback
- **Organized Storage** - Files sorted by date/time/device/owner
- **PDF Reports** - Generate security audit reports (optional)

## Hardware Requirements

- Raspberry Pi Zero 2 W
- USB cable (data capable)
- MicroSD card (8GB+)

## Software Requirements

- Raspberry Pi OS Lite
- Python 3.11+
- USB gadget mode enabled

## Installation

### 1. Enable USB Gadget Mode

```bash
# Add to /boot/config.txt
dtoverlay=dwc2

# Add to /boot/cmdline.txt (after rootwait)
modules-load=dwc2,g_hid
```

### 2. Clone Repository

```bash
git clone https://github.com/sahilbhatt99/Portable-Security-Auditor-using-Raspberry-Pi-Zero-2-W.git
cd Portable-Security-Auditor-using-Raspberry-Pi-Zero-2-W
```

### 3. Run Setup Script

```bash
chmod +x run.sh
./run.sh
```

The script will:
- Create virtual environment
- Install dependencies
- Check HID device
- Start Flask app on port 80
- Start upload server on port 8000

## Usage

### 1. Access Dashboard

Open browser on Windows PC:
- `http://172.16.0.1` (USB gadget IP)
- `http://raspberrypi.local` (mDNS)

### 2. Set Scan Information

- Device Name: `PC-001`
- Owner Name: `John Doe`
- Scan Number: `1`
- Click "Save Scan Info"

### 3. Enable HID System

- Click "Enable HID" button
- Status shows "enabled"

### 4. Execute Payload

- Select payload from dropdown
- Click "Execute"
- Watch live log for progress

### 5. View Results

Files saved to: `uploads/YYYYMMDD_HHMMSS_scanN_device_owner/`

## Available Payloads

| Payload | Description | Output |
|---------|-------------|--------|
| `test` | Notepad test | - |
| `sysinfo` | System info | JSON to Pi |
| `compliance` | Compliance check | JSON to Pi |
| `export_policies` | HKLM Policies | HKLM_Policies.reg |
| `export_user_policies` | HKCU Policies | HKCU_Policies.reg |
| `export_services` | Services registry | Services.reg |
| `export_control` | Control registry | Control.reg |
| `export_firewall` | Firewall config | firewall.wfw |
| `export_defender` | Defender settings | defender.json |
| `export_drivers` | Driver list | drivers.txt |
| `export_devices` | Device list | devices.txt |
| `full_audit` | All exports + upload | All 9 files |
| `export_registry_hkcu` | HKCU policy registry query (enforced state) | audit_hkcu_registry.txt |
| `export_rsop_computer` | RSOP computer namespace via WMI | audit_rsop_computer.json |
| `export_rsop_user` | RSOP user namespace via CIM | audit_rsop_user.json |
| `export_secedit` | Security policy (account, user rights, options) | audit_secpol.cfg |
| `export_auditpol` | Advanced audit policies (all categories) | audit_auditpol.txt |
| `export_net_users` | Local user accounts + logon restrictions | audit_net_users.txt |
| `export_gp_cache` | Group Policy cache (applied GPO GUIDs) | audit_gp_cache.json |
| `upload_files` | Upload existing files | All 8 files |

## Project Structure

```
.
├── app.py                 # Flask web application
├── run.sh                 # Startup script
├── requirements.txt       # Python dependencies
├── hid/                   # HID injection system
│   ├── executor.py        # Low-level HID device I/O
│   ├── payload_builder.py # Payload templates
│   └── hid_controller.py  # High-level orchestration
├── portal/                # Upload server
│   └── upload_server.py   # HTTP file receiver
├── parser/                # Report generator (optional)
│   ├── audit_parser.py    # File parser
│   └── report_generator.py# PDF generator
├── templates/             # Web UI
│   └── index.html         # Dashboard
└── uploads/               # Received files
```

## API Endpoints

### Dashboard
- `GET /` - Web dashboard
- `GET /status` - System status
- `GET /logs` - Compliance logs

### HID Control
- `POST /hid/enable` - Enable HID
- `POST /hid/disable` - Disable HID
- `GET /hid/payloads` - List payloads
- `POST /hid/execute` - Execute payload
- `GET /hid/live-log` - Live execution log
- `POST /hid/clear-log` - Clear log

### Scan Metadata
- `POST /scan/set-metadata` - Set device/owner/scan info

### Upload Server
- `GET :8000` - Server status
- `POST :8000` - Upload file

## Configuration

### Change Server IP

Edit `hid/payload_builder.py`:
```python
default_vars = {
    'SERVER_IP': '172.16.0.1',  # Change this
}
```

### Change Upload Port

Edit `portal/upload_server.py`:
```python
def start_upload_server(port=8000):  # Change port
```

## Troubleshooting

### HID Device Not Found

```bash
sudo modprobe g_hid
ls /dev/hidg0  # Should exist
```

### Upload Server Not Reachable

```bash
# Check if port 8000 is listening
sudo netstat -tlnp | grep 8000

# Test from Windows
curl http://172.16.0.1:8000
```

### Parser Module Error

Parser (reportlab) is optional. App works without it.

To install:
```bash
sudo apt-get install python3-pil libjpeg-dev zlib1g-dev
pip install pillow reportlab
```

## Security Notes

- Requires admin/UAC elevation on Windows
- Uses `Ctrl+Shift+Enter` for elevation
- Auto-confirms UAC with `Alt+Y`
- 2-second cooldown between executions
- All commands logged

## Windows Compatibility

- ✅ Windows 10/11 Home
- ✅ Windows 10/11 Pro
- ✅ Windows 10/11 Enterprise
- ⚠️ Requires PowerShell 5.0+

## License

MIT License

## Author

Sahil Bhatt (@sahilbhatt99)

## Contributing

Pull requests welcome!

## Acknowledgments

- USB HID gadget mode
- Flask web framework
- ReportLab PDF generation
