# Flask + HID Integration

## Architecture

```
┌─────────────────────────────────────────┐
│         Flask Web Application           │
│                                         │
│  ┌────────────┐      ┌───────────────┐  │
│  │  Dashboard │◄────►│ HID Controller│  │
│  │   Routes   │      │               │  │
│  └────────────┘      └───────┬───────┘  │
│                              │          │
│                      ┌───────▼───────┐  │
│                      │    Payload    │  │
│                      │    Builder    │  │
│                      └───────┬───────┘  │
│                              │          │
│                      ┌───────▼───────┐  │
│                      │   Executor    │  │
│                      │  /dev/hidg0   │  │
│                      └───────────────┘  │
└─────────────────────────────────────────┘
```

## API Endpoints

### Compliance Routes
- `GET /` - Dashboard UI
- `POST /check` - Compliance check
- `GET /status` - System status
- `GET /logs` - Compliance logs

### HID Routes
- `POST /hid/enable` - Enable HID system
- `POST /hid/disable` - Disable HID system
- `GET /hid/payloads` - List available payloads
- `POST /hid/execute` - Execute payload
- `GET /hid/logs` - HID execution logs
- `GET /hid/status` - HID system status

## Dashboard Features

1. **System Status Panel**
   - Pi status
   - USB link status
   - Policy engine status
   - HID system status (enabled/disabled)

2. **HID Control Panel**
   - Enable/Disable buttons
   - Payload dropdown selector
   - Execute button
   - Result display

3. **Compliance Panel**
   - Latest check results
   - Manual test trigger
   - System data display

## Usage Flow

1. User opens dashboard
2. Enables HID system via button
3. Selects payload from dropdown
4. Clicks Execute
5. HID controller checks:
   - System enabled?
   - Cooldown expired?
6. Payload builder generates commands
7. Executor sends HID reports to /dev/hidg0
8. Target system receives keystrokes
9. Results logged and displayed

## Integration Points

**app.py imports:**
```python
from hid import HIDController
hid_controller = HIDController()
```

**Status integration:**
```python
def get_system_status():
    hid_status = hid_controller.get_status()
    return {
        "hid_enabled": hid_status['enabled'],
        "hid_payloads": hid_status['available_payloads']
    }
```

**Execution integration:**
```python
@app.route('/hid/execute', methods=['POST'])
def hid_execute():
    result = hid_controller.execute_payload(payload_name, variables)
    return jsonify(result)
```

## Security Features

- Enable/disable toggle
- 10-second cooldown between executions
- Execution logging
- Error handling
- Variable sanitization

## Deployment

```bash
# Activate venv
source venv/bin/activate  # Linux/Pi
venv\Scripts\activate     # Windows

# Run application
sudo python app.py  # Port 80 requires sudo
```
