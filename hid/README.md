# HID Execution System

Modular backend for USB HID keyboard injection on Raspberry Pi Zero 2 W.

## Architecture

```
hid/
├── __init__.py           # Package exports
├── executor.py           # Low-level HID device communication
├── payload_builder.py    # Dynamic payload generation
├── hid_controller.py     # High-level orchestration
└── README.md            # This file
```

## Components

### executor.py
- Direct `/dev/hidg0` communication
- USB HID report structure (8-byte keyboard reports)
- Keycode mapping (ASCII → HID)
- Modifier key support (CTRL, ALT, SHIFT, WIN)
- Timing control for keystrokes

### payload_builder.py
- Template-based payload system
- Variable substitution ({{TIMESTAMP}}, {{SERVER_IP}}, etc.)
- Built-in payloads: `sysinfo`, `compliance`, `test`
- Custom payload registration

### hid_controller.py
- Enable/disable HID system
- Execution logging
- Cooldown protection (prevents rapid re-execution)
- Payload orchestration

## Usage Example

```python
from hid import HIDController

# Initialize controller
controller = HIDController()

# Enable HID system
controller.enable_hid()

# Execute payload with custom variables
result = controller.execute_payload('compliance', {
    'SERVER_IP': '192.168.7.1:80',
    'HOST_ID': 'audit-001'
})

# Check execution log
logs = controller.get_execution_log(limit=10)

# List available payloads
payloads = controller.list_payloads()
```

## Safety Features

- Cooldown period (10s default) between executions
- Enable/disable toggle
- Execution logging
- Exception handling

## Expansion Points

- Add database logging
- Implement payload encryption
- Add execution scheduling
- Support multi-stage payloads
- Add result validation
