"""
Low-level HID executor for USB keyboard emulation.
Handles direct communication with /dev/hidg0 device.
"""

import time

# HID device path
HID_DEVICE = "/dev/hidg0"

# USB HID Keyboard Report Structure (8 bytes):
# Byte 0: Modifier keys bitmap
# Byte 1: Reserved (always 0x00)
# Bytes 2-7: Up to 6 simultaneous key presses

# HID Keycode mapping (USB HID Usage Tables)
KEYMAP = {
    'a': 0x04, 'b': 0x05, 'c': 0x06, 'd': 0x07, 'e': 0x08,
    'f': 0x09, 'g': 0x0a, 'h': 0x0b, 'i': 0x0c, 'j': 0x0d,
    'k': 0x0e, 'l': 0x0f, 'm': 0x10, 'n': 0x11, 'o': 0x12,
    'p': 0x13, 'q': 0x14, 'r': 0x15, 's': 0x16, 't': 0x17,
    'u': 0x18, 'v': 0x19, 'w': 0x1a, 'x': 0x1b, 'y': 0x1c,
    'z': 0x1d,
    '1': 0x1e, '2': 0x1f, '3': 0x20, '4': 0x21, '5': 0x22,
    '6': 0x23, '7': 0x24, '8': 0x25, '9': 0x26, '0': 0x27,
    '\n': 0x28, '\t': 0x2b, ' ': 0x2c,
    '-': 0x2d, '=': 0x2e, '[': 0x2f, ']': 0x30, '\\': 0x31,
    ';': 0x33, "'": 0x34, '`': 0x35, ',': 0x36, '.': 0x37,
    '/': 0x38,
}

# Shifted characters mapping
SHIFT_MAP = {
    'A': 'a', 'B': 'b', 'C': 'c', 'D': 'd', 'E': 'e',
    'F': 'f', 'G': 'g', 'H': 'h', 'I': 'i', 'J': 'j',
    'K': 'k', 'L': 'l', 'M': 'm', 'N': 'n', 'O': 'o',
    'P': 'p', 'Q': 'q', 'R': 'r', 'S': 's', 'T': 't',
    'U': 'u', 'V': 'v', 'W': 'w', 'X': 'x', 'Y': 'y',
    'Z': 'z',
    '!': '1', '@': '2', '#': '3', '$': '4', '%': '5',
    '^': '6', '&': '7', '*': '8', '(': '9', ')': '0',
    '_': '-', '+': '=', '{': '[', '}': ']', '|': '\\',
    ':': ';', '"': "'", '~': '`', '<': ',', '>': '.',
    '?': '/',
}

# Modifier key bitmasks
MODIFIERS = {
    'CTRL': 0x01,
    'SHIFT': 0x02,
    'ALT': 0x04,
    'WIN': 0x08,
    'RIGHT_CTRL': 0x10,
    'RIGHT_SHIFT': 0x20,
    'RIGHT_ALT': 0x40,
    'RIGHT_WIN': 0x80,
}

# Special keys
SPECIAL_KEYS = {
    'ENTER': 0x28,
    'ESC': 0x29,
    'BACKSPACE': 0x2a,
    'TAB': 0x2b,
    'SPACE': 0x2c,
    'UP': 0x52,
    'DOWN': 0x51,
    'LEFT': 0x50,
    'RIGHT': 0x4f,
}


class HIDExecutor:
    """Low-level HID keyboard executor"""
    
    def __init__(self, device_path=HID_DEVICE):
        self.device_path = device_path
        self.keystroke_delay = 0.01  # 10ms between keystrokes
        self.command_delay = 0.02    # 20ms for key press/release
    
    def send_report(self, modifier, keycode):
        """
        Send HID keyboard report to device.
        
        Args:
            modifier: Modifier keys bitmap (0x00 for none)
            keycode: HID keycode to send
        """
        try:
            with open(self.device_path, 'wb') as hid:
                # Press key
                report = bytes([modifier, 0, keycode, 0, 0, 0, 0, 0])
                hid.write(report)
                time.sleep(self.command_delay)
                
                # Release key
                release = bytes([0, 0, 0, 0, 0, 0, 0, 0])
                hid.write(release)
                time.sleep(self.keystroke_delay)
        except Exception as e:
            raise IOError(f"Failed to write to HID device: {e}")
    
    def type_char(self, char):
        """Type a single character"""
        # Check if shift is needed
        if char in SHIFT_MAP:
            base_char = SHIFT_MAP[char]
            keycode = KEYMAP.get(base_char)
            if keycode:
                self.send_report(MODIFIERS['SHIFT'], keycode)
        elif char in KEYMAP:
            self.send_report(0, KEYMAP[char])
        else:
            # Unsupported character, skip
            pass
    
    def type_string(self, text):
        """Type a string of text"""
        for char in text:
            self.type_char(char)
    
    def press_key(self, key_name):
        """Press a special key (ENTER, ESC, etc.)"""
        if key_name in SPECIAL_KEYS:
            self.send_report(0, SPECIAL_KEYS[key_name])
        else:
            raise ValueError(f"Unknown special key: {key_name}")
    
    def key_combo(self, modifiers, key):
        """
        Execute key combination (e.g., CTRL+C, WIN+R).
        
        Args:
            modifiers: List of modifier names ['CTRL', 'SHIFT']
            key: Key name or character
        """
        # Build modifier bitmap
        mod_bitmap = 0
        for mod in modifiers:
            if mod in MODIFIERS:
                mod_bitmap |= MODIFIERS[mod]
        
        # Get keycode
        if key in SPECIAL_KEYS:
            keycode = SPECIAL_KEYS[key]
        elif key.lower() in KEYMAP:
            keycode = KEYMAP[key.lower()]
        else:
            raise ValueError(f"Unknown key: {key}")
        
        self.send_report(mod_bitmap, keycode)
    
    def delay(self, milliseconds):
        """Wait for specified milliseconds"""
        time.sleep(milliseconds / 1000.0)
