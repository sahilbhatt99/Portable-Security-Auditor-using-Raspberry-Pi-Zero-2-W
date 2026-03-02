import time

HID = "/dev/hidg0"

# Basic keymap (extend as needed)
KEYMAP = {
    "a": 0x04, "b": 0x05, "c": 0x06, "d": 0x07,
    "e": 0x08, "f": 0x09, "g": 0x0a, "h": 0x0b,
    "i": 0x0c, "j": 0x0d, "k": 0x0e, "l": 0x0f,
    "m": 0x10, "n": 0x11, "o": 0x12, "p": 0x13,
    "q": 0x14, "r": 0x15, "s": 0x16, "t": 0x17,
    "u": 0x18, "v": 0x19, "w": 0x1a, "x": 0x1b,
    "y": 0x1c, "z": 0x1d,
    " ": 0x2c,
}

MODIFIERS = {
    "CTRL": 0x01,
    "SHIFT": 0x02,
    "ALT": 0x04,
    "WIN": 0x08,
}

ENTER = 0x28

def send(mod, key):
    with open(HID, "wb") as f:
        f.write(bytes([mod, 0, key, 0, 0, 0, 0, 0]))
        time.sleep(0.02)
        f.write(b'\x00' * 8)

def type_text(text):
    for ch in text.lower():
        if ch in KEYMAP:
            send(0, KEYMAP[ch])
            time.sleep(0.01)

def run_script(script_lines):
    for line in script_lines:
        line = line.strip()

        if line.startswith("TYPE "):
            type_text(line[5:])

        elif line == "ENTER":
            send(0, ENTER)

        elif line.startswith("WAIT "):
            ms = int(line.split()[1])
            time.sleep(ms / 1000)

        elif "+" in line:  # Modifier combo
            parts = line.split("+")
            mod = 0
            key = None
            for p in parts:
                if p in MODIFIERS:
                    mod |= MODIFIERS[p]
                else:
                    key = KEYMAP.get(p.lower())
            if key:
                send(mod, key)

if __name__ == "__main__":
    print("Reading script.txt...")
    with open("script.txt") as f:
        run_script(f.readlines())
