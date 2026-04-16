from http.server import BaseHTTPRequestHandler, HTTPServer
import os
import threading
import logging
from datetime import datetime

BASE_UPLOAD_DIR = "uploads"
os.makedirs(BASE_UPLOAD_DIR, exist_ok=True)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('UploadServer')

# Store current scan metadata
current_scan = {
    'device_name': 'unknown',
    'owner_name': 'unknown',
    'scan_type': 'Full_Audit'
}

# Expected files per scan type. Update these lists to match your payloads.
EXPECTED_FILES = {
    'Full_Audit': {
        'audit_sysinfo.json', 'audit_hklm_policies.txt', 'audit_hkcu_policies.txt',
        'audit_services.txt', 'audit_control.txt', 'audit_firewall.txt',
        'audit_defender.json', 'audit_drivers.txt', 'audit_devices.txt',
        'audit_auditpol.txt', 'audit_gp_cache.json', 'audit_net_users.txt',
        'audit_secpol.cfg', 'audit_gpresult_computer.txt', 'audit_gpresult_user.txt'
    },
    'Home_Audit': {
        'audit_sysinfo.json', 'audit_hklm_policies.txt', 'audit_hkcu_policies.txt',
        'audit_services.txt', 'audit_control.txt', 'audit_firewall.txt',
        'audit_defender.json', 'audit_drivers.txt', 'audit_devices.txt',
        'audit_auditpol.txt', 'audit_gp_cache.json', 'audit_net_users.txt',
        'audit_gpresult_computer.txt', 'audit_gpresult_user.txt'
        # secedit excluded — not available on Home edition
    },
    'Basic_Audit': {
        'audit_sysinfo.json', 'audit_firewall.txt', 'audit_defender.json'
    }
}

# Track received files for the current session
_received_files = set()
_task_completed = False

def set_scan_metadata(device_name, owner_name, scan_type):
    """Set metadata for current scan and reset tracking state"""
    global _received_files, _task_completed
    current_scan['device_name'] = device_name
    current_scan['owner_name'] = owner_name
    current_scan['scan_type'] = scan_type
    _received_files = set()
    _task_completed = False
    logger.info(f"[SCAN] Metadata set: {owner_name}/{device_name} ({scan_type}). Awaiting files...")

def get_upload_directory():
    """Generate upload directory based on current scan metadata"""
    date_str = datetime.now().strftime("%Y-%m-%d")
    device = current_scan['device_name'].replace(' ', '_')
    owner = current_scan['owner_name'].replace(' ', '_')
    scan_type = current_scan['scan_type'].replace(' ', '_')
    
    upload_dir = os.path.join(BASE_UPLOAD_DIR, owner, device, date_str, scan_type)
    os.makedirs(upload_dir, exist_ok=True)
    return upload_dir

class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        logger.info("%s - %s" % (self.address_string(), format % args))
    
    def do_GET(self):
        """Handle GET requests for testing"""
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b"Upload server is running. Use POST to upload files.")
    
    def do_POST(self):
        global _received_files, _task_completed
        try:
            length = int(self.headers.get('Content-Length', 0))
            data = self.rfile.read(length)

            filename = self.headers.get("X-Filename", "upload.bin")
            upload_dir = get_upload_directory()
            filepath = os.path.join(upload_dir, filename)

            with open(filepath, "wb") as f:
                f.write(data)
            
            _received_files.add(filename)
            scan_type = current_scan['scan_type']
            expected = EXPECTED_FILES.get(scan_type, set())
            remaining = expected - _received_files
            
            logger.info(f"✓ Received: {filename} ({length} bytes) [{len(_received_files)}/{len(expected)}]")
            
            if remaining:
                logger.info(f"   Remaining files for '{scan_type}': {', '.join(sorted(remaining))}")

            # Fire task complete only once when all expected files have arrived
            if expected and not remaining and not _task_completed:
                _task_completed = True
                logger.info(f"✅ TASK COMPLETED — All {len(expected)} files received for scan '{scan_type}'.")

            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"OK")
        except Exception as e:
            logger.error(f"✗ Upload failed: {e}")
            self.send_response(500)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(f"Error: {e}".encode())

server = None

def start_upload_server(port=8000):
    """Start upload server in background thread"""
    global server
    server = HTTPServer(("0.0.0.0", port), Handler)
    logger.info(f"Upload server listening on port {port}")
    server.serve_forever()

def start_background():
    """Start upload server in daemon thread"""
    thread = threading.Thread(target=start_upload_server, daemon=True)
    thread.start()
    return thread

if __name__ == '__main__':
    start_upload_server()
