from http.server import BaseHTTPRequestHandler, HTTPServer
import os
import threading
import logging

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('UploadServer')

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
        try:
            length = int(self.headers.get('Content-Length', 0))
            data = self.rfile.read(length)

            filename = self.headers.get("X-Filename", "upload.bin")
            filepath = os.path.join(UPLOAD_DIR, filename)

            with open(filepath, "wb") as f:
                f.write(data)
            
            logger.info(f"✓ Received file: {filename} ({length} bytes)")

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
