from http.server import BaseHTTPRequestHandler, HTTPServer
import os

UPLOAD_DIR = "/home/hunter/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers['Content-Length'])
        data = self.rfile.read(length)

        filename = self.headers.get("X-Filename", "upload.bin")
        filepath = os.path.join(UPLOAD_DIR, filename)

        with open(filepath, "wb") as f:
            f.write(data)

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

server = HTTPServer(("0.0.0.0", 8000), Handler)
print("Listening on port 8000...")
server.serve_forever()
