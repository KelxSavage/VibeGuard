from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
import os

DEMO_DIR = Path(__file__).resolve().parent

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(DEMO_DIR), **kwargs)

    # Intentionally omit security headers so VibeGuard can detect them.
    # This server binds only to loopback and is not exposed to the LAN.

if __name__ == "__main__":
    os.chdir(DEMO_DIR)
    server = HTTPServer(("127.0.0.1", 8765), Handler)
    print("VibeGuard demo running at http://127.0.0.1:8765")
    print("Local-only. Press Ctrl+C to stop.")
    server.serve_forever()
