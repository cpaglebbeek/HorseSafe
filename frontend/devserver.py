#!/usr/bin/env python3
"""HorseSafe frontend dev-server v0.0.3-Merkle.

Vervangt `python -m http.server 8000` met correcte security-headers + WASM MIME:
- Cross-Origin-Opener-Policy: same-origin
- Cross-Origin-Embedder-Policy: require-corp
- application/wasm voor .wasm files
- application/javascript voor .mjs (UTF-8 explicit)

Doel: verifieer of Argon2id-KDF werkt met juiste headers (BUG-001-retry-vector).

Gebruik:
    cd frontend
    python3 devserver.py 8000
"""

from __future__ import annotations

import http.server
import mimetypes
import sys


class DevServerHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self) -> None:
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Embedder-Policy", "require-corp")
        self.send_header("Cross-Origin-Resource-Policy", "cross-origin")
        super().end_headers()


def main() -> None:
    mimetypes.add_type("application/wasm", ".wasm")
    mimetypes.add_type("application/javascript", ".mjs")
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    server = http.server.HTTPServer(("0.0.0.0", port), DevServerHandler)
    print(f"HorseSafe frontend dev-server op http://localhost:{port}/")
    print("Headers: COOP/COEP + WASM-MIME. Argon2-WASM-friendly.")
    server.serve_forever()


if __name__ == "__main__":
    main()
