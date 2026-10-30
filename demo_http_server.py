#!/usr/bin/env python3
"""Small h2 service with GET and POST endpoints for the SFC demonstration."""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


PAGE = b"<h1>Automated SFC</h1><p>This response came from h2.</p>\n"
ATTACK = b"Demo signature observed; the next request will be quarantined.\n"


class DemoHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def respond(self, status, body, content_type="text/plain"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/":
            self.respond(200, PAGE, "text/html")
        elif self.path == "/attack":
            self.respond(200, ATTACK)
        else:
            self.respond(404, b"Not found\n")

    def do_POST(self):
        if self.path != "/upload":
            self.respond(404, b"Not found\n")
            return
        try:
            remaining = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.respond(400, b"Invalid Content-Length\n")
            return
        if not 0 <= remaining <= 4 * 1024 * 1024:
            self.respond(413, b"Maximum upload size is 4 MiB\n")
            return
        received = remaining
        while remaining:
            chunk = self.rfile.read(min(65536, remaining))
            if not chunk:
                self.respond(400, b"Incomplete upload\n")
                return
            remaining -= len(chunk)
        self.respond(200, f"Received {received} bytes\n".encode())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("port", type=int)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("10.0.0.2", args.port), DemoHandler)
    print(f"h2 HTTP server listening on TCP/{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
