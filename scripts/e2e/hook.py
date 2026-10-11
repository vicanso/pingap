#!/usr/bin/env python3
"""A receiver of webhooks for the end-to-end checks.

    hook.py <port> <log file>

Answers every POST with 200 and what ntfy answers a message with, and
writes one line for it: the method, the path, the `Authorization` it came
with, and the body.
"""
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT, LOG = int(sys.argv[1]), sys.argv[2]


class Hook(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        auth = self.headers.get("Authorization", "-")
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(f"{self.command} {self.path} auth={auth} "
                    f"{body.decode(errors='replace')}\n")
        answer = b'{"id":"e2e","event":"message"}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(answer)))
        self.end_headers()
        self.wfile.write(answer)

    def log_message(self, *args):
        pass


HTTPServer(("127.0.0.1", PORT), Hook).serve_forever()
