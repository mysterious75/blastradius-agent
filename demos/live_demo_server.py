"""Live demo target — a deliberately vulnerable mini web app (stdlib only).

Runs an HTTP server with realistic bugs the BlastRadius dynamic web scanner
should find: reflected XSS, open redirect, wildcard CORS, missing security
headers, exposed /.git/config, and a directory-listing page.

Usage:
    python demos/live_demo_server.py            # starts on http://127.0.0.1:8090
    # in another terminal:
    python -m blastradius.web --target http://127.0.0.1:8090
"""

import http.server
import sys
import urllib.parse


class DemoHandler(http.server.BaseHTTPRequestHandler):
    def _send(self, status, body, headers=None, location=None):
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        if location:
            self.send_header("Location", location)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path, qs = parsed.path, urllib.parse.parse_qs(parsed.query)
        if path == "/":
            self._send(200, (
                b"<html><body><h1>Demo Corp Portal</h1>"
                b'<a href="/search?q=hello">search</a> | '
                b'<a href="/redirect?next=/">goto</a> | '
                b'<a href="/cors">api</a> | '
                b'<a href="/list">files</a>'
                b'<form method="post" action="/submit"><input name="msg"></form>'
                b"</body></html>"
            ))
        elif path == "/search":
            q = qs.get("q", [""])[0]
            self._send(200, f"<html><body>results for: {q}</body></html>".encode())
        elif path == "/redirect":
            self._send(302, b"", location=qs.get("next", [""])[0] or "/")
        elif path == "/cors":
            self._send(200, b'{"ok":1}', headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            })
        elif path == "/list":
            self._send(200, b"<html><body><h1>Index of /</h1></body></html>")
        elif path == "/.git/config":
            self._send(200, b"[core]\n\trepositoryformatversion = 0\n")
        elif path == "/submit" or path.startswith("/submit"):
            self._send(200, b"<html><body>ok</body></html>")
        else:
            self._send(404, b"not found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode(errors="replace")
        self._send(200, f"<html><body>echo: {body}</body></html>".encode())

    def log_message(self, *args):
        pass  # silence


def main(argv=None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="BlastRadius live demo target")
    ap.add_argument("--port", type=int, default=8090)
    args = ap.parse_args(argv)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", args.port), DemoHandler)
    print(f"[demo] vulnerable demo app at http://127.0.0.1:{args.port}")
    print("[demo] scan it with: python -m blastradius.web --target http://127.0.0.1:%d" % args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
