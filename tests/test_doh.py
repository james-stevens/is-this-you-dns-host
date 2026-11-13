"""RESOLVER_BASE_URL is the only resolver the client talks to."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from dns_host.app import create_app
from dns_host.doh import DohClient
from dns_host.storage import Store


def test_client_sends_only_documented_parameters(lab):
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.path)
            body = json.dumps({"Status": 2, "Answer": []}).encode()
            self.send_response(200)
            self.send_header("content-type", "application/dns-json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _fmt, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        client = DohClient(f"http://127.0.0.1:{port}/", timeout=2)
        client.query("Example.COM", "DS", server="ns1.parent.example.", rd=0, do=1, cd=1)
    finally:
        server.shutdown()
    assert seen
    path = seen[0]
    assert path.startswith("/?")
    assert "name=example.com." in path
    assert "type=DS" in path
    assert "do=1" in path
    assert "rd=0" in path
    assert "cd=1" in path
    assert "server=ns1.parent.example." in path
    keys = set(part.split("=", 1)[0] for part in path.split("?", 1)[1].split("&"))
    assert keys <= {"name", "type", "do", "rd", "cd", "server"}


def test_resolver_base_url_override_is_used(env, tmp_path):
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.path)
            body = json.dumps({"Status": 2}).encode()
            self.send_response(200)
            self.send_header("content-type", "application/dns-json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _fmt, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        env.settings.resolver_base_url = f"http://127.0.0.1:{port}/"
        store = Store(tmp_path / "other.db")
        store.ensure_catalog(env.clock.t)
        app = create_app(env.settings, lookup=None, store=store, notifier=env.notifier)
        client = app.test_client()
        body = env.lab.zone()
        response = client.post(
            "/v1/zones/user.example",
            data=json.dumps(body),
            headers={"Content-Type": "application/json", "X-Real-IP": "203.0.113.9"},
        )
    finally:
        server.shutdown()
    assert response.status_code == 503, response.get_json()
    assert response.get_json()["error"] == "parent_lookup_unavailable"
    assert seen
    assert all("do=1" in path and "rd=0" in path for path in seen)
    assert all("web3dns.net" not in path for path in seen)
    for path in seen:
        keys = set(part.split("=", 1)[0] for part in path.split("?", 1)[1].split("&"))
        assert keys <= {"name", "type", "do", "rd", "cd", "server"}
