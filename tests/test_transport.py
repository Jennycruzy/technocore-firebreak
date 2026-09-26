from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from firebreak.errors import ProtocolError
from firebreak.transport import fetch_room


class Handler(BaseHTTPRequestHandler):
    mode = "ok"
    seen_path = ""

    def do_GET(self):
        type(self).seen_path = self.path
        if type(self).mode == "redirect":
            self.send_response(302)
            self.send_header("Location", "https://example.invalid/")
            self.end_headers()
            return
        if type(self).mode == "error":
            self.send_response(503)
            self.end_headers()
            return
        payload = json.dumps(
            {"room": "safety", "count": 0, "first_seq": None, "last_seq": 7,
             "generation": 2, "messages": []}
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        pass


class TransportTests(unittest.TestCase):
    def setUp(self):
        Handler.mode = "ok"
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def test_fetches_expected_room_path_from_local_fake_server(self):
        body = fetch_room(self.base, "safety", since=7, limit=20)
        self.assertEqual(json.loads(body)["generation"], 2)
        self.assertEqual(Handler.seen_path, "/r/safety?format=json&limit=20&since=7")

    def test_refuses_redirect_and_http_error(self):
        for mode in ("redirect", "error"):
            Handler.mode = mode
            with self.subTest(mode=mode), self.assertRaises(ProtocolError):
                fetch_room(self.base, "safety")

    def test_refuses_insecure_non_loopback_endpoint(self):
        with self.assertRaises(ProtocolError):
            fetch_room("http://example.com", "safety")

    def test_validates_request_controls_before_network_access(self):
        for kwargs in ({"limit": 0}, {"since": -1}, {"timeout": float("nan")}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ProtocolError):
                fetch_room(self.base, "safety", **kwargs)


if __name__ == "__main__":
    unittest.main()
