from __future__ import annotations

import base64
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from firebreak.did import did_of, sign_message, verify_record
from firebreak.errors import ProtocolError
from firebreak.publish import publish_signed_message


class PublishHandler(BaseHTTPRequestHandler):
    path: str = ""

    def do_GET(self):
        type(self).path = self.path
        payload = b"accepted"
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        return


class PublishTests(unittest.TestCase):
    def test_unapproved_publication_fails_before_network_access(self):
        key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        with self.assertRaisesRegex(ProtocolError, "explicit operator approval"):
            publish_signed_message("http://127.0.0.1:1", key, "lobby", "1", "hello")

    def test_approved_publication_sends_the_canonical_signed_path(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), PublishHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
            result = publish_signed_message(
                f"http://127.0.0.1:{server.server_port}",
                key,
                "lobby",
                "7",
                "hello\nworld",
                approved=True,
            )
            path = urlsplit(PublishHandler.path).path.split("/")
            did, signature, nonce, text = map(unquote, path[-4:])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        self.assertEqual(result["did"], did_of(key))
        self.assertEqual((did, nonce, text), (result["did"], "7", "hello world"))
        raw_signature = base64.urlsafe_b64decode(signature + "==")
        self.assertEqual(len(raw_signature), 64)
        self.assertTrue(
            verify_record(
                "lobby",
                {"from": did, "nonce": 7, "text": text, "sig": signature},
            )
        )
        self.assertEqual(result["response_bytes"], len(b"accepted"))

    def test_preview_signs_the_same_tuple_without_sending(self):
        key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        preview = sign_message(key, "lobby", "1", "hello")
        self.assertEqual(preview["canonical"], "lobby|1|hello")


if __name__ == "__main__":
    unittest.main()
