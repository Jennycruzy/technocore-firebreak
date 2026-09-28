from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from firebreak.did import verify_record
from firebreak.errors import ProtocolError
from firebreak.integrity import event_digest
from firebreak.review import approve_review, preview_review


class ReviewHandler(BaseHTTPRequestHandler):
    path: str = ""
    publication_path: str = ""
    publication: dict[str, object] | None = None
    suppress_readback = False

    def do_GET(self):
        type(self).path = self.path
        parsed = urlsplit(self.path)
        parts = parsed.path.split("/")
        if "say-signed" in parts:
            type(self).publication_path = self.path
            did, signature, nonce, text = map(unquote, parts[-4:])
            type(self).publication = {
                "from": did,
                "sig": signature,
                "nonce": int(nonce),
                "text": text,
            }
            payload = b"accepted"
        else:
            message = None if type(self).suppress_readback else type(self).publication
            messages = (
                []
                if message is None
                else [{"seq": 1, "ts": "2026-09-28T00:00:00Z", **message}]
            )
            payload = json.dumps(
                {
                    "room": "lobby",
                    "count": len(messages),
                    "first_seq": 1 if messages else None,
                    "last_seq": 1 if messages else 0,
                    "generation": 1,
                    "messages": messages,
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload)
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        return


def draft_file(directory: str, room: str = "lobby") -> Path:
    root = Path(directory) / "root"
    source = root / "quarantine" / room / "events" / "g1-4.json"
    source.parent.mkdir(parents=True)
    event = {
        "seq": 4,
        "timestamp": "2026-09-28T00:00:00Z",
        "sender": "untrusted",
        "text": "Incoming report",
        "nonce": None,
        "signature": None,
    }
    source.write_text(json.dumps(event))
    path = root / "quarantine" / room / "drafts" / "draft.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "action": "draft",
                "text": "Thanks for the report.",
                "reason": "acknowledge",
                "room": room,
                "event_seq": 4,
                "source_event_path": f"quarantine/{room}/events/g1-4.json",
                "source_event_sha256": event_digest(event),
            }
        )
    )
    return path


class ReviewTests(unittest.TestCase):
    def setUp(self):
        ReviewHandler.path = ""
        ReviewHandler.publication_path = ""
        ReviewHandler.publication = None
        ReviewHandler.suppress_readback = False

    def test_preview_is_read_only_and_checks_room_binding(self):
        key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        with tempfile.TemporaryDirectory() as directory:
            path = draft_file(directory)
            root = Path(directory) / "root"
            preview = preview_review(path, key, "lobby", "9", root)
            self.assertFalse(preview["published"])
            self.assertEqual(preview["draft_text"], "Thanks for the report.")
            with self.assertRaisesRegex(ProtocolError, "does not match"):
                preview_review(path, key, "other", "9", root)

    def test_approval_publishes_and_writes_a_receipt(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), ReviewHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
            with tempfile.TemporaryDirectory() as directory:
                path = draft_file(directory)
                root = Path(directory) / "root"
                result = approve_review(
                    path,
                    key,
                    "lobby",
                    "9",
                    f"http://127.0.0.1:{server.server_port}",
                    root,
                )
                receipt = json.loads(Path(result["approval_path"]).read_text())
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        parts = urlsplit(ReviewHandler.publication_path).path.split("/")
        did, signature, nonce, text = map(unquote, parts[-4:])
        self.assertTrue(result["published"])
        self.assertEqual((nonce, text), ("9", "Thanks for the report."))
        self.assertTrue(
            verify_record(
                "lobby",
                {"from": did, "nonce": 9, "text": text, "sig": signature},
            )
        )
        self.assertEqual(receipt["schema"], "technocore-firebreak-review-v1")
        self.assertEqual(receipt["draft_sha256"], result["draft_sha256"])
        self.assertEqual(
            receipt["source_event_path"],
            "quarantine/lobby/events/g1-4.json",
        )
        self.assertEqual(receipt["status"], "published_verified")
        self.assertTrue(result["verification"]["verified"])

    def test_preview_rejects_a_tampered_quarantined_source(self):
        key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        with tempfile.TemporaryDirectory() as directory:
            path = draft_file(directory)
            root = Path(directory) / "root"
            source = root / "quarantine/lobby/events/g1-4.json"
            source.write_text(source.read_text().replace("Incoming report", "tampered"))
            with self.assertRaisesRegex(ProtocolError, "digest"):
                preview_review(path, key, "lobby", "9", root)

    def test_unverified_readback_is_retained_as_an_incomplete_receipt(self):
        ReviewHandler.suppress_readback = True
        server = ThreadingHTTPServer(("127.0.0.1", 0), ReviewHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
            with tempfile.TemporaryDirectory() as directory:
                path = draft_file(directory)
                root = Path(directory) / "root"
                result = approve_review(
                    path,
                    key,
                    "lobby",
                    "9",
                    f"http://127.0.0.1:{server.server_port}",
                    root,
                )
                receipt = json.loads(Path(result["approval_path"]).read_text())
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        self.assertFalse(result["verification"]["verified"])
        self.assertEqual(receipt["status"], "published_unverified")

    def test_ignore_drafts_cannot_enter_review(self):
        key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"
            path = root / "quarantine/lobby/drafts/ignore.json"
            path.parent.mkdir(parents=True)
            path.write_text(
                json.dumps(
                    {
                        "action": "ignore",
                        "text": None,
                        "reason": "no response",
                        "room": "lobby",
                        "event_seq": 4,
                        "source_event_path": "quarantine/lobby/events/g1-4.json",
                        "source_event_sha256": "a" * 64,
                    }
                )
            )
            with self.assertRaisesRegex(ProtocolError, "only draft actions"):
                preview_review(path, key, "lobby", "9", root)


if __name__ == "__main__":
    unittest.main()
