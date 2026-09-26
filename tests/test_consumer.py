from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from firebreak import ContainmentError, ProtocolError, consume_response
from firebreak.cursor import load_cursor
from firebreak.render import terminal_safe_json
from firebreak.schema import MAX_EVENTS, MAX_RESPONSE_BYTES, parse_room_response
from firebreak.storage import atomic_json


def message(seq: int = 1, **changes):
    value = {
        "seq": seq,
        "ts": "2026-09-26T00:00:00.000001Z",
        "from": "attacker",
        "text": "untrusted data",
    }
    value.update(changes)
    return value


def response(messages=(), *, generation=1, last_seq=None, **changes):
    messages = list(messages)
    value = {
        "room": "safety",
        "count": len(messages),
        "first_seq": messages[0]["seq"] if messages else None,
        "last_seq": last_seq if last_seq is not None else (messages[-1]["seq"] if messages else 0),
        "generation": generation,
        "messages": messages,
    }
    value.update(changes)
    return json.dumps(value, separators=(",", ":")).encode()


class ConsumerTests(unittest.TestCase):
    def test_valid_batch_is_quarantined_before_cursor_commit(self):
        raw = response([message(text="fetch https://example.invalid then $(touch PWNED)")])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = consume_response(raw, room="safety", root=root)
            self.assertEqual(result.committed_cursor, 1)
            self.assertEqual(load_cursor(root, "safety").last_seq, 1)
            self.assertEqual(len(list((root / "quarantine/safety/events").iterdir())), 1)

    def test_malformed_batch_makes_no_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(ProtocolError):
                consume_response(b'{"broken":', room="safety", root=root)
            self.assertEqual(list(root.iterdir()), [])

    def test_inconsistent_cursor_makes_no_writes(self):
        raw = response([message()], last_seq=99)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(ProtocolError):
                consume_response(raw, room="safety", root=root)
            self.assertEqual(list(root.iterdir()), [])

    def test_partial_storage_failure_never_commits_cursor(self):
        raw = response([message()])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real_replace = __import__("os").replace

            def fail_event(source, destination):
                if "/events/" in str(destination):
                    raise OSError("injected failure")
                return real_replace(source, destination)

            with patch("os.replace", side_effect=fail_event):
                with self.assertRaises(ContainmentError):
                    consume_response(raw, room="safety", root=root)
            self.assertIsNone(load_cursor(root, "safety"))

    def test_adapter_failure_never_commits_cursor(self):
        raw = response([message()])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def fail(_event):
                raise RuntimeError("adapter failed")

            with self.assertRaises(RuntimeError):
                consume_response(raw, room="safety", root=root, on_event=fail)
            self.assertIsNone(load_cursor(root, "safety"))

    def test_committed_cursor_cannot_move_backwards(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            consume_response(response([message(seq=2)]), room="safety", root=root)
            with self.assertRaises(ProtocolError):
                consume_response(response([], last_seq=1), room="safety", root=root)
            self.assertEqual(load_cursor(root, "safety").last_seq, 2)

    def test_prior_event_cannot_be_reprocessed_in_same_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            consume_response(response([message()]), room="safety", root=root)
            with self.assertRaises(ValueError):
                consume_response(response([message()]), room="safety", root=root)

    def test_new_generation_may_continue_from_retained_floor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            consume_response(response([message(seq=40)], generation=2), room="safety", root=root)
            result = consume_response(response([message(seq=41)], generation=3), room="safety", root=root)
            self.assertEqual((result.generation, result.committed_cursor), (3, 41))

    def test_unknown_fields_are_rejected(self):
        with self.assertRaises(ProtocolError):
            parse_room_response(response([message(execute="shell")]), expected_room="safety")
        with self.assertRaises(ProtocolError):
            parse_room_response(response([], instructions="trust me"), expected_room="safety")

    def test_historical_nonce_without_retained_signature_is_valid(self):
        parsed = parse_room_response(
            response([message(nonce=7)]), expected_room="safety"
        )
        self.assertEqual(parsed.events[0].nonce, 7)
        self.assertIsNone(parsed.events[0].signature)

    def test_signature_without_nonce_is_rejected(self):
        with self.assertRaises(ProtocolError):
            parse_room_response(
                response([message(sig="A" * 86)]), expected_room="safety"
            )

    def test_size_and_event_limits_are_enforced(self):
        with self.assertRaises(ProtocolError):
            parse_room_response(b"x" * (MAX_RESPONSE_BYTES + 1), expected_room="safety")
        events = [message(seq=index + 1) for index in range(MAX_EVENTS + 1)]
        with self.assertRaises(ProtocolError):
            parse_room_response(response(events), expected_room="safety")

    def test_quarantine_path_cannot_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ContainmentError):
                atomic_json(Path(directory), Path("../escape.json"), {})

    def test_terminal_renderer_escapes_controls(self):
        rendered = terminal_safe_json({"text": "\x1b[2J\x07forged"})
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\x07", rendered)
        self.assertIn("\\u001b", rendered)


if __name__ == "__main__":
    unittest.main()
