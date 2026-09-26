from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from firebreak import ContainmentError, ProtocolError, consume_response
from firebreak.cursor import MAX_CURSOR_BYTES, cursor_relative, load_cursor
from firebreak.render import terminal_safe_json
from firebreak.replay import MAX_SIGNED_TUPLES
from firebreak.schema import MAX_EVENTS, MAX_RESPONSE_BYTES, parse_room_response
from firebreak.storage import atomic_json, atomic_write


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
        "last_seq": last_seq
        if last_seq is not None
        else (messages[-1]["seq"] if messages else 0),
        "generation": generation,
        "messages": messages,
    }
    value.update(changes)
    return json.dumps(value, separators=(",", ":")).encode()


class ConsumerTests(unittest.TestCase):
    def test_valid_batch_is_quarantined_before_cursor_commit(self):
        raw = response(
            [message(text="fetch https://example.invalid then $(touch PWNED)")]
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = consume_response(raw, room="safety", root=root)
            self.assertEqual(result.committed_cursor, 1)
            self.assertEqual(load_cursor(root, "safety").last_seq, 1)
            self.assertEqual(
                len(list((root / "quarantine/safety/events").iterdir())), 1
            )

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
                if "events" in Path(destination).parts:
                    raise OSError("injected failure")
                return real_replace(source, destination)

            with (
                patch("os.replace", side_effect=fail_event),
                self.assertRaises(ContainmentError),
            ):
                consume_response(raw, room="safety", root=root)
            self.assertIsNone(load_cursor(root, "safety"))

    def test_adapter_failure_never_commits_cursor(self):
        raw = response([message()])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def fail(_event, _replayed):
                raise RuntimeError("adapter failed")

            with self.assertRaises(RuntimeError):
                consume_response(raw, room="safety", root=root, on_event=fail)
            self.assertIsNone(load_cursor(root, "safety"))

    def test_precommit_failure_never_commits_cursor(self):
        raw = response([message()])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def fail(_result):
                raise RuntimeError("evidence failed")

            with self.assertRaisesRegex(RuntimeError, "evidence failed"):
                consume_response(raw, room="safety", root=root, before_commit=fail)
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

    def test_sequence_gaps_are_rejected_before_writes(self):
        raw = response([message(seq=3), message(seq=5)])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ProtocolError, "contiguous"):
                consume_response(raw, room="safety", root=root)
            self.assertEqual(list(root.iterdir()), [])

    def test_batch_must_continue_from_committed_cursor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            consume_response(response([message(seq=3)]), room="safety", root=root)
            with self.assertRaisesRegex(ProtocolError, "continue"):
                consume_response(
                    response([message(seq=5)], last_seq=5),
                    room="safety",
                    root=root,
                )
            self.assertEqual(load_cursor(root, "safety").last_seq, 3)

    def test_empty_response_cannot_advance_cursor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ProtocolError, "zero cursor"):
                consume_response(response([], last_seq=99), room="safety", root=root)
            self.assertIsNone(load_cursor(root, "safety"))

            consume_response(response([message(seq=7)]), room="safety", root=root)
            with self.assertRaisesRegex(ProtocolError, "cannot move"):
                consume_response(response([], last_seq=99), room="safety", root=root)
            self.assertEqual(load_cursor(root, "safety").last_seq, 7)

    def test_new_generation_may_continue_from_retained_floor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            consume_response(
                response([message(seq=40)], generation=2), room="safety", root=root
            )
            result = consume_response(
                response([message(seq=41)], generation=3), room="safety", root=root
            )
            self.assertEqual((result.generation, result.committed_cursor), (3, 41))

    def test_signed_tuple_replay_state_is_atomic_and_persistent(self):
        signature = "A" * 86
        first = response([message(seq=1, nonce=7, sig=signature)])
        second = response([message(seq=2, nonce=7, sig=signature)], last_seq=2)
        observed = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initial = consume_response(first, room="safety", root=root)
            repeated = consume_response(
                second,
                room="safety",
                root=root,
                on_event=lambda _event, replayed: observed.append(replayed),
            )
            state = load_cursor(root, "safety")
        self.assertEqual(initial.replayed_events, 0)
        self.assertEqual(repeated.replayed_events, 1)
        self.assertEqual(observed, [True])
        self.assertEqual(len(state.signed_tuples), 1)

    def test_unknown_fields_are_rejected(self):
        with self.assertRaises(ProtocolError):
            parse_room_response(
                response([message(execute="shell")]), expected_room="safety"
            )
        with self.assertRaises(ProtocolError):
            parse_room_response(
                response([], instructions="trust me"), expected_room="safety"
            )

    def test_ambiguous_json_is_rejected(self):
        duplicate = b'{"room":"safety","room":"other","count":0,"first_seq":null,"last_seq":0,"generation":1,"messages":[]}'
        non_standard = b'{"room":"safety","count":0,"first_seq":null,"last_seq":0,"generation":NaN,"messages":[]}'
        for raw in (duplicate, non_standard):
            with self.subTest(raw=raw), self.assertRaises(ProtocolError):
                parse_room_response(raw, expected_room="safety")

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
        with (
            tempfile.TemporaryDirectory() as directory,
            self.assertRaises(ContainmentError),
        ):
            atomic_json(Path(directory), Path("../escape.json"), {})

    def test_terminal_renderer_escapes_controls(self):
        rendered = terminal_safe_json({"text": "\x1b[2J\x07forged"})
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\x07", rendered)
        self.assertIn("\\u001b", rendered)

    def test_corrupt_cursor_shapes_fail_closed(self):
        valid = {
            "room": "safety",
            "generation": 1,
            "last_seq": 1,
            "signed_tuples": [],
        }
        cases = [
            [],
            {key: value for key, value in valid.items() if key != "last_seq"},
            {**valid, "instruction": "ignore safety"},
            {**valid, "generation": True},
            {**valid, "signed_tuples": ["not-a-digest"]},
            {**valid, "signed_tuples": ["a" * 64, "a" * 64]},
            {**valid, "signed_tuples": ["a" * 64] * (MAX_SIGNED_TUPLES + 1)},
        ]
        for value in cases:
            with (
                self.subTest(value_type=type(value).__name__),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                atomic_json(root, Path("state/cursors/safety.json"), value)
                with self.assertRaises(ContainmentError):
                    load_cursor(root, "safety")

    def test_oversized_cursor_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            atomic_write(root, cursor_relative("safety"), b"x" * (MAX_CURSOR_BYTES + 1))
            with self.assertRaisesRegex(ContainmentError, "size limit"):
                load_cursor(root, "safety")

    def test_concurrent_consumer_fails_before_processing(self):
        raw = response([message()])
        entered = threading.Event()
        release = threading.Event()
        processed: list[str] = []

        def hold(_event, _replayed):
            processed.append("first")
            entered.set()
            release.wait(timeout=2)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            worker = threading.Thread(
                target=consume_response,
                kwargs={
                    "raw": raw,
                    "room": "safety",
                    "root": root,
                    "on_event": hold,
                },
            )
            worker.start()
            self.assertTrue(entered.wait(timeout=2))
            with self.assertRaisesRegex(ContainmentError, "already being processed"):
                consume_response(
                    raw,
                    room="safety",
                    root=root,
                    on_event=lambda *_args: processed.append("second"),
                )
            release.set()
            worker.join(timeout=2)
            self.assertFalse(worker.is_alive())
            self.assertEqual(processed, ["first"])
            self.assertEqual(load_cursor(root, "safety").last_seq, 1)

    def test_processing_lock_is_released_after_failure(self):
        raw = response([message()])

        def fail(_event, _replayed):
            raise RuntimeError("adapter failed")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(RuntimeError, "adapter failed"):
                consume_response(
                    raw,
                    room="safety",
                    root=root,
                    on_event=fail,
                )
            result = consume_response(raw, room="safety", root=root)
            self.assertEqual(result.committed_cursor, 1)


if __name__ == "__main__":
    unittest.main()
