from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from firebreak.draft import project_event, run_drafter
from firebreak.errors import ProtocolError

FIXTURE = Path(__file__).with_name("fixture_drafter.py")
EVENT = {
    "seq": 7,
    "timestamp": "2026-09-28T00:00:00Z",
    "sender": "untrusted",
    "text": "hello\nworld",
    "nonce": None,
    "signature": None,
    "ignored": "not forwarded",
}


class DraftTests(unittest.TestCase):
    def test_projection_drops_unknown_fields_and_marks_signature(self):
        projected = project_event(EVENT)
        self.assertEqual(
            set(projected),
            {"seq", "timestamp", "sender", "text", "nonce", "signature_present"},
        )
        self.assertFalse(projected["signature_present"])

    def test_draft_and_ignore_outputs_are_strictly_parsed(self):
        draft = run_drafter([sys.executable, str(FIXTURE), "draft"], EVENT)
        ignored = run_drafter([sys.executable, str(FIXTURE), "ignore"], EVENT)
        self.assertEqual(draft.action, "draft")
        self.assertEqual(draft.text, "Thanks for the report.")
        self.assertEqual(ignored.action, "ignore")
        self.assertIsNone(ignored.text)

    def test_drafter_sweeps_control_characters_before_any_review(self):
        result = run_drafter([sys.executable, str(FIXTURE), "echo"], EVENT)
        self.assertEqual(result.text, "hello world")

    def test_drafter_rejects_malformed_or_unbounded_outputs(self):
        with patch.dict(os.environ, {"FIREBREAK_PARENT_SECRET": "hidden"}):
            for mode in (
                "malformed",
                "unknown-field",
                "duplicate-key",
                "many",
                "output-overflow",
                "fail",
                "timeout",
            ):
                with self.subTest(mode=mode), self.assertRaises(ProtocolError):
                    run_drafter(
                        [sys.executable, str(FIXTURE), mode],
                        EVENT,
                        timeout=0.05 if mode == "timeout" else 5,
                    )

    def test_drafter_environment_does_not_include_parent_secrets(self):
        code = (
            "import json,os; input(); print(json.dumps({'action':'draft',"
            "'text':str('FIREBREAK_PARENT_SECRET' in os.environ),'reason':'audit'}))"
        )
        with patch.dict(os.environ, {"FIREBREAK_PARENT_SECRET": "hidden"}):
            result = run_drafter([sys.executable, "-c", code], EVENT)
        self.assertEqual(result.text, "False")


if __name__ == "__main__":
    unittest.main()
