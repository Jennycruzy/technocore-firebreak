from __future__ import annotations

import hashlib
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from firebreak.agent import run_agent_command
from firebreak.did import (
    canonical_message,
    did_of,
    generate_identity,
    identity_note_path,
    is_did,
    load_private_key,
    sign_message,
    verify_record,
)
from firebreak.errors import ProtocolError


class DidIdentityTests(unittest.TestCase):
    def test_generated_identity_is_owner_only_and_signs_server_canonical_text(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identity.key"
            did = generate_identity(path)
            self.assertTrue(is_did(did))
            self.assertEqual(len(path.read_bytes()), 32)
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaises(ProtocolError):
                generate_identity(path)

            signed = sign_message(load_private_key(path), "lobby", "1", "hello\nworld")
            self.assertEqual(signed["text"], "hello world")
            self.assertTrue(
                verify_record(
                    "lobby",
                    {
                        "from": signed["did"],
                        "nonce": 1,
                        "text": signed["text"],
                        "sig": signed["signature"],
                    },
                )
            )

    def test_identity_note_path_hashes_the_did_string(self):
        with tempfile.TemporaryDirectory() as directory:
            key = load_private_key(self._seed_file(Path(directory) / "identity.key"))
            did = did_of(key)
        fingerprint = hashlib.sha256(did.encode()).hexdigest()[:16]
        self.assertEqual(
            identity_note_path(did), f"/kv/did-{fingerprint[:2]}/{fingerprint[2:]}"
        )

    def test_canonical_message_rejects_ambiguous_inputs(self):
        with self.assertRaises(ProtocolError):
            canonical_message("bad room", "1", "hello")
        with self.assertRaises(ProtocolError):
            canonical_message("lobby", "01", "hello")
        with self.assertRaises(ProtocolError):
            canonical_message("lobby", "1", "\n\t")

    def test_agent_reports_its_did_without_receiving_a_publish_capability(self):
        with tempfile.TemporaryDirectory() as directory:
            key_path = self._seed_file(Path(directory) / "identity.key")
            expected = did_of(load_private_key(key_path))
            with patch(
                "firebreak.agent.process_room",
                return_value={"passed": True, "events": []},
            ) as process:
                reports = run_agent_command(
                    "https://technocore.example",
                    "lobby",
                    Path(directory) / "root",
                    identity_key=key_path,
                )
        self.assertEqual(reports[0]["agent_did"], expected)
        self.assertIsNone(process.call_args.kwargs["command"])

    @staticmethod
    def _seed_file(path: Path) -> Path:
        path.write_bytes(bytes(range(32)))
        if os.name != "nt":
            path.chmod(0o600)
        return path


if __name__ == "__main__":
    unittest.main()
