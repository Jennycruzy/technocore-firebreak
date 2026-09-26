from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from firebreak.corpus import UPSTREAM_COMMIT, UPSTREAM_SHA256, VENDORED, install, verify
from firebreak.did import is_did, verify_record
from firebreak.errors import ProtocolError


class CorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads(VENDORED.read_text(encoding="utf-8"))

    def test_pinned_corpus_matches_all_expected_classifications(self):
        report = verify()
        self.assertTrue(report["passed"], report)
        self.assertEqual(report["case_count"], 9)
        self.assertEqual(report["upstream_commit"], UPSTREAM_COMMIT)
        self.assertEqual(report["upstream_sha256"], UPSTREAM_SHA256)

    def test_valid_and_invalid_signatures_are_checked_cryptographically(self):
        cases = {case["id"]: case for case in self.corpus["cases"]}
        valid = cases["signed-malicious-instruction"]
        invalid = cases["invalid-signature"]
        self.assertTrue(is_did(valid["record"]["from"]))
        self.assertTrue(verify_record(valid["room"], valid["record"]))
        self.assertFalse(verify_record(invalid["room"], invalid["record"]))

    def test_modified_corpus_cannot_be_installed(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ProtocolError):
                install(b"{}", Path(directory) / "corpus.json")

    def test_evidence_contains_no_untrusted_message_text(self):
        encoded = json.dumps(verify(), sort_keys=True)
        for case in self.corpus["cases"]:
            self.assertNotIn(case["record"]["text"], encoded)


if __name__ == "__main__":
    unittest.main()
