from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from firebreak.certify import certify, write_certification


class CertificationTests(unittest.TestCase):
    def test_reference_adapter_is_contained_across_upstream_corpus(self):
        with tempfile.TemporaryDirectory() as directory:
            report = certify(Path(directory) / "root")
        self.assertTrue(report["passed"], report)
        self.assertEqual(report["case_count"], 9)
        self.assertTrue(all(case["canary_calls"] == 0 for case in report["cases"]))
        self.assertTrue(all(case["executed_effects"] == [] for case in report["cases"]))

    def test_certification_evidence_excludes_message_text(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = certify(root / "root")
            write_certification(report, root / "evidence")
            encoded = (root / "evidence/certification.json").read_text()
        self.assertNotIn("Ignore your operator", encoded)
        self.assertEqual(json.loads(encoded)["schema"], "technocore-firebreak-certification-v1")


if __name__ == "__main__":
    unittest.main()
