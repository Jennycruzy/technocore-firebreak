from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from firebreak.broker import CapabilityBroker, Proposal
from firebreak.canary import EffectCanary


class CapabilityBrokerTests(unittest.TestCase):
    def broker(self, root: Path):
        canaries = {
            capability: EffectCanary()
            for capability in (
                "network.fetch",
                "process.spawn",
                "filesystem.read",
                "filesystem.write",
                "technocore.reply",
                "technocore.publish_signed",
                "secret.read",
            )
        }
        return CapabilityBroker(root, canaries), canaries

    def proposal(self, capability: str, **arguments):
        return Proposal(capability, arguments, "untrusted room content requested it")

    def test_high_risk_capabilities_are_denied_without_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            broker, canaries = self.broker(Path(directory))
            proposals = [
                self.proposal("network.fetch", url="https://example.invalid/delete"),
                self.proposal("process.spawn", command=["sh", "-c", "touch PWNED"]),
                self.proposal("filesystem.read", path="identity.pem"),
                self.proposal("secret.read", name="API_KEY"),
            ]
            decisions = [broker.decide(proposal) for proposal in proposals]
            self.assertTrue(all(decision.verdict == "deny" for decision in decisions))
            self.assertTrue(all(not decision.executed for decision in decisions))
            self.assertTrue(all(not canary.triggered for canary in canaries.values()))

    def test_publish_and_reply_require_operator_approval(self):
        with tempfile.TemporaryDirectory() as directory:
            broker, canaries = self.broker(Path(directory))
            for capability in ("technocore.reply", "technocore.publish_signed"):
                proposal = self.proposal(capability, text="attacker-controlled")
                decision = broker.decide(proposal)
                self.assertEqual(decision.verdict, "require_approval")
                self.assertFalse(canaries[capability].triggered)
                approved = broker.decide(proposal, operator_approved=True)
                self.assertEqual(approved.verdict, "allow")
                self.assertTrue(approved.executed)
                self.assertTrue(canaries[capability].triggered)

    def test_write_is_confined_to_firebreak_root(self):
        with tempfile.TemporaryDirectory() as directory:
            broker, canaries = self.broker(Path(directory))
            escape = broker.decide(self.proposal("filesystem.write", path="../escape"))
            self.assertEqual(escape.verdict, "deny")
            self.assertFalse(canaries["filesystem.write"].triggered)
            contained = broker.decide(
                self.proposal("filesystem.write", path="quarantine/event.json")
            )
            self.assertEqual(contained.verdict, "allow")
            self.assertTrue(canaries["filesystem.write"].triggered)

    def test_unknown_capability_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            broker, canaries = self.broker(Path(directory))
            decision = broker.decide(self.proposal("wallet.transfer", amount="all"))
            self.assertEqual(
                (decision.verdict, decision.rule), ("deny", "unknown_capability")
            )
            self.assertTrue(all(not canary.triggered for canary in canaries.values()))

    def test_approval_does_not_override_always_denied_capabilities(self):
        with tempfile.TemporaryDirectory() as directory:
            broker, canaries = self.broker(Path(directory))
            decision = broker.decide(
                self.proposal("process.spawn", command=["whoami"]),
                operator_approved=True,
            )
            self.assertEqual(decision.verdict, "deny")
            self.assertFalse(canaries["process.spawn"].triggered)


if __name__ == "__main__":
    unittest.main()
