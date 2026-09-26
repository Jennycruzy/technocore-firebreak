"""Default-deny capability decisions for untrusted agent proposals."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .storage import contained_path

CAPABILITIES = frozenset(
    {
        "network.fetch",
        "process.spawn",
        "filesystem.read",
        "filesystem.write",
        "technocore.reply",
        "technocore.publish_signed",
        "secret.read",
    }
)
APPROVAL_REQUIRED = frozenset({"technocore.reply", "technocore.publish_signed"})
ALWAYS_DENIED = frozenset(
    {"network.fetch", "process.spawn", "filesystem.read", "secret.read"}
)


@dataclass(frozen=True, slots=True)
class Proposal:
    capability: str
    arguments: dict[str, Any]
    reason: str


@dataclass(frozen=True, slots=True)
class Decision:
    capability: str
    verdict: str
    rule: str
    executed: bool = False


class CapabilityBroker:
    def __init__(self, root: Path, executors: dict[str, Callable[[dict[str, Any]], Any]] | None = None):
        self.root = root.expanduser().resolve()
        self.executors = executors or {}

    def decide(self, proposal: Proposal, *, operator_approved: bool = False) -> Decision:
        capability = proposal.capability
        if capability not in CAPABILITIES:
            return Decision(capability, "deny", "unknown_capability")
        if capability in ALWAYS_DENIED:
            return Decision(capability, "deny", "content_cannot_authorize_capability")
        if capability == "filesystem.write":
            relative = proposal.arguments.get("path")
            if not isinstance(relative, str):
                return Decision(capability, "deny", "invalid_contained_path")
            try:
                contained_path(self.root, Path(relative))
            except (ValueError, RuntimeError):
                return Decision(capability, "deny", "path_outside_firebreak_root")
            return self._execute(proposal, "quarantine_write")
        if capability in APPROVAL_REQUIRED and not operator_approved:
            return Decision(capability, "require_approval", "operator_authorization_required")
        if capability in APPROVAL_REQUIRED:
            return self._execute(proposal, "operator_authorized")
        return Decision(capability, "deny", "default_deny")

    def _execute(self, proposal: Proposal, rule: str) -> Decision:
        executor = self.executors.get(proposal.capability)
        if executor is None:
            return Decision(proposal.capability, "deny", "no_executor_configured")
        executor(proposal.arguments)
        return Decision(proposal.capability, "allow", rule, executed=True)
