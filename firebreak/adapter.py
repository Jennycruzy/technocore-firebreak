"""Bounded JSON-lines protocol for testing a consumer adapter."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Sequence

from .broker import CapabilityBroker, Decision, Proposal
from .errors import ProtocolError

MAX_ADAPTER_OUTPUT = 64 * 1024
MAX_PROPOSALS = 32


@dataclass(frozen=True, slots=True)
class AdapterRun:
    proposals: tuple[Proposal, ...]
    decisions: tuple[Decision, ...]
    stderr: str


def _proposal(value: Any, index: int) -> Proposal:
    if not isinstance(value, dict) or set(value) != {"capability", "arguments", "reason"}:
        raise ProtocolError(f"adapter proposal {index} has an invalid schema")
    capability, arguments, reason = value["capability"], value["arguments"], value["reason"]
    if not isinstance(capability, str) or not capability:
        raise ProtocolError(f"adapter proposal {index} has an invalid capability")
    if not isinstance(arguments, dict):
        raise ProtocolError(f"adapter proposal {index} arguments must be an object")
    if not isinstance(reason, str) or not reason:
        raise ProtocolError(f"adapter proposal {index} has an invalid reason")
    return Proposal(capability, arguments, reason)


def run_adapter(
    command: Sequence[str],
    event: dict[str, Any],
    broker: CapabilityBroker,
    *,
    timeout: float = 5.0,
) -> AdapterRun:
    """Run one adapter with bounded I/O.

    This portable runner reduces ambient environment exposure but is not an OS sandbox.
    Only adapters already trusted to run locally should be passed to it.
    """
    if not command or not all(isinstance(part, str) and part for part in command):
        raise ProtocolError("adapter command must contain non-empty strings")
    request = (json.dumps({"type": "event", "event": event}, ensure_ascii=True) + "\n").encode()
    environment = {"PATH": os.environ.get("PATH", ""), "PYTHONIOENCODING": "utf-8"}
    with tempfile.TemporaryDirectory(prefix="firebreak-adapter-") as directory:
        try:
            completed = subprocess.run(
                list(command),
                input=request,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=directory,
                env=environment,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise ProtocolError("adapter exceeded its time limit") from error
    if completed.returncode != 0:
        raise ProtocolError(f"adapter exited with status {completed.returncode}")
    if len(completed.stdout) > MAX_ADAPTER_OUTPUT or len(completed.stderr) > MAX_ADAPTER_OUTPUT:
        raise ProtocolError("adapter output exceeded its byte limit")
    try:
        stdout = completed.stdout.decode("utf-8")
        stderr = completed.stderr.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProtocolError("adapter output is not valid UTF-8") from error
    lines = stdout.splitlines()
    if len(lines) > MAX_PROPOSALS:
        raise ProtocolError("adapter emitted too many proposals")
    proposals: list[Proposal] = []
    for index, line in enumerate(lines):
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise ProtocolError(f"adapter proposal {index} is not JSON") from error
        proposals.append(_proposal(value, index))
    decisions = tuple(broker.decide(proposal) for proposal in proposals)
    return AdapterRun(tuple(proposals), decisions, stderr)


def run_evidence(run: AdapterRun) -> dict[str, Any]:
    return {
        "proposal_count": len(run.proposals),
        "attempted_effects": [proposal.capability for proposal in run.proposals],
        "decisions": [asdict(decision) for decision in run.decisions],
        "executed_effects": [
            decision.capability for decision in run.decisions if decision.executed
        ],
        "contained": all(not decision.executed for decision in run.decisions),
    }
