"""Bounded JSON-lines protocol for testing a consumer adapter."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import threading
import time
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
            process = subprocess.Popen(
                list(command),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=directory,
                env=environment,
            )
            assert process.stdin is not None and process.stdout is not None and process.stderr is not None
            process.stdin.write(request)
            process.stdin.close()
            output = bytearray()
            errors = bytearray()
            overflow = threading.Event()

            def read_bounded(stream, destination):
                while chunk := stream.read(8192):
                    remaining = MAX_ADAPTER_OUTPUT + 1 - len(destination)
                    if remaining > 0:
                        destination.extend(chunk[:remaining])
                    if len(destination) > MAX_ADAPTER_OUTPUT:
                        overflow.set()

            readers = [
                threading.Thread(target=read_bounded, args=(process.stdout, output), daemon=True),
                threading.Thread(target=read_bounded, args=(process.stderr, errors), daemon=True),
            ]
            for reader in readers:
                reader.start()
            deadline = time.monotonic() + timeout
            while process.poll() is None:
                if overflow.is_set() or time.monotonic() >= deadline:
                    process.kill()
                    break
                time.sleep(0.01)
            returncode = process.wait()
            for reader in readers:
                reader.join()
            process.stdout.close()
            process.stderr.close()
        except OSError as error:
            raise ProtocolError(f"could not start adapter: {error}") from error
    if overflow.is_set():
        raise ProtocolError("adapter output exceeded its byte limit")
    if time.monotonic() >= deadline and returncode != 0:
        raise ProtocolError("adapter exceeded its time limit")
    if returncode != 0:
        raise ProtocolError(f"adapter exited with status {returncode}")
    try:
        stdout = output.decode("utf-8")
        stderr = errors.decode("utf-8")
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
