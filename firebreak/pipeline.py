"""End-to-end fetch, quarantine, adapter, broker, evidence, and cursor processing."""

from __future__ import annotations

import hashlib
import json
import sys
from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .adapter import run_adapter, run_evidence
from .broker import CapabilityBroker
from .canary import EffectCanary
from .consumer import consume_response
from .cursor import load_cursor
from .draft import run_drafter
from .errors import ProtocolError
from .models import IngestionResult
from .storage import atomic_json
from .transport import fetch_room


def process_room(
    base_url: str,
    room: str,
    root: Path,
    *,
    command: Sequence[str] | None = None,
    draft_command: Sequence[str] | None = None,
    draft_timeout: float = 5.0,
    since: int | None = None,
) -> dict[str, Any]:
    previous = load_cursor(root, room)
    if previous is None:
        if since not in (None, 0):
            raise ProtocolError("initial request cannot skip unconsumed events")
        effective_since = since
    else:
        if since is not None and since != previous.last_seq:
            raise ProtocolError("since must match the committed cursor")
        effective_since = previous.last_seq
    raw = fetch_room(base_url, room, since=effective_since)
    adapter_command = list(
        command or [sys.executable, "-m", "firebreak.reference_adapter"]
    )
    event_results: list[dict[str, Any]] = []
    report: dict[str, Any] | None = None

    def process_event(event: dict[str, object], replayed: bool) -> None:
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
        run = run_adapter(adapter_command, event, CapabilityBroker(root, canaries))
        evidence = run_evidence(run)
        evidence["seq"] = event["seq"]
        evidence["replay_detected"] = replayed
        evidence["canary_calls"] = sum(
            len(canary.calls) for canary in canaries.values()
        )
        if evidence["executed_effects"] or evidence["canary_calls"]:
            raise RuntimeError("unapproved effect escaped containment")
        if draft_command:
            draft = run_drafter(draft_command, event, timeout=draft_timeout)
            draft_id = hashlib.sha256(
                json.dumps(event, ensure_ascii=True, sort_keys=True).encode()
            ).hexdigest()[:16]
            draft_relative = (
                Path("quarantine") / room / "drafts" / f"{event['seq']}-{draft_id}.json"
            )
            atomic_json(root, draft_relative, draft.record())
            evidence["draft"] = draft.evidence(draft_relative.as_posix())
        event_results.append(evidence)

    def write_evidence(result: IngestionResult) -> None:
        nonlocal report
        report = {
            "schema": "technocore-firebreak-run-v1",
            "ingestion": asdict(result),
            "adapter": adapter_command,
            "events": event_results,
            "passed": all(event["contained"] for event in event_results),
        }
        atomic_json(
            root,
            Path("evidence")
            / room
            / f"g{result.generation}-{result.committed_cursor}.json",
            report,
        )

    consume_response(
        raw,
        room=room,
        root=root,
        on_event=process_event,
        before_commit=write_evidence,
    )
    if report is None:
        raise RuntimeError("pipeline completed without durable evidence")
    return report
