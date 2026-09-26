"""Validate the whole batch, quarantine it, then commit its cursor."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path

from .cursor import commit_cursor, load_cursor, validate_transition
from .errors import ProtocolError
from .models import CursorState, IngestionResult
from .schema import parse_room_response
from .storage import atomic_json, atomic_write


def consume_response(
    raw: bytes,
    *,
    room: str,
    root: Path,
    on_event: Callable[[dict[str, object]], None] | None = None,
) -> IngestionResult:
    response = parse_room_response(raw, expected_room=room)
    previous = load_cursor(root, room)
    next_state = CursorState(room, response.generation, response.last_seq)
    validate_transition(previous, next_state)
    if previous and response.generation == previous.generation:
        for event in response.events:
            if event.seq <= previous.last_seq:
                raise ProtocolError(
                    "response contains an event at or behind the committed cursor"
                )

    digest = hashlib.sha256(raw).hexdigest()
    batch = Path("quarantine") / room / f"g{response.generation}-{digest}.json"
    atomic_write(root, batch, raw)
    for event in response.events:
        relative = (
            Path("quarantine")
            / room
            / "events"
            / f"g{response.generation}-{event.seq}.json"
        )
        event_value = asdict(event)
        atomic_json(root, relative, event_value)
        if on_event is not None:
            on_event(event_value)
    commit_cursor(root, next_state)
    return IngestionResult(
        room=room,
        generation=response.generation,
        previous_cursor=previous.last_seq if previous else None,
        committed_cursor=response.last_seq,
        accepted_events=len(response.events),
        batch_sha256=digest,
    )
