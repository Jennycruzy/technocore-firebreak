"""Validate the whole batch, quarantine it, then commit its cursor."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path

from .cursor import commit_cursor, load_cursor, validate_transition
from .errors import ProtocolError
from .models import CursorState, IngestionResult
from .replay import remember, signed_tuple_digest
from .schema import parse_room_response
from .storage import atomic_json, atomic_write


def consume_response(
    raw: bytes,
    *,
    room: str,
    root: Path,
    on_event: Callable[[dict[str, object], bool], None] | None = None,
    before_commit: Callable[[IngestionResult], None] | None = None,
) -> IngestionResult:
    response = parse_room_response(raw, expected_room=room)
    previous = load_cursor(root, room)
    history = list(previous.signed_tuples if previous else ())
    next_state = CursorState(room, response.generation, response.last_seq)
    validate_transition(previous, next_state)
    if previous:
        if not response.events and response.last_seq != previous.last_seq:
            raise ProtocolError("empty response cannot move the committed cursor")
        if response.events and response.events[0].seq != previous.last_seq + 1:
            raise ProtocolError("response does not continue from the committed cursor")
    elif not response.events and response.last_seq != 0:
        raise ProtocolError("initial empty response must have a zero cursor")

    batch_digest = hashlib.sha256(raw).hexdigest()
    batch = Path("quarantine") / room / f"g{response.generation}-{batch_digest}.json"
    atomic_write(root, batch, raw)
    replayed_events = 0
    for event in response.events:
        relative = (
            Path("quarantine")
            / room
            / "events"
            / f"g{response.generation}-{event.seq}.json"
        )
        event_value = asdict(event)
        atomic_json(root, relative, event_value)
        tuple_digest = signed_tuple_digest(room, event_value)
        replayed = tuple_digest in history if tuple_digest is not None else False
        replayed_events += int(replayed)
        if on_event is not None:
            on_event(event_value, replayed)
        if tuple_digest is not None:
            remember(history, tuple_digest)
    next_state = CursorState(
        room, response.generation, response.last_seq, tuple(history)
    )
    result = IngestionResult(
        room=room,
        generation=response.generation,
        previous_cursor=previous.last_seq if previous else None,
        committed_cursor=response.last_seq,
        accepted_events=len(response.events),
        replayed_events=replayed_events,
        batch_sha256=batch_digest,
    )
    if before_commit is not None:
        before_commit(result)
    commit_cursor(root, next_state)
    return result
