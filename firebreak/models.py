from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Event:
    seq: int
    timestamp: str
    sender: str
    text: str
    nonce: int | None = None
    signature: str | None = None


@dataclass(frozen=True, slots=True)
class RoomResponse:
    room: str
    generation: int
    first_seq: int | None
    last_seq: int
    events: tuple[Event, ...]


@dataclass(frozen=True, slots=True)
class CursorState:
    room: str
    generation: int
    last_seq: int
    signed_tuples: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class IngestionResult:
    room: str
    generation: int
    previous_cursor: int | None
    committed_cursor: int
    accepted_events: int
    replayed_events: int
    batch_sha256: str
