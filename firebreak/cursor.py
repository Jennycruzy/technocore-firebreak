from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from .errors import ContainmentError, ProtocolError
from .models import CursorState
from .storage import atomic_json, contained_path


def cursor_relative(room: str) -> Path:
    return Path("state") / "cursors" / f"{room}.json"


def load_cursor(root: Path, room: str) -> CursorState | None:
    path = contained_path(root, cursor_relative(room))
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise ContainmentError(f"cannot read cursor for {room}: {error}") from error
    try:
        value = json.loads(raw.decode("utf-8"))
        tuples = value.get("signed_tuples", [])
        if not isinstance(tuples, list) or not all(
            isinstance(item, str) for item in tuples
        ):
            raise TypeError
        state = CursorState(
            room=value["room"],
            generation=value["generation"],
            last_seq=value["last_seq"],
            signed_tuples=tuple(tuples),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as error:
        raise ContainmentError(f"cursor for {room} is corrupt") from error
    if state.room != room:
        raise ContainmentError(f"cursor for {room} names a different room")
    if any(
        isinstance(item, bool) or not isinstance(item, int) or item < 0
        for item in (state.generation, state.last_seq)
    ):
        raise ContainmentError(f"cursor for {room} contains invalid values")
    return state


def validate_transition(previous: CursorState | None, next_state: CursorState) -> None:
    if previous is None:
        return
    if next_state.generation < previous.generation:
        raise ProtocolError("room generation moved backwards")
    if next_state.last_seq < previous.last_seq:
        raise ProtocolError("room cursor moved backwards")


def commit_cursor(root: Path, state: CursorState) -> Path:
    return atomic_json(root, cursor_relative(state.room), asdict(state))
