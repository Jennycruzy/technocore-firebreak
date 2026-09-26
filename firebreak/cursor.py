from __future__ import annotations

import json
import re
from dataclasses import asdict
from pathlib import Path

from .errors import ContainmentError, ProtocolError
from .models import CursorState
from .replay import MAX_SIGNED_TUPLES
from .storage import atomic_json, contained_path

MAX_CURSOR_BYTES = 128 * 1024
CURSOR_FIELDS = frozenset({"room", "generation", "last_seq", "signed_tuples"})
DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def cursor_relative(room: str) -> Path:
    return Path("state") / "cursors" / f"{room}.json"


def load_cursor(root: Path, room: str) -> CursorState | None:
    path = contained_path(root, cursor_relative(room))
    try:
        with path.open("rb") as cursor_file:
            raw = cursor_file.read(MAX_CURSOR_BYTES + 1)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise ContainmentError(f"cannot read cursor for {room}: {error}") from error
    if len(raw) > MAX_CURSOR_BYTES:
        raise ContainmentError(f"cursor for {room} exceeds its size limit")
    try:
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict) or set(value) != CURSOR_FIELDS:
            raise TypeError
        tuples = value["signed_tuples"]
        if (
            not isinstance(tuples, list)
            or len(tuples) > MAX_SIGNED_TUPLES
            or len(set(tuples)) != len(tuples)
            or not all(
                isinstance(item, str) and DIGEST.fullmatch(item) is not None
                for item in tuples
            )
        ):
            raise TypeError
        state = CursorState(
            room=value["room"],
            generation=value["generation"],
            last_seq=value["last_seq"],
            signed_tuples=tuple(tuples),
        )
    except (KeyError, UnicodeDecodeError, json.JSONDecodeError, TypeError) as error:
        raise ContainmentError(f"cursor for {room} is corrupt") from error
    if not isinstance(state.room, str) or state.room != room:
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
