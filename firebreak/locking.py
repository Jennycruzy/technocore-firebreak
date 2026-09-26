"""Cross-platform, fail-closed room processing locks."""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .errors import ContainmentError
from .storage import contained_path


@contextmanager
def room_lock(root: Path, room: str) -> Iterator[None]:
    relative = Path("state") / "locks" / f"{room}.lock"
    lock = contained_path(root, relative)
    try:
        lock.parent.mkdir(parents=True, exist_ok=True)
        os.mkdir(lock)
    except FileExistsError as error:
        raise ContainmentError(f"room {room} is already being processed") from error
    except OSError as error:
        raise ContainmentError(f"cannot lock room {room}: {error}") from error
    try:
        yield
    finally:
        try:
            os.rmdir(lock)
        except OSError as error:
            raise ContainmentError(f"cannot release room {room}: {error}") from error
