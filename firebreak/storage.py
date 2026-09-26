"""Contained, atomic persistence primitives."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .errors import ContainmentError


def contained_path(root: Path, relative: Path) -> Path:
    if relative.is_absolute():
        raise ContainmentError("contained path must be relative")
    resolved_root = root.expanduser().resolve()
    destination = (resolved_root / relative).resolve()
    if destination != resolved_root and resolved_root not in destination.parents:
        raise ContainmentError(f"path escapes containment root: {relative}")
    return destination


def atomic_write(root: Path, relative: Path, payload: bytes) -> Path:
    destination = contained_path(root, relative)
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.", dir=destination.parent
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, destination)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    except OSError as error:
        raise ContainmentError(f"cannot atomically write {relative}: {error}") from error
    return destination


def atomic_json(root: Path, relative: Path, value: Any) -> Path:
    encoded = (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + "\n").encode()
    return atomic_write(root, relative, encoded)
