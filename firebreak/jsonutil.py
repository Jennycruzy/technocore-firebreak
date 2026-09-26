"""Strict JSON decoding shared by untrusted input boundaries."""

from __future__ import annotations

import json
from typing import Any


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def strict_json_loads(value: str) -> Any:
    return json.loads(
        value,
        object_pairs_hook=_object,
        parse_constant=_constant,
    )
