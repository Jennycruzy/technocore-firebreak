from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from typing import Any


def terminal_safe_json(value: Any) -> str:
    """Render data without emitting raw control characters or non-ASCII format controls."""
    if is_dataclass(value) and not isinstance(value, type):
        value = asdict(value)
    return json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2)
