"""Stable fingerprints for quarantined event records."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any


def event_digest(event: Mapping[str, Any]) -> str:
    """Hash the canonical JSON representation of one stored event."""
    payload = json.dumps(
        dict(event), ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
