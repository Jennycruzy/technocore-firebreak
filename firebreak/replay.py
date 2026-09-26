"""Bounded signed-tuple observation state."""

from __future__ import annotations

import hashlib
from typing import Any

MAX_SIGNED_TUPLES = 1024


def signed_tuple_digest(room: str, event: dict[str, Any]) -> str | None:
    sender = event.get("sender")
    nonce = event.get("nonce")
    text = event.get("text")
    signature = event.get("signature")
    if (
        not isinstance(sender, str)
        or isinstance(nonce, bool)
        or not isinstance(nonce, int)
    ):
        return None
    if not isinstance(text, str) or not isinstance(signature, str):
        return None
    payload = f"{room}|{sender}|{nonce}|{text}|{signature}".encode()
    return hashlib.sha256(payload).hexdigest()


def remember(history: list[str], digest: str) -> None:
    if digest in history:
        history.remove(digest)
    history.append(digest)
    del history[:-MAX_SIGNED_TUPLES]
