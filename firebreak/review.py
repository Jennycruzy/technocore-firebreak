"""Human review and approval bridge for quarantined drafts."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .did import clean_message, sign_message
from .errors import ProtocolError
from .integrity import event_digest
from .jsonutil import strict_json_loads
from .publish import publish_signed_message, verify_signed_publication
from .storage import atomic_json, contained_path

MAX_REVIEW_DRAFT_BYTES = 64 * 1024
REVIEW_FIELDS = frozenset(
    {
        "action",
        "text",
        "reason",
        "room",
        "event_seq",
        "source_event_path",
        "source_event_sha256",
    }
)
SOURCE_EVENT_FIELDS = frozenset(
    {"seq", "timestamp", "sender", "text", "nonce", "signature"}
)
SOURCE_EVENT_NAME = re.compile(r"g([0-9]+)-([0-9]+)\.json\Z")


def load_review_draft(path: Path) -> tuple[dict[str, Any], str]:
    """Load one quarantined draft and return its record plus file digest."""
    try:
        raw = path.expanduser().read_bytes()
    except OSError as error:
        raise ProtocolError(f"could not read draft: {error}") from error
    if len(raw) > MAX_REVIEW_DRAFT_BYTES:
        raise ProtocolError("draft exceeds the review size limit")
    try:
        value = strict_json_loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise ProtocolError("draft is not strict UTF-8 JSON") from error
    if not isinstance(value, dict) or set(value) != REVIEW_FIELDS:
        raise ProtocolError("draft has an invalid review schema")
    if value["action"] != "draft":
        raise ProtocolError("only draft actions can be reviewed for publication")
    if not isinstance(value["text"], str):
        raise ProtocolError("draft text must be a string")
    if not isinstance(value["reason"], str) or not value["reason"]:
        raise ProtocolError("draft reason must be a non-empty string")
    if not isinstance(value["room"], str) or not value["room"]:
        raise ProtocolError("draft room must be a non-empty string")
    if (
        isinstance(value["event_seq"], bool)
        or not isinstance(value["event_seq"], int)
        or value["event_seq"] < 1
    ):
        raise ProtocolError("draft event_seq must be a positive integer")
    source_digest = value["source_event_sha256"]
    if (
        not isinstance(source_digest, str)
        or len(source_digest) != 64
        or any(character not in "0123456789abcdef" for character in source_digest)
    ):
        raise ProtocolError("draft source_event_sha256 is invalid")
    if (
        not isinstance(value["source_event_path"], str)
        or not value["source_event_path"]
    ):
        raise ProtocolError("draft source_event_path is invalid")
    try:
        value["text"] = clean_message(value["text"])
    except ProtocolError as error:
        raise ProtocolError(f"draft text is invalid: {error}") from error
    return value, hashlib.sha256(raw).hexdigest()


def _verify_source_event(root: Path, room: str, draft: dict[str, Any]) -> str:
    """Bind the draft to the exact event retained by the quarantine."""
    relative = Path(draft["source_event_path"])
    filename_match = SOURCE_EVENT_NAME.fullmatch(relative.name)
    if (
        relative.is_absolute()
        or len(relative.parts) != 4
        or relative.parts[:3] != ("quarantine", room, "events")
        or filename_match is None
        or int(filename_match.group(2)) != draft["event_seq"]
    ):
        raise ProtocolError("draft source_event_path is outside the room quarantine")
    try:
        source_path = contained_path(root, relative)
        raw = source_path.read_bytes()
    except OSError as error:
        raise ProtocolError(
            f"could not read quarantined source event: {error}"
        ) from error
    if len(raw) > MAX_REVIEW_DRAFT_BYTES:
        raise ProtocolError("quarantined source event exceeds the review size limit")
    try:
        event = strict_json_loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise ProtocolError(
            "quarantined source event is not strict UTF-8 JSON"
        ) from error
    if not isinstance(event, dict) or set(event) != SOURCE_EVENT_FIELDS:
        raise ProtocolError("quarantined source event has an invalid schema")
    if event.get("seq") != draft["event_seq"]:
        raise ProtocolError("draft source event sequence does not match")
    if event_digest(event) != draft["source_event_sha256"]:
        raise ProtocolError("draft source event digest does not match quarantine")
    return relative.as_posix()


def _review_draft_path(path: Path, root: Path, room: str) -> Path:
    """Require the reviewed draft to remain in this room's quarantine."""
    candidate = path.expanduser().resolve()
    try:
        relative = candidate.relative_to(root.expanduser().resolve())
    except ValueError as error:
        raise ProtocolError("draft path is outside the Firebreak root") from error
    if len(relative.parts) != 4 or relative.parts[:3] != ("quarantine", room, "drafts"):
        raise ProtocolError("draft path is outside the room quarantine")
    return contained_path(root, relative)


def preview_review(
    path: Path,
    key: Ed25519PrivateKey,
    room: str,
    nonce: str,
    root: Path,
) -> dict[str, Any]:
    """Build the exact signed preview without performing a network write."""
    candidate = path.expanduser()
    draft, draft_digest = load_review_draft(candidate)
    if draft["room"] != room:
        raise ProtocolError("review room does not match the quarantined draft")
    draft_path = _review_draft_path(candidate, root, draft["room"])
    source_event_path = _verify_source_event(root, room, draft)
    signed = sign_message(key, room, nonce, draft["text"])
    return {
        "draft_path": str(draft_path),
        "draft_sha256": draft_digest,
        "source_event_sha256": draft["source_event_sha256"],
        "source_event_path": source_event_path,
        "event_seq": draft["event_seq"],
        "reason": draft["reason"],
        "draft_text": draft["text"],
        "signed": signed,
        "published": False,
    }


def approve_review(
    path: Path,
    key: Ed25519PrivateKey,
    room: str,
    nonce: str,
    base_url: str,
    root: Path,
    *,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Publish a reviewed draft and retain a local approval receipt."""
    preview = preview_review(path, key, room, nonce, root)
    publication = publish_signed_message(
        base_url,
        key,
        room,
        nonce,
        preview["draft_text"],
        approved=True,
        timeout=timeout,
    )
    verification = verify_signed_publication(
        base_url,
        key,
        room,
        nonce,
        preview["draft_text"],
        publication["signature"],
        timeout=timeout,
    )
    approval_id = hashlib.sha256(
        json.dumps(
            {
                "draft_sha256": preview["draft_sha256"],
                "room": room,
                "nonce": nonce,
            },
            sort_keys=True,
        ).encode()
    ).hexdigest()
    receipt = {
        "schema": "technocore-firebreak-review-v1",
        "approved_at": datetime.now(UTC).isoformat(),
        "draft_path": preview["draft_path"],
        "draft_sha256": preview["draft_sha256"],
        "source_event_path": preview["source_event_path"],
        "source_event_sha256": preview["source_event_sha256"],
        "event_seq": preview["event_seq"],
        "did": publication["did"],
        "room": room,
        "nonce": nonce,
        "text_sha256": hashlib.sha256(
            preview["draft_text"].encode("utf-8")
        ).hexdigest(),
        "signature": publication["signature"],
        "response_sha256": publication["response_sha256"],
        "verification": verification,
        "status": "published_verified"
        if verification["verified"]
        else "published_unverified",
    }
    receipt_path = atomic_json(root, Path("approvals") / f"{approval_id}.json", receipt)
    return {
        **preview,
        "publication": publication,
        "verification": verification,
        "published": True,
        "approval_path": str(receipt_path),
    }
