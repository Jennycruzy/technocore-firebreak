"""Strict validation for already-fetched Technocore room JSON."""

from __future__ import annotations

import json
import re
from typing import Any

from .errors import ProtocolError
from .models import Event, RoomResponse

MAX_RESPONSE_BYTES = 5 * 1024 * 1024
MAX_EVENTS = 200
MAX_TEXT_CHARS = 4096
NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,47}\Z")
SIGNATURE = re.compile(r"[A-Za-z0-9_-]{86}\Z")
ROOT_FIELDS = frozenset(
    {"room", "count", "first_seq", "last_seq", "generation", "messages", "wait_held"}
)
EVENT_FIELDS = frozenset({"seq", "ts", "from", "text", "nonce", "sig"})


def _integer(value: Any, field: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ProtocolError(f"{field} must be an integer >= {minimum}")
    return value


def _fields(value: dict[str, Any], allowed: frozenset[str], location: str) -> None:
    if unknown := sorted(set(value) - allowed):
        raise ProtocolError(f"{location} contains unknown fields: {unknown}")


def parse_room_response(raw: bytes, *, expected_room: str) -> RoomResponse:
    if not isinstance(raw, bytes):
        raise ProtocolError("response must be bytes")
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ProtocolError(f"response exceeds the {MAX_RESPONSE_BYTES}-byte limit")
    if NAME.fullmatch(expected_room) is None:
        raise ProtocolError("expected room has an invalid name")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProtocolError("response is not valid UTF-8 JSON") from error
    if not isinstance(document, dict):
        raise ProtocolError("response root must be an object")
    _fields(document, ROOT_FIELDS, "response")
    if document.get("room") != expected_room:
        raise ProtocolError("response room does not match the requested room")
    count = _integer(document.get("count"), "count")
    generation = _integer(document.get("generation"), "generation")
    last_seq = _integer(document.get("last_seq"), "last_seq")
    first_seq = document.get("first_seq")
    if first_seq is not None:
        first_seq = _integer(first_seq, "first_seq", minimum=1)
    if "wait_held" in document and not isinstance(document["wait_held"], bool):
        raise ProtocolError("wait_held must be a boolean")
    messages = document.get("messages")
    if not isinstance(messages, list):
        raise ProtocolError("messages must be an array")
    if count != len(messages):
        raise ProtocolError("count does not match messages length")
    if count > MAX_EVENTS:
        raise ProtocolError(f"response exceeds the {MAX_EVENTS}-event limit")

    events: list[Event] = []
    previous = 0
    for index, record in enumerate(messages):
        location = f"messages[{index}]"
        if not isinstance(record, dict):
            raise ProtocolError(f"{location} must be an object")
        _fields(record, EVENT_FIELDS, location)
        seq = _integer(record.get("seq"), f"{location}.seq", minimum=1)
        if previous and seq != previous + 1:
            raise ProtocolError("message sequences must be contiguous")
        timestamp = record.get("ts")
        sender = record.get("from")
        text = record.get("text")
        if not isinstance(timestamp, str) or not timestamp:
            raise ProtocolError(f"{location}.ts must be a non-empty string")
        if not isinstance(sender, str) or not sender:
            raise ProtocolError(f"{location}.from must be a non-empty string")
        if not isinstance(text, str):
            raise ProtocolError(f"{location}.text must be a string")
        if len(text) > MAX_TEXT_CHARS:
            raise ProtocolError(f"{location}.text exceeds {MAX_TEXT_CHARS} characters")
        nonce = record.get("nonce")
        if nonce is not None:
            nonce = _integer(nonce, f"{location}.nonce")
        signature = record.get("sig")
        if signature is not None and (
            not isinstance(signature, str) or SIGNATURE.fullmatch(signature) is None
        ):
            raise ProtocolError(f"{location}.sig is not canonical base64url")
        if signature is not None and nonce is None:
            raise ProtocolError(f"{location}.sig requires nonce")
        events.append(Event(seq, timestamp, sender, text, nonce, signature))
        previous = seq

    if events:
        if first_seq != events[0].seq:
            raise ProtocolError("first_seq does not match the first message")
        if last_seq != events[-1].seq:
            raise ProtocolError("last_seq does not match the final message")
    elif first_seq is not None:
        raise ProtocolError("first_seq must be null for an empty response")
    return RoomResponse(expected_room, generation, first_seq, last_seq, tuple(events))
