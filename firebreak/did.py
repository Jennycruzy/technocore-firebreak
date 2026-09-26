"""Minimal Ed25519 did:key verification for retained Technocore records."""

from __future__ import annotations

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .errors import ProtocolError

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
INDEX = {character: index for index, character in enumerate(ALPHABET)}
ED25519_PREFIX = b"\xed\x01"


def _base58_decode(value: str) -> bytes:
    number = 0
    for character in value:
        try:
            number = number * 58 + INDEX[character]
        except KeyError as error:
            raise ProtocolError("DID contains a non-base58btc character") from error
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\x00" * (len(value) - len(value.lstrip("1"))) + decoded


def public_key(did: str) -> Ed25519PublicKey:
    prefix = "did:key:z"
    if not isinstance(did, str) or not did.startswith(prefix):
        raise ProtocolError("sender is not an Ed25519 did:key")
    decoded = _base58_decode(did[len(prefix) :])
    if len(decoded) != 34 or not decoded.startswith(ED25519_PREFIX):
        raise ProtocolError("DID does not contain a canonical Ed25519 public key")
    try:
        return Ed25519PublicKey.from_public_bytes(decoded[2:])
    except ValueError as error:
        raise ProtocolError("DID contains invalid Ed25519 key bytes") from error


def is_did(value: object) -> bool:
    try:
        public_key(value)  # type: ignore[arg-type]
    except ProtocolError:
        return False
    return True


def verify_record(room: str, record: dict[str, object]) -> bool:
    sender, nonce, text, signature = (
        record.get("from"),
        record.get("nonce"),
        record.get("text"),
        record.get("sig"),
    )
    if (
        not isinstance(sender, str)
        or isinstance(nonce, bool)
        or not isinstance(nonce, int)
    ):
        return False
    if not isinstance(text, str) or not isinstance(signature, str):
        return False
    try:
        raw_signature = base64.urlsafe_b64decode(signature + "==")
        key = public_key(sender)
        key.verify(raw_signature, f"{room}|{nonce}|{text}".encode())
    except (ValueError, InvalidSignature, ProtocolError):
        return False
    return True
