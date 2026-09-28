"""Minimal Ed25519 did:key verification for retained Technocore records."""

from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets
import stat
import tempfile
import unicodedata
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .errors import ProtocolError

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
INDEX = {character: index for index, character in enumerate(ALPHABET)}
ED25519_PREFIX = b"\xed\x01"
NONCE_MAX = 10**19 - 1
MESSAGE_MAX = 4096
INVISIBLE_CATEGORIES = frozenset(("Cc", "Cf", "Cs", "Co", "Zl", "Zp"))
ROOM = re.compile(r"[a-z0-9][a-z0-9_-]{0,47}\Z")


def _base58_decode(value: str) -> bytes:
    number = 0
    for character in value:
        try:
            number = number * 58 + INDEX[character]
        except KeyError as error:
            raise ProtocolError("DID contains a non-base58btc character") from error
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\x00" * (len(value) - len(value.lstrip("1"))) + decoded


def _base58_encode(value: bytes) -> str:
    number = int.from_bytes(value, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = ALPHABET[remainder] + encoded
    return "1" * (len(value) - len(value.lstrip(b"\x00"))) + (encoded or "")


def did_of(key: Ed25519PrivateKey) -> str:
    """Render the canonical Ed25519 `did:key` used by Technocore."""
    public = key.public_key().public_bytes_raw()
    return "did:key:z" + _base58_encode(ED25519_PREFIX + public)


def _check_key_permissions(path: Path) -> None:
    if os.name != "nt" and stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ProtocolError("identity key file must be readable only by its owner")


def load_private_key(path: Path) -> Ed25519PrivateKey:
    """Load a raw 32-byte seed from an owner-only identity file."""
    path = path.expanduser()
    try:
        _check_key_permissions(path)
        seed = path.read_bytes()
    except OSError as error:
        raise ProtocolError(f"could not read identity key: {error}") from error
    if len(seed) != 32:
        raise ProtocolError("identity key must contain exactly 32 seed bytes")
    try:
        return Ed25519PrivateKey.from_private_bytes(seed)
    except ValueError as error:
        raise ProtocolError("identity key is not a valid Ed25519 seed") from error


def generate_identity(path: Path) -> str:
    """Create an owner-only raw Ed25519 seed and return its public `did:key`."""
    path = path.expanduser()
    if path.exists():
        raise ProtocolError(f"identity key already exists: {path}")
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{path.name}.", dir=path.parent
        )
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                descriptor = -1
                output.write(secrets.token_bytes(32))
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
    except OSError as error:
        raise ProtocolError(f"could not create identity key: {error}") from error
    return did_of(load_private_key(path))


def identity_note_path(did: str) -> str:
    """Return the sharded public identity-note path from the Technocore guide."""
    public_key(did)
    fingerprint = hashlib.sha256(did.encode("utf-8")).hexdigest()[:16]
    return f"/kv/did-{fingerprint[:2]}/{fingerprint[2:]}"


def clean_message(text: str) -> str:
    """Apply the server's single-line sweep before signing."""
    if not isinstance(text, str):
        raise ProtocolError("message text must be a string")
    cleaned = "".join(
        " " if unicodedata.category(character) in INVISIBLE_CATEGORIES else character
        for character in text
    ).strip()
    if not cleaned:
        raise ProtocolError(
            "message text is empty after the server's single-line sweep"
        )
    if len(cleaned) > MESSAGE_MAX:
        raise ProtocolError(f"message text exceeds the {MESSAGE_MAX}-character limit")
    return cleaned


def canonical_message(room: str, nonce: str, text: str) -> tuple[str, str]:
    """Return `(canonical, swept_text)` for a signed room message."""
    if not isinstance(room, str) or ROOM.fullmatch(room) is None:
        raise ProtocolError("room has an invalid name")
    if not isinstance(nonce, str) or not nonce.isascii() or not nonce.isdigit():
        raise ProtocolError("nonce must contain 1-19 ASCII digits")
    numeric = int(nonce)
    if not 1 <= numeric <= NONCE_MAX or str(numeric) != nonce:
        raise ProtocolError("nonce must be canonical decimal text from 1 to 19 digits")
    swept = clean_message(text)
    return f"{room}|{nonce}|{swept}", swept


def sign_message(
    key: Ed25519PrivateKey, room: str, nonce: str, text: str
) -> dict[str, str]:
    """Sign a canonical room message without performing any network write."""
    canonical, swept = canonical_message(room, nonce, text)
    signature = (
        base64.urlsafe_b64encode(key.sign(canonical.encode("utf-8")))
        .decode()
        .rstrip("=")
    )
    return {
        "did": did_of(key),
        "nonce": nonce,
        "text": swept,
        "signature": signature,
        "canonical": canonical,
    }


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
