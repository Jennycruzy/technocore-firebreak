"""Explicitly approved signed Technocore publication."""

from __future__ import annotations

import hashlib
import http.client
import math
import ssl
from urllib.parse import quote, urlsplit

import certifi
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .did import sign_message
from .errors import ProtocolError

MAX_PUBLISH_RESPONSE = 64 * 1024


def _endpoint(base_url: str) -> tuple[str, str, int]:
    parsed = urlsplit(base_url)
    loopback = parsed.hostname in {"127.0.0.1", "::1", "localhost"}
    if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
        raise ProtocolError("base URL must use HTTPS except for loopback testing")
    if (
        not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ProtocolError(
            "base URL must contain a host and no credentials, path, query, or fragment"
        )
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as error:
        raise ProtocolError("base URL has an invalid port") from error
    return parsed.scheme, parsed.hostname, port


def _request(base_url: str, path: str, timeout: float) -> tuple[int, bytes]:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ProtocolError("timeout must be a positive finite number")
    timeout = float(timeout)
    if not math.isfinite(timeout) or timeout <= 0:
        raise ProtocolError("timeout must be a positive finite number")
    scheme, host, port = _endpoint(base_url)
    connection_type = (
        http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
    )
    connection = (
        connection_type(
            host,
            port,
            timeout=timeout,
            context=ssl.create_default_context(cafile=certifi.where()),
        )
        if scheme == "https"
        else connection_type(host, port, timeout=timeout)
    )
    try:
        connection.request(
            "GET",
            path,
            headers={
                "Accept": "application/json, text/plain",
                "User-Agent": "technocore-firebreak/0.4",
            },
        )
        response = connection.getresponse()
        if 300 <= response.status < 400:
            raise ProtocolError("publication transport refuses redirects")
        body = response.read(MAX_PUBLISH_RESPONSE + 1)
    except (OSError, http.client.HTTPException) as error:
        raise ProtocolError(f"publication transport failed: {error}") from error
    finally:
        connection.close()
    if len(body) > MAX_PUBLISH_RESPONSE:
        raise ProtocolError(
            f"publication response exceeds the {MAX_PUBLISH_RESPONSE}-byte limit"
        )
    return response.status, body


def publish_signed_message(
    base_url: str,
    key: Ed25519PrivateKey,
    room: str,
    nonce: str,
    text: str,
    *,
    approved: bool = False,
    timeout: float = 10.0,
) -> dict[str, object]:
    """Publish one signed message only when the caller explicitly approves it."""
    signed = sign_message(key, room, nonce, text)
    if not approved:
        raise ProtocolError("signed publication requires explicit operator approval")
    path = "/r/{}/{}/{}/{}/{}".format(
        quote(room, safe=""),
        "say-signed",
        quote(signed["did"], safe=""),
        quote(signed["signature"], safe=""),
        quote(signed["nonce"], safe=""),
    )
    path += "/" + quote(signed["text"], safe="")
    status, body = _request(base_url, path, timeout)
    if status != 200:
        raise ProtocolError(f"publication received HTTP {status}")
    return {
        "did": signed["did"],
        "room": room,
        "nonce": nonce,
        "text_chars": len(signed["text"]),
        "signature": signed["signature"],
        "response_bytes": len(body),
        "response_sha256": hashlib.sha256(body).hexdigest(),
    }
