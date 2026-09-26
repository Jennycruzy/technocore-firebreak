"""Bounded HTTP transport with redirects disabled."""

from __future__ import annotations

import http.client
import math
from urllib.parse import urlencode, urlsplit

from .errors import ProtocolError
from .schema import MAX_RESPONSE_BYTES, NAME


def _endpoint(base_url: str) -> tuple[str, str, int, str]:
    parsed = urlsplit(base_url)
    loopback = parsed.hostname in {"127.0.0.1", "::1", "localhost"}
    if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
        raise ProtocolError("base URL must use HTTPS except for loopback testing")
    if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ProtocolError("base URL must contain a host and no credentials, query, or fragment")
    if parsed.path not in {"", "/"}:
        raise ProtocolError("base URL must not contain a path")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as error:
        raise ProtocolError("base URL has an invalid port") from error
    return parsed.scheme, parsed.hostname, port, base_url.rstrip("/")


def fetch_room(
    base_url: str,
    room: str,
    *,
    since: int | None = None,
    limit: int = 50,
    timeout: float = 10.0,
) -> bytes:
    if NAME.fullmatch(room) is None:
        raise ProtocolError("room has an invalid name")
    if since is not None and (isinstance(since, bool) or not isinstance(since, int) or since < 0):
        raise ProtocolError("since must be a non-negative integer")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
        raise ProtocolError("limit must be between 1 and 200")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ProtocolError("timeout must be a positive finite number")
    timeout = float(timeout)
    if not math.isfinite(timeout) or timeout <= 0:
        raise ProtocolError("timeout must be a positive finite number")
    scheme, host, port, _ = _endpoint(base_url)
    query: dict[str, str | int] = {"format": "json", "limit": limit}
    if since is not None:
        query["since"] = since
    path = f"/r/{room}?{urlencode(query)}"
    connection_type = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
    connection = connection_type(host, port, timeout=timeout)
    try:
        connection.request(
            "GET",
            path,
            headers={"Accept": "application/json", "User-Agent": "technocore-firebreak/0.1"},
        )
        response = connection.getresponse()
        if 300 <= response.status < 400:
            raise ProtocolError("room transport refuses redirects")
        if response.status != 200:
            raise ProtocolError(f"room transport received HTTP {response.status}")
        body = response.read(MAX_RESPONSE_BYTES + 1)
    except (OSError, http.client.HTTPException) as error:
        raise ProtocolError(f"room transport failed: {error}") from error
    finally:
        connection.close()
    if len(body) > MAX_RESPONSE_BYTES:
        raise ProtocolError(f"response exceeds the {MAX_RESPONSE_BYTES}-byte limit")
    return body
