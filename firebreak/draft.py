"""Bounded, non-executing response drafting protocol for the reference agent."""

from __future__ import annotations

import hashlib
import json
import math
import os
import subprocess
import tempfile
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from .did import clean_message
from .errors import ProtocolError
from .jsonutil import strict_json_loads

MAX_DRAFTER_OUTPUT = 64 * 1024
MAX_REASON_CHARS = 512


@dataclass(frozen=True, slots=True)
class DraftResult:
    """A model proposal that has no execution capability."""

    action: str
    text: str | None
    reason: str

    def record(self) -> dict[str, str | None]:
        return {"action": self.action, "text": self.text, "reason": self.reason}

    def evidence(self, path: str) -> dict[str, Any]:
        text = self.text or ""
        return {
            "action": self.action,
            "reason": self.reason,
            "text_chars": len(text),
            "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "quarantine_path": path,
        }


def project_event(event: dict[str, object]) -> dict[str, object]:
    """Expose only the deliberate event fields a drafter needs to see."""
    seq = event.get("seq")
    timestamp = event.get("timestamp")
    sender = event.get("sender")
    text = event.get("text")
    nonce = event.get("nonce")
    signature = event.get("signature")
    if (
        isinstance(seq, bool)
        or not isinstance(seq, int)
        or not isinstance(timestamp, str)
        or not isinstance(sender, str)
        or not isinstance(text, str)
        or (
            nonce is not None
            and (isinstance(nonce, bool) or not isinstance(nonce, int))
        )
        or (signature is not None and not isinstance(signature, str))
    ):
        raise ProtocolError("event cannot be projected for drafting")
    return {
        "seq": seq,
        "timestamp": timestamp,
        "sender": sender,
        "text": text,
        "nonce": nonce,
        "signature_present": signature is not None,
    }


def _result(value: Any) -> DraftResult:
    if not isinstance(value, dict) or set(value) != {"action", "text", "reason"}:
        raise ProtocolError("drafter output has an invalid schema")
    action, text, reason = value["action"], value["text"], value["reason"]
    if action not in {"ignore", "draft"}:
        raise ProtocolError("drafter action must be ignore or draft")
    if not isinstance(reason, str) or not reason or len(reason) > MAX_REASON_CHARS:
        raise ProtocolError("drafter reason is invalid")
    if action == "ignore":
        if text is not None:
            raise ProtocolError("ignore action must not contain draft text")
        return DraftResult(action, None, reason)
    if not isinstance(text, str):
        raise ProtocolError("draft action requires text")
    try:
        cleaned = clean_message(text)
    except ProtocolError as error:
        raise ProtocolError(f"drafter text is invalid: {error}") from error
    return DraftResult(action, cleaned, reason)


def run_drafter(
    command: Sequence[str], event: dict[str, object], *, timeout: float = 5.0
) -> DraftResult:
    """Run a trusted local drafter with bounded I/O and no capability path."""
    if not command or not all(isinstance(part, str) and part for part in command):
        raise ProtocolError("drafter command must contain non-empty strings")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ProtocolError("drafter timeout must be a positive finite number")
    if not math.isfinite(float(timeout)) or timeout <= 0:
        raise ProtocolError("drafter timeout must be a positive finite number")
    request = (
        json.dumps({"type": "draft", "event": project_event(event)}, ensure_ascii=True)
        + "\n"
    ).encode()
    environment = {"PATH": os.environ.get("PATH", ""), "PYTHONIOENCODING": "utf-8"}
    timed_out = False
    overflow = threading.Event()
    with tempfile.TemporaryDirectory(prefix="firebreak-drafter-") as directory:
        try:
            process = subprocess.Popen(
                list(command),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=directory,
                env=environment,
            )
            assert (
                process.stdin is not None
                and process.stdout is not None
                and process.stderr is not None
            )
            process.stdin.write(request)
            process.stdin.close()
            output = bytearray()
            errors = bytearray()

            def read_bounded(stream, destination):
                while chunk := stream.read(8192):
                    remaining = MAX_DRAFTER_OUTPUT + 1 - len(destination)
                    if remaining > 0:
                        destination.extend(chunk[:remaining])
                    if len(destination) > MAX_DRAFTER_OUTPUT:
                        overflow.set()

            readers = [
                threading.Thread(
                    target=read_bounded, args=(process.stdout, output), daemon=True
                ),
                threading.Thread(
                    target=read_bounded, args=(process.stderr, errors), daemon=True
                ),
            ]
            for reader in readers:
                reader.start()
            deadline = time.monotonic() + float(timeout)
            while process.poll() is None:
                if overflow.is_set() or time.monotonic() >= deadline:
                    timed_out = time.monotonic() >= deadline
                    process.kill()
                    break
                time.sleep(0.01)
            returncode = process.wait()
            for reader in readers:
                reader.join()
            process.stdout.close()
            process.stderr.close()
        except OSError as error:
            raise ProtocolError(f"could not start drafter: {error}") from error
    if overflow.is_set():
        raise ProtocolError("drafter output exceeded its byte limit")
    if timed_out:
        raise ProtocolError("drafter exceeded its time limit")
    if returncode != 0:
        raise ProtocolError(f"drafter exited with status {returncode}")
    try:
        stdout = output.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProtocolError("drafter output is not valid UTF-8") from error
    lines = stdout.splitlines()
    if len(lines) != 1 or not lines[0]:
        raise ProtocolError("drafter must emit exactly one JSON object")
    try:
        value = strict_json_loads(lines[0])
    except ValueError as error:
        raise ProtocolError("drafter output is not JSON") from error
    return _result(value)
