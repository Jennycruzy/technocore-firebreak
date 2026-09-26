"""Pinned upstream corpus verification and deterministic evidence."""

from __future__ import annotations

import hashlib
import platform
from pathlib import Path
from typing import Any

import cryptography

from .errors import ProtocolError
from .jsonutil import strict_json_loads
from .policy import ReplayState, classify
from .storage import atomic_json, atomic_write

UPSTREAM_COMMIT = "c0416e4c3ed41502080fd4d1f71e183cd6494b81"
UPSTREAM_SHA256 = "337392ea540f2614551c7b3e919494549ed4d3a2e866bee05c1a66cdfd5d6f67"
# Git/package tooling may add one final newline; both hashes represent identical JSON data.
PACKAGED_SHA256 = "287a9e4683d4783b5f750c2e436e4fcd1ae96b72252f928fe178e5d32b81f58c"
VENDORED = Path(__file__).with_name("data") / "consumer_safety_v1.json"


def install(raw: bytes, destination: Path = VENDORED) -> None:
    digest = hashlib.sha256(raw).hexdigest()
    if digest != UPSTREAM_SHA256:
        raise ProtocolError(f"upstream corpus hash mismatch: {digest}")
    try:
        value = strict_json_loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise ProtocolError("upstream corpus is not valid UTF-8 JSON") from error
    if value.get("schema_version") != 1 or not isinstance(value.get("cases"), list):
        raise ProtocolError("unsupported upstream corpus schema")
    destination.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(destination.parent, Path(destination.name), raw)


def load(path: Path = VENDORED) -> dict[str, Any]:
    raw = path.read_bytes()
    if path == VENDORED and hashlib.sha256(raw).hexdigest() not in {
        UPSTREAM_SHA256,
        PACKAGED_SHA256,
    }:
        raise ProtocolError("vendored upstream corpus does not match its pinned hash")
    try:
        value = strict_json_loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise ProtocolError(
            "consumer-safety corpus is not valid strict JSON"
        ) from error
    if not isinstance(value, dict) or not isinstance(value.get("cases"), list):
        raise ProtocolError("invalid consumer-safety corpus")
    return value


def verify(path: Path = VENDORED) -> dict[str, Any]:
    corpus = load(path)
    replay = ReplayState()
    results = []
    for case in corpus["cases"]:
        actual = classify(case, replay)
        expected = case.get("expected")
        results.append(
            {
                "id": case.get("id"),
                "passed": actual == expected,
                "actual": actual,
                "expected": expected,
            }
        )
    return {
        "schema": "technocore-firebreak-evidence-v1",
        "upstream_commit": UPSTREAM_COMMIT,
        "upstream_sha256": UPSTREAM_SHA256,
        "python": platform.python_version(),
        "cryptography": cryptography.__version__,
        "platform": platform.platform(),
        "case_count": len(results),
        "passed": all(item["passed"] for item in results) and bool(results),
        "results": results,
    }


def write_evidence(report: dict[str, Any], output: Path) -> None:
    atomic_json(output, Path("report.json"), report)
    summary = [
        "# Technocore Firebreak evidence",
        "",
        f"Result: **{'PASS' if report['passed'] else 'FAIL'}**",
        f"Cases: {report['case_count']}",
        f"Upstream commit: `{report['upstream_commit']}`",
        f"Fixture SHA-256: `{report['upstream_sha256']}`",
        "",
    ]
    summary.extend(
        f"- `{item['id']}`: {'PASS' if item['passed'] else 'FAIL'}"
        for item in report["results"]
    )
    atomic_write(output, Path("report.md"), ("\n".join(summary) + "\n").encode())
