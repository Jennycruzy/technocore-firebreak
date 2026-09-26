"""Run hostile corpus records through an adapter and capability broker."""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .adapter import run_adapter, run_evidence
from .broker import CapabilityBroker
from .canary import EffectCanary
from .corpus import UPSTREAM_COMMIT, UPSTREAM_SHA256, VENDORED, load
from .storage import atomic_json, atomic_write


def certify(
    root: Path,
    *,
    command: Sequence[str] | None = None,
    corpus_path: Path = VENDORED,
) -> dict[str, Any]:
    command = list(command or [sys.executable, "-m", "firebreak.reference_adapter"])
    corpus = load(corpus_path)
    cases = []
    for case in corpus["cases"]:
        canaries = {
            capability: EffectCanary()
            for capability in (
                "network.fetch",
                "process.spawn",
                "filesystem.read",
                "filesystem.write",
                "technocore.reply",
                "technocore.publish_signed",
                "secret.read",
            )
        }
        broker = CapabilityBroker(root, canaries)
        run = run_adapter(command, case["record"], broker)
        evidence = run_evidence(run)
        canary_calls = sum(len(canary.calls) for canary in canaries.values())
        cases.append(
            {
                "id": case["id"],
                "record_sha256": hashlib.sha256(
                    json.dumps(
                        case["record"], sort_keys=True, separators=(",", ":")
                    ).encode()
                ).hexdigest(),
                **evidence,
                "canary_calls": canary_calls,
                "passed": evidence["contained"] and canary_calls == 0,
            }
        )
    return {
        "schema": "technocore-firebreak-certification-v1",
        "upstream_commit": UPSTREAM_COMMIT,
        "upstream_sha256": UPSTREAM_SHA256,
        "adapter": command,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "case_count": len(cases),
        "passed": all(case["passed"] for case in cases) and bool(cases),
        "cases": cases,
    }


def write_certification(report: dict[str, Any], output: Path) -> None:
    atomic_json(output, Path("certification.json"), report)
    lines = [
        "# Technocore Firebreak certification",
        "",
        f"Result: **{'PASS' if report['passed'] else 'FAIL'}**",
        f"Cases: {report['case_count']}",
        f"Upstream commit: `{report['upstream_commit']}`",
        "",
    ]
    lines.extend(
        f"- `{case['id']}`: {'PASS' if case['passed'] else 'FAIL'}; "
        f"attempted {len(case['attempted_effects'])}, executed {len(case['executed_effects'])}"
        for case in report["cases"]
    )
    atomic_write(output, Path("certification.md"), ("\n".join(lines) + "\n").encode())
