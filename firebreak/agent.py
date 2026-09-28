"""Bounded reference agent that polls a room through the Firebreak pipeline."""

from __future__ import annotations

import argparse
import math
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import ProtocolError
from .pipeline import process_room
from .render import terminal_safe_json


@dataclass(frozen=True, slots=True)
class AgentConfig:
    base_url: str
    room: str
    root: Path
    rounds: int = 1
    interval: float = 1.0
    adapter: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            isinstance(self.rounds, bool)
            or not isinstance(self.rounds, int)
            or not 1 <= self.rounds <= 10_000
        ):
            raise ProtocolError("rounds must be an integer between 1 and 10000")
        if isinstance(self.interval, bool) or not isinstance(
            self.interval, (int, float)
        ):
            raise ProtocolError(
                "interval must be a finite number between 0 and 60 seconds"
            )
        if not math.isfinite(float(self.interval)) or not 0 <= self.interval <= 60:
            raise ProtocolError(
                "interval must be a finite number between 0 and 60 seconds"
            )
        if any(not isinstance(part, str) or not part for part in self.adapter):
            raise ProtocolError("adapter command must contain non-empty strings")


def run_agent(config: AgentConfig) -> list[dict[str, Any]]:
    """Poll a room a bounded number of times and return safe run reports.

    The pipeline owns validation, quarantine, cursor commits, and capability decisions. This
    loop adds no approval path: replies and signed publication remain operator-gated, while
    network, process, filesystem-read, and secret capabilities remain denied by the broker.
    """
    reports = []
    for round_number in range(config.rounds):
        report = process_room(
            config.base_url,
            config.room,
            config.root,
            command=config.adapter or None,
        )
        report["agent_round"] = round_number + 1
        report["agent_rounds"] = config.rounds
        reports.append(report)
        if round_number + 1 < config.rounds:
            time.sleep(config.interval)
    return reports


def run_agent_command(
    base_url: str,
    room: str,
    root: Path,
    *,
    rounds: int = 1,
    interval: float = 1.0,
    adapter: Sequence[str] = (),
) -> list[dict[str, Any]]:
    """Convenience wrapper for callers that do not need to construct AgentConfig."""
    return run_agent(
        AgentConfig(
            base_url=base_url,
            room=room,
            root=root,
            rounds=rounds,
            interval=interval,
            adapter=tuple(adapter),
        )
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="firebreak-agent")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--root", type=Path, default=Path(".firebreak"))
    parser.add_argument("--rounds", type=int, default=1)
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("room")
    parser.add_argument("--adapter", nargs=argparse.REMAINDER, default=[])
    args = parser.parse_args(argv)
    try:
        reports = run_agent_command(
            args.base_url,
            args.room,
            args.root,
            rounds=args.rounds,
            interval=args.interval,
            adapter=args.adapter,
        )
    except (OSError, ProtocolError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    for report in reports:
        print(terminal_safe_json(report))
    return 0 if all(report["passed"] for report in reports) else 1


if __name__ == "__main__":
    raise SystemExit(main())
