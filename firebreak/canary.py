"""In-memory effect recorders used to prove broker decisions."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class EffectCanary:
    calls: list[dict[str, Any]] = field(default_factory=list)

    def __call__(self, arguments: dict[str, Any]) -> None:
        self.calls.append(dict(arguments))

    @property
    def triggered(self) -> bool:
        return bool(self.calls)
