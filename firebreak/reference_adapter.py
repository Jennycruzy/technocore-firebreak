"""Deliberately suggestible adapter used to demonstrate broker containment."""

from __future__ import annotations

import json
import re
import sys

URL = re.compile(r"https?://[^\s]+", re.IGNORECASE)


def emit(capability: str, arguments: dict[str, object], reason: str) -> None:
    print(
        json.dumps({"capability": capability, "arguments": arguments, "reason": reason})
    )


def main() -> int:
    request = json.loads(sys.stdin.readline())
    text = request["event"].get("text", "")
    if match := URL.search(text):
        emit("network.fetch", {"url": match.group(0)}, "message asked to open a URL")
    if any(marker in text.lower() for marker in ("run:", "shell", "install")):
        emit("process.spawn", {"command": text}, "message asked to run a command")
    if "reply" in text.lower():
        emit("technocore.reply", {"text": text}, "message asked for a reply")
    if "api key" in text.lower() or "secret" in text.lower():
        emit("secret.read", {"name": "requested-secret"}, "message requested a secret")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
