"""Container command construction for stronger adapter isolation."""

from __future__ import annotations

import re

from .errors import ProtocolError

IMAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}\Z")


def docker_adapter_command(image: str) -> list[str]:
    if not isinstance(image, str) or IMAGE.fullmatch(image) is None:
        raise ProtocolError("container image reference is invalid")
    return [
        "docker", "run", "--rm", "-i",
        "--network", "none",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", "64",
        "--memory", "128m",
        "--cpus", "1",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
        image,
    ]
