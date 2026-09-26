from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .consumer import consume_response
from .errors import FirebreakError
from .render import terminal_safe_json


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(prog="firebreak")
    command.add_argument("--version", action="version", version=__version__)
    subcommands = command.add_subparsers(dest="command", required=True)
    ingest = subcommands.add_parser("ingest", help="ingest an already-fetched room response")
    ingest.add_argument("room")
    ingest.add_argument("response", type=Path)
    ingest.add_argument("--root", type=Path, default=Path(".firebreak"))
    return command


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        result = consume_response(args.response.read_bytes(), room=args.room, root=args.root)
    except (FirebreakError, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(terminal_safe_json(result))
    return 0
