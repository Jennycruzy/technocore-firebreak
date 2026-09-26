from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .consumer import consume_response
from .corpus import install, verify, write_evidence
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
    corpus = subcommands.add_parser("corpus", help="install or verify the pinned upstream corpus")
    corpus_commands = corpus.add_subparsers(dest="corpus_command", required=True)
    corpus_install = corpus_commands.add_parser("install")
    corpus_install.add_argument("source", type=Path)
    corpus_verify = corpus_commands.add_parser("verify")
    corpus_verify.add_argument("--source", type=Path)
    corpus_verify.add_argument("--output", type=Path, default=Path("evidence"))
    return command


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "corpus":
            if args.corpus_command == "install":
                install(args.source.read_bytes())
                print("installed pinned upstream corpus")
                return 0
            report = verify(args.source) if args.source else verify()
            write_evidence(report, args.output)
            print(terminal_safe_json(report))
            return 0 if report["passed"] else 1
        result = consume_response(args.response.read_bytes(), room=args.room, root=args.root)
    except (FirebreakError, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(terminal_safe_json(result))
    return 0
