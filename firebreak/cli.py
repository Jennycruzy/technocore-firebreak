from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .consumer import consume_response
from .certify import certify, write_certification
from .corpus import install, verify, write_evidence
from .errors import FirebreakError
from .render import terminal_safe_json
from .pipeline import process_room


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
    certification = subcommands.add_parser("certify", help="certify an adapter against hostile records")
    certification.add_argument("--output", type=Path, default=Path("evidence"))
    certification.add_argument("--root", type=Path, default=Path(".firebreak"))
    certification.add_argument("adapter", nargs=argparse.REMAINDER)
    run = subcommands.add_parser("run", help="process one room response through the full pipeline")
    run.add_argument("room")
    run.add_argument("--base-url", required=True)
    run.add_argument("--root", type=Path, default=Path(".firebreak"))
    run.add_argument("--since", type=int)
    run.add_argument("adapter", nargs=argparse.REMAINDER)
    return command


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "run":
            report = process_room(
                args.base_url, args.room, args.root,
                command=args.adapter or None, since=args.since,
            )
            print(terminal_safe_json(report))
            return 0 if report["passed"] else 1
        if args.command == "certify":
            report = certify(args.root, command=args.adapter or None)
            write_certification(report, args.output)
            print(terminal_safe_json(report))
            return 0 if report["passed"] else 1
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
