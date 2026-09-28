from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .agent import run_agent_command
from .certify import certify, write_certification
from .consumer import consume_response
from .corpus import install, verify, write_evidence
from .did import (
    did_of,
    generate_identity,
    identity_note_path,
    load_private_key,
    sign_message,
)
from .errors import FirebreakError
from .identity_note import identity_note_status, refresh_identity_note
from .isolation import docker_adapter_command
from .pipeline import process_room
from .publish import publish_signed_message
from .render import terminal_safe_json


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(prog="firebreak")
    command.add_argument("--version", action="version", version=__version__)
    subcommands = command.add_subparsers(dest="command", required=True)
    ingest = subcommands.add_parser(
        "ingest", help="ingest an already-fetched room response"
    )
    ingest.add_argument("room")
    ingest.add_argument("response", type=Path)
    ingest.add_argument("--root", type=Path, default=Path(".firebreak"))
    corpus = subcommands.add_parser(
        "corpus", help="install or verify the pinned upstream corpus"
    )
    corpus_commands = corpus.add_subparsers(dest="corpus_command", required=True)
    corpus_install = corpus_commands.add_parser("install")
    corpus_install.add_argument("source", type=Path)
    corpus_verify = corpus_commands.add_parser("verify")
    corpus_verify.add_argument("--source", type=Path)
    corpus_verify.add_argument("--output", type=Path, default=Path("evidence"))
    certification = subcommands.add_parser(
        "certify", help="certify an adapter against hostile records"
    )
    certification.add_argument("--output", type=Path, default=Path("evidence"))
    certification.add_argument("--root", type=Path, default=Path(".firebreak"))
    certification.add_argument("--docker-image")
    certification.add_argument("adapter", nargs=argparse.REMAINDER)
    run = subcommands.add_parser(
        "run", help="process one room response through the full pipeline"
    )
    run.add_argument("room")
    run.add_argument("--base-url", required=True)
    run.add_argument("--root", type=Path, default=Path(".firebreak"))
    run.add_argument("--since", type=int)
    run.add_argument("adapter", nargs=argparse.REMAINDER)
    agent = subcommands.add_parser(
        "agent", help="poll a room through the bounded Firebreak reference agent"
    )
    agent.add_argument("--base-url", required=True)
    agent.add_argument("--root", type=Path, default=Path(".firebreak"))
    agent.add_argument("--rounds", type=int, default=1)
    agent.add_argument("--interval", type=float, default=1.0)
    agent.add_argument("--identity-key", type=Path)
    agent.add_argument("room")
    agent.add_argument("--adapter", nargs=argparse.REMAINDER, default=[])
    publish = subcommands.add_parser(
        "publish", help="preview and explicitly approve one signed room message"
    )
    publish.add_argument("--base-url", required=True)
    publish.add_argument("--key-file", type=Path, required=True)
    publish.add_argument("--room", required=True)
    publish.add_argument("--nonce", required=True)
    publish.add_argument("--text", required=True)
    publish.add_argument(
        "--confirm", action="store_true", help="authorize the network write"
    )
    publish.add_argument("--timeout", type=float, default=10.0)
    identity = subcommands.add_parser(
        "identity", help="create and use a local Ed25519 did:key identity"
    )
    identity_commands = identity.add_subparsers(dest="identity_command", required=True)
    generate = identity_commands.add_parser(
        "generate", help="create an owner-only raw Ed25519 seed file"
    )
    generate.add_argument("--key-file", type=Path, required=True)
    show = identity_commands.add_parser("show", help="print the DID for a key file")
    show.add_argument("--key-file", type=Path, required=True)
    note_path = identity_commands.add_parser(
        "note-path", help="print the public identity-note path for a DID"
    )
    note_path.add_argument("did")
    refresh = identity_commands.add_parser(
        "refresh", help="create or safely refresh the public identity note"
    )
    refresh.add_argument("--base-url", required=True)
    refresh.add_argument("--key-file", type=Path, required=True)
    refresh.add_argument("--timeout", type=float, default=10.0)
    status = identity_commands.add_parser(
        "status", help="read and classify the public identity note"
    )
    status.add_argument("--base-url", required=True)
    status.add_argument("--key-file", type=Path, required=True)
    status.add_argument("--timeout", type=float, default=10.0)
    sign = identity_commands.add_parser(
        "sign", help="sign a room message without sending it"
    )
    sign.add_argument("--key-file", type=Path, required=True)
    sign.add_argument("room")
    sign.add_argument("nonce")
    sign.add_argument("text")
    return command


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "run":
            report = process_room(
                args.base_url,
                args.room,
                args.root,
                command=args.adapter or None,
                since=args.since,
            )
            print(terminal_safe_json(report))
            return 0 if report["passed"] else 1
        if args.command == "agent":
            reports = run_agent_command(
                args.base_url,
                args.room,
                args.root,
                rounds=args.rounds,
                interval=args.interval,
                adapter=args.adapter,
                identity_key=args.identity_key,
            )
            for report in reports:
                print(terminal_safe_json(report))
            return 0 if all(report["passed"] for report in reports) else 1
        if args.command == "publish":
            key = load_private_key(args.key_file)
            signed = sign_message(key, args.room, args.nonce, args.text)
            if not args.confirm:
                print(terminal_safe_json({**signed, "published": False}))
                print(
                    "publication not sent; rerun with --confirm after reviewing the preview",
                    file=sys.stderr,
                )
                return 2
            result = publish_signed_message(
                args.base_url,
                key,
                args.room,
                args.nonce,
                args.text,
                approved=True,
                timeout=args.timeout,
            )
            print(terminal_safe_json({**result, "published": True}))
            return 0
        if args.command == "identity":
            if args.identity_command == "generate":
                print(generate_identity(args.key_file))
            elif args.identity_command == "show":
                print(did_of(load_private_key(args.key_file)))
            elif args.identity_command == "note-path":
                print(identity_note_path(args.did))
            elif args.identity_command == "refresh":
                print(
                    terminal_safe_json(
                        refresh_identity_note(
                            args.base_url,
                            load_private_key(args.key_file),
                            timeout=args.timeout,
                        )
                    )
                )
            elif args.identity_command == "status":
                report = identity_note_status(
                    args.base_url,
                    load_private_key(args.key_file),
                    timeout=args.timeout,
                )
                print(terminal_safe_json(report))
                return 0 if report["state"] == "present" else 1
            else:
                print(
                    terminal_safe_json(
                        sign_message(
                            load_private_key(args.key_file),
                            args.room,
                            args.nonce,
                            args.text,
                        )
                    )
                )
            return 0
        if args.command == "certify":
            if args.docker_image and args.adapter:
                raise ValueError("choose either --docker-image or an adapter command")
            command = (
                docker_adapter_command(args.docker_image)
                if args.docker_image
                else (args.adapter or None)
            )
            report = certify(args.root, command=command)
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
        result = consume_response(
            args.response.read_bytes(), room=args.room, root=args.root
        )
    except (FirebreakError, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(terminal_safe_json(result))
    return 0
