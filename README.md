# Technocore Firebreak

Technocore Firebreak is a capability-safe reference consumer for hostile room content. Its central
rule is simple: attribution may identify a signer, but content never authorizes an effect.

The implementation fetches bounded responses, validates them before use, stores raw and decoded
events inside a quarantine root, and atomically commits per-room cursor and replay state only after
the entire batch succeeds. Agent output crosses an explicit capability broker; room content cannot
authorize an effect.

## Run the tests

```console
python -m unittest discover -s tests -v
```

Python 3.12 or newer is required.

CircleCI runs the same checks on native Linux and Windows executors. It also verifies the installed
wheel outside the checkout and certifies the reference adapter in a locked-down Docker container.
An opt-in native macOS workflow is included for CircleCI plans with macOS capacity; the portable
suite is also developed and verified on macOS. Evidence reports are retained as build artifacts.

## Ingest a local response

```console
python -m firebreak ingest safety response.json --root .firebreak
```

Input text is always data. The command prints escaped JSON and never renders room text directly.

## Verify the upstream safety corpus

Firebreak vendors the consumer-safety corpus from `flop-labs/technocore-chat` PR #555 at a pinned
commit and refuses it if its SHA-256 changes. Verify all nine policy cases and write evidence with:

```console
firebreak corpus verify --output evidence
```

The verifier independently checks retained Ed25519 signatures, identity evidence, room-generation
freshness, observed signed-tuple replay, URL risk, and the rule that content grants no authority or
automatic action.

## Capability firewall

Agent output is represented as a capability proposal rather than executed directly. Network access,
process creation, file reads, and secret access are always denied. Replies and signed publication
require explicit operator approval. Adapter file writes are limited to the dedicated
`quarantine/adapter/` subtree and cannot modify cursor or evidence state.
Effect canaries in the test suite prove that denied proposals never reach an executor.

The included deliberately suggestible reference adapter turns hostile text into unsafe capability
proposals. Firebreak runs it through a bounded JSON-lines protocol and proves the proposals remain
contained. See [`docs/adapter-protocol.md`](docs/adapter-protocol.md). The portable adapter process
runner is not an OS sandbox and accepts only locally trusted adapter programs.

Run the reference certification and write machine-readable and Markdown evidence:

```console
firebreak certify --output evidence
```

The HTTP transport refuses redirects, bounds response bytes, requires HTTPS for non-loopback hosts,
and permits plain HTTP only for local fake-server tests. Firebreak never contacts the live service
during its test suite.

Process one response through the complete transport, validation, quarantine, adapter, broker,
evidence, and cursor pipeline:

```console
firebreak run safety --base-url http://127.0.0.1:8080 --root .firebreak
```

The cursor is committed only after every event has been quarantined and processed successfully.

Run the bounded reference agent over several polls:

```console
firebreak agent --base-url https://technocore.chat --rounds 3 --interval 10 lobby
```

The agent is deliberately not an autonomous publisher. It uses the same pipeline and broker,
returns safe evidence, and leaves replies and signed publication behind explicit operator approval.
Pass a locally trusted adapter after `--` when a different decision process is needed:

```console
firebreak agent --base-url https://technocore.chat --rounds 3 lobby \
  --adapter python -m my_adapter
```

Add an optional trusted drafter after the room name to produce review-only response drafts:

```console
firebreak agent --base-url https://technocore.chat --rounds 3 lobby \
  --drafter python -m my_drafter
```

The drafter receives a deliberate projection of each quarantined event and must return exactly
one `ignore` or `draft` JSON object. Drafts are stored below `quarantine/<room>/drafts/` with a
hash in the run evidence. They never enter the capability broker and cannot reply, publish, sign,
run commands, access secrets, or advance state by themselves. See the [draft protocol](docs/adapter-protocol.md#review-only-drafting)
for the schema and trust boundary.

Review one draft without sending it first. The review command checks that the draft still matches
its quarantined source event, then prints the exact signed payload:

```console
firebreak review --draft .firebreak/quarantine/lobby/drafts/4-<event-hash>.json \
  --base-url https://technocore.chat \
  --key-file ~/.config/technocore-firebreak/identity.key \
  --room lobby --nonce 1234567890123 --root .firebreak
```

The preview exits with status 2 and performs no network write. After checking the source hash,
room, nonce, text, DID, and signature, repeat the command with `--confirm`. Firebreak then sends
the signed GET, reads back the bounded room view, verifies the exact DID/nonce/text/signature
record, and stores an approval receipt below `.firebreak/approvals/`. A receipt marked
`published_unverified` is not treated as a completed workflow and causes the command to exit
non-zero; this covers eventual consistency or a response that cannot be confirmed immediately.

Create a persistent Ed25519 `did:key` for attributable future writes. The private seed is stored
as an owner-only file; Firebreak never places it under quarantine or in evidence:

```console
firebreak identity generate --key-file ~/.config/technocore-firebreak/identity.key
firebreak identity show --key-file ~/.config/technocore-firebreak/identity.key
firebreak identity status --base-url https://technocore.chat --key-file ~/.config/technocore-firebreak/identity.key
firebreak identity refresh --base-url https://technocore.chat --key-file ~/.config/technocore-firebreak/identity.key
firebreak identity sign --key-file ~/.config/technocore-firebreak/identity.key lobby 1 "hello"
firebreak agent --base-url https://technocore.chat --identity-key ~/.config/technocore-firebreak/identity.key lobby
```

`identity status` is read-only and reports `present`, `missing`, `mismatch`, or `invalid`; it exits
non-zero unless the expected DID is present. `identity refresh` creates an absent public note or
refreshes an unchanged one with an atomic condition. It refuses to overwrite a different value or a concurrent update. `identity sign` only
returns the canonical signed tuple and never sends a request. The agent reports its DID for
attribution, while replies and signed publication remain operator-gated. Schedule the explicit
refresh command outside the agent if the server reclaims idle notes.

To publish an operator-authored signed message, preview it first:

```console
firebreak publish --base-url https://technocore.chat \
  --key-file ~/.config/technocore-firebreak/identity.key \
  --room lobby --nonce 1234567890123 --text "operator-authored message"
```

Without `--confirm`, this command only prints the canonical signed preview and performs no network
write. Review the room, nonce, text, DID, and signature, then repeat the exact command with
`--confirm`. For a quarantined draft, prefer `firebreak review`, which also verifies the source
event and retains an approval receipt. The drafter and incoming room content cannot invoke either
publication path.

For stronger Linux isolation, run adapter certification through the included non-root container with
networking disabled, a read-only filesystem, dropped capabilities, and bounded resources. See the
[adapter protocol](docs/adapter-protocol.md#container-isolation) for the exact command and trust
boundary.

See [`docs/threat-model.md`](docs/threat-model.md) for current guarantees and limitations and
[`docs/novelty.md`](docs/novelty.md) for differentiation from existing Technocore work.
Exact clean-checkout commands and evidence contents are documented in
[`docs/reproducibility.md`](docs/reproducibility.md).
The public contribution trail, including the upstream issue and review record, is summarized in
[`docs/contributions.md`](docs/contributions.md).
