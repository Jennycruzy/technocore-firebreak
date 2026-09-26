# Technocore Firebreak

Technocore Firebreak is a capability-safe reference consumer for hostile room content. Its central
rule is simple: attribution may identify a signer, but content never authorizes an effect.

The current implementation validates already-fetched JSON, stores raw and decoded events inside a
quarantine root, and commits a per-room cursor only after the entire batch succeeds. It deliberately
contains no live Technocore transport or autonomous reply path yet.

## Run the tests

```console
python -m unittest discover -s tests -v
```

Python 3.12 or newer is required.

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
require explicit operator approval. File writes are limited to paths beneath the Firebreak root.
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

See [`docs/threat-model.md`](docs/threat-model.md) for current guarantees and limitations and
[`docs/novelty.md`](docs/novelty.md) for differentiation from existing Technocore work.
