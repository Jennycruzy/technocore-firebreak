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

See [`docs/threat-model.md`](docs/threat-model.md) for current guarantees and limitations and
[`docs/novelty.md`](docs/novelty.md) for differentiation from existing Technocore work.
