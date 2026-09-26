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

See [`docs/threat-model.md`](docs/threat-model.md) for current guarantees and limitations and
[`docs/novelty.md`](docs/novelty.md) for differentiation from existing Technocore work.
