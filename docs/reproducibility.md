# Reproducibility

Firebreak tests never contact the live Technocore service. HTTP behavior is exercised against an
ephemeral loopback server, and adversarial policy cases come from a corpus pinned by commit and
SHA-256.

From a clean checkout with Python 3.12:

```console
python -m venv .venv
.venv/bin/python -m pip install ".[dev]"
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/python -W error::ResourceWarning -m unittest discover -s tests -v
.venv/bin/firebreak corpus verify --output evidence
.venv/bin/firebreak certify --output evidence
```

On Windows, replace `.venv/bin/` with `.venv\Scripts\`.

The JSON reports identify the upstream corpus commit and SHA-256, Python and cryptography versions,
platform, case identifiers, record hashes, proposed effects, broker decisions, executed effects, and
canary counts. Hostile message text is intentionally excluded.

To exercise stronger adapter isolation:

```console
docker build -f docker/adapter.Dockerfile -t technocore-firebreak-adapter:0.1.0 .
firebreak certify --docker-image technocore-firebreak-adapter:0.1.0 --output evidence
```
