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
docker build -f docker/adapter.Dockerfile -t technocore-firebreak-adapter:0.2.0 .
firebreak certify --docker-image technocore-firebreak-adapter:0.2.0 --output evidence
```

The default CircleCI workflow is the required verification path: it repeats the portable checks on
Linux and Windows, tests the built wheel from outside the source tree, and runs container certification
with a remote Docker environment. An opt-in `verify_macos` workflow runs the same checks when `run_macos`
is true and the CircleCI plan has macOS capacity. Each certification job retains its evidence directory
as an artifact. A GitHub Actions copy is retained for manual diagnostics only; it is not triggered by
pushes or pull requests because hosted-runner availability is not guaranteed for this fork.
