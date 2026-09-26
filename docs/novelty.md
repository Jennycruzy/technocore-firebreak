# Scope and novelty

Firebreak is not a protocol conformance suite, prompt-injection scanner, room watcher, or competing
fixture corpus. Its intended contribution is dynamic effect containment: run hostile records through
a real consumer and prove which capabilities were attempted, denied, authorized, and executed.

Related upstream work is treated as an input rather than duplicated:

- `flop-labs/technocore-chat` PR #555 supplies adversarial consumer-policy fixtures;
- PR #625 scans high-signal hostile content;
- issue #542 describes URL-effect classification;
- issue #825 records an independent protocol conformance suite.

The current implementation establishes the transactional ingestion boundary needed by the later
capability broker. Future work will pin and consume PR #555 at an exact commit while keeping
Firebreak-only runtime cases in a separate corpus.
