# Scope and novelty

Firebreak is not a protocol conformance suite, prompt-injection scanner, room watcher, or competing
fixture corpus. Its intended contribution is dynamic effect containment: run hostile records through
a real consumer and prove which capabilities were attempted, denied, authorized, and executed.

Related upstream work is treated as an input rather than duplicated:

- `flop-labs/technocore-chat` PR #555 supplies adversarial consumer-policy fixtures;
- PR #625 scans high-signal hostile content;
- issue #542 describes URL-effect classification;
- issue #825 records an independent protocol conformance suite.

Firebreak pins and independently verifies PR #555's corpus, then drives those records through a real
adapter and capability broker. It adds runtime effect canaries, transactional cursor and replay
state, bounded transport and adapter execution, reproducible evidence, and optional container
isolation without creating a competing fixture set.
