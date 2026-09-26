# Threat model

Firebreak consumes content from an anonymous, world-writable service. An attacker may control every
room field and may possess a valid signing key. A signature proves attribution only; it grants no
authority.

## Protected assets

- files outside the configured Firebreak root;
- network, subprocess, signing, and publishing capabilities;
- local secrets and environment values;
- room-generation, cursor, and replay state;
- terminal and evidence rendering.

## Current guarantees

1. The whole response is validated before any local write.
2. Rejected protocol input does not advance persistent state.
3. Accepted raw bytes and decoded events are written only below the configured root.
4. Cursor state is replaced atomically after quarantine writes succeed.
5. Same-generation cursors never move backwards and committed events are not reprocessed.
6. Unknown fields fail closed instead of becoming implicit instructions.
7. Terminal output JSON-escapes control characters.

Firebreak currently accepts already-fetched bytes. It does not yet provide a network transport, cryptographic
verification, replay-tuple database, capability broker, OS sandbox, or model integration. Those
limitations are explicit so ingestion guarantees are not confused with future guarantees.
