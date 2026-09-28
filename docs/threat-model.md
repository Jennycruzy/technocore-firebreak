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
4. Cursor state is replaced atomically only after quarantine, adapter processing, and durable run
   evidence succeed.
5. Same-generation cursors never move backwards and committed events are not reprocessed.
6. Event sequences must be contiguous, empty responses cannot advance state, and subsequent fetches
   continue from the persisted cursor.
7. Unknown fields fail closed instead of becoming implicit instructions.
8. Terminal output JSON-escapes control characters.
9. Network, subprocess, filesystem-read, and secret capabilities are never authorized by content.
10. Reply and signed-publication capabilities require explicit operator approval.
11. Adapter filesystem writes are confined to the dedicated `quarantine/adapter/` subtree and
    cannot target cursor or evidence state.
12. A bounded signed-tuple history is committed atomically in the same room-state document as the
    cursor, so replay observations cannot diverge from cursor progress.
13. Persistent cursor files have a bounded, exact schema; malformed or extended local state fails
    closed before any network request.
14. A cross-platform per-room lock prevents concurrent consumers from processing the same cursor
    state; contention fails before adapter execution.
15. Duplicate object keys and non-standard constants are rejected at every untrusted JSON boundary.

Firebreak includes a bounded HTTP transport and an optional locked-down Docker boundary for locally
trusted adapters. Docker and the host kernel remain trusted, and the portable subprocess runner is
not an OS sandbox. Firebreak does not include model-provider integration or grant an adapter direct
access to effectful executors. The broker supports fake or explicitly configured executors so every
effect remains visible and testable.

The bounded reference agent is a polling loop around this same pipeline. It has no model-provider
credentials, no automatic approval path, and no authority to publish. A model-backed adapter remains
an operator-selected extension and must be treated as locally trusted unless it runs in the Docker
isolation boundary. An optional local Ed25519 seed gives the agent a `did:key` for future
attribution; the seed is never copied into quarantine or evidence, and the signing command only
produces a canonical tuple for an operator to review.
