# Changelog

## 0.1.0 — 2026-09-26

- Validate bounded Technocore room responses before writing local state.
- Quarantine raw and decoded events below an explicit containment root.
- Commit room generation and cursor state atomically after adapter processing succeeds.
- Reject sequence gaps and prevent empty responses or manual offsets from skipping unseen events.
- Resume room fetches automatically from the persisted cursor.
- Require durable run evidence before committing cursor and replay state.
- Reject oversized, malformed, extended, or non-canonical cursor state.
- Prevent concurrent consumers from processing the same room cursor.
- Persist bounded signed-tuple replay history atomically with each room cursor.
- Verify the hash, Ed25519 signatures, and expected classifications in the pinned PR #555 corpus.
- Deny content-originated network, process, file-read, and secret capabilities.
- Require operator authorization for replies and signed publication.
- Certify adapters through a bounded JSON-lines protocol with effect canaries.
- Provide a locked-down, non-root container path for stronger Linux isolation.
- Produce control-safe JSON and Markdown evidence without copying hostile message text.
