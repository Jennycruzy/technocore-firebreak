# Changelog

## Unreleased

- Remove optional model/drafter/review integration and promotional launch-copy material from the
  main branch. The v0.4.0 release remains an immutable historical snapshot.

## 0.4.0 — 2026-09-28

- Add preview-first, explicitly approved signed publication for operator-authored messages.
- Reject unapproved publication before network access and verify canonical signed paths in tests.
- Add a source-bound review bridge for quarantined drafts, with tamper detection and exact source
  hashes in run evidence.
- Read back and verify the signed record after an approved review, then retain a local approval
  receipt that distinguishes verified from unverified publication.
- Keep incoming content and drafter output unable to invoke publication.
- Expand the regression suite to 78 tests.

## 0.3.0 — 2026-09-28

- Add a bounded review-only drafter protocol for producing response drafts from quarantined
  event projections.
- Keep draft text in quarantine with hashes in evidence; no draft can invoke a capability,
  publish, sign, or advance a cursor.
- Reject malformed, duplicated, unknown, oversized, timed-out, and non-canonical drafter output.
- Expand the regression suite to 70 tests.

## 0.2.0 — 2026-09-28

- Add a read-only identity-note status check with mismatch and malformed-content classification.
- Add collision-safe identity-note creation and refresh with strict read verification and atomic
  write conditions.
- Use the `certifi` CA bundle for portable HTTPS verification on identity-note operations.
- Publish the bounded agent and DID tooling as a versioned release with 62 regression tests.
- Add a bounded `firebreak agent` polling loop and `firebreak-agent` entry point.
- Keep the reference agent behind the same quarantine, capability broker, evidence, and cursor
  commit rules; it has no automatic reply or publication approval path.
- Add owner-only Ed25519 `did:key` generation, loading, identity-note paths, and offline message
  signing for attributable future writes.

## 0.1.0 — 2026-09-26

- Validate bounded Technocore room responses before writing local state.
- Quarantine raw and decoded events below an explicit containment root.
- Commit room generation and cursor state atomically after adapter processing succeeds.
- Reject sequence gaps and prevent empty responses or manual offsets from skipping unseen events.
- Resume room fetches automatically from the persisted cursor.
- Require durable run evidence before committing cursor and replay state.
- Reject oversized, malformed, extended, or non-canonical cursor state.
- Prevent concurrent consumers from processing the same room cursor.
- Reject ambiguous duplicate-key and non-standard JSON inputs.
- Persist bounded signed-tuple replay history atomically with each room cursor.
- Verify the hash, Ed25519 signatures, and expected classifications in the pinned PR #555 corpus.
- Deny content-originated network, process, file-read, and secret capabilities.
- Require operator authorization for replies and signed publication.
- Certify adapters through a bounded JSON-lines protocol with effect canaries.
- Provide a locked-down, non-root container path for stronger Linux isolation.
- Produce control-safe JSON and Markdown evidence without copying hostile message text.
