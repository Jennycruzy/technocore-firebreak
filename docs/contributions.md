# Public contribution record

Firebreak is an independent consumer-safety implementation. It is not an official Technocore
submission portal or a claim that the upstream service has adopted every part of this repository.
The public contribution trail is therefore split between this evidence repository and focused
upstream issues or pull requests.

## Firebreak evidence

- Repository: <https://github.com/Jennycruzy/technocore-firebreak>
- Completed release: <https://github.com/Jennycruzy/technocore-firebreak/releases/tag/v0.4.0>
- Release commit: `1e6027d765ef36df21fc0fdfbb6741a073632487`
- CircleCI pipeline: <https://app.circleci.com/pipelines/github/Jennycruzy/technocore-firebreak/18>
- Reproducible suite: 78 tests, pinned hostile corpus verification, adapter certification, and
  Linux/Windows/wheel/container checks.

The v0.4.0 workflow demonstrates bounded fetch, quarantine, classification, review-only drafting,
source-event binding, explicit human confirmation, signed publication, bounded read-back
verification, and a local approval receipt. Tests use loopback fake servers; no hostile live-room
content is required.

## Upstream protocol contribution

- Finding: [#925 — duplicate JSON keys silently select a semantic value](https://github.com/flop-labs/technocore-chat/issues/925)
- Upstream implementation: [PR #926 — reject duplicate JSON object names](https://github.com/flop-labs/technocore-chat/pull/926)

The finding reported an ambiguous JSON write boundary affecting room and note POST bodies. The
review record on PR #926 contains the cap-compliant helper shape, escaped-key regression guidance,
and a compatibility review for nested duplicate names. PR #926 is upstream-owned and remains the
authoritative place for that server change; Firebreak does not duplicate it.

## How to evaluate the work

1. Re-run the commands in [`docs/reproducibility.md`](reproducibility.md).
2. Inspect the release commit and retained evidence before relying on a claim.
3. Treat upstream issues and pull requests as separate records: an open PR is not a merged fix,
   and an independent Firebreak result is not a Technocore server guarantee.

Future upstream submissions should be narrow server or documentation changes backed by a minimal
reproduction. New consumer-side safety features belong here, where they can be tested without
adding another overlapping upstream conformance corpus.
