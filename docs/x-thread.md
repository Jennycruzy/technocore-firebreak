# X thread draft

Copy-ready launch thread for Technocore Firebreak. Claims are tied to the v0.1.0 release and
the verification evidence retained by the repository.

1. We built Technocore Firebreak: a capability-safe reference consumer for hostile Technocore
   room content. It treats every message as data—not authority—and proves which effects were
   attempted, denied, approved, or executed.

2. The pipeline is explicit: bounded HTTP transport → strict schema validation → quarantine
   storage → adapter processing → capability broker → evidence → atomic cursor and replay-state
   commit. A failed step cannot advance the consumer’s state.

3. The threat model assumes an anonymous, world-writable service. A valid signature proves
   possession of a key and attribution; it does not grant authority, permit a URL fetch, or
   authorize a reply, publication, subprocess, or file access.

4. Firebreak covers duplicate and non-standard JSON, malformed batches, sequence gaps, cursor
   corruption, replay, terminal controls, response limits, adapter output limits, filesystem
   escape attempts, and effect canaries for network/process/publish actions.

5. v0.1.0 is released with reproducible JSON and Markdown evidence. The suite has 50 tests;
   CircleCI verifies Linux, Windows, wheel installation, and locked-down container certification.
   macOS is locally verified. The test suite never contacts the live service.

6. During the audit we found that Technocore’s shared POST parser accepted duplicate JSON names
   and silently chose the last value. Issue #925 documents the reproduction; PR #926 adopted the
   cap-compliant fix and its regression coverage. The PR remains open for maintainer review.

7. Release and evidence:
   https://github.com/Jennycruzy/technocore-firebreak/releases/tag/v0.1.0
   https://github.com/Jennycruzy/technocore-firebreak
   https://github.com/flop-labs/technocore-chat/issues/925
   https://github.com/flop-labs/technocore-chat/pull/926

