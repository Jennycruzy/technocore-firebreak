# Adapter protocol

Firebreak sends one UTF-8 JSON line containing an untrusted event. An adapter may answer with up to
32 JSON lines, each containing exactly `capability`, `arguments`, and `reason`. Adapter output is a
proposal, never an instruction to execute.

```json
{"capability":"network.fetch","arguments":{"url":"https://example.invalid"},"reason":"message requested a fetch"}
```

The portable runner limits time and output, uses a temporary working directory, and explicitly
passes only `PATH` and `PYTHONIOENCODING` from its parent environment. The operating system may add
its own process variables. These restrictions reduce accidental exposure; they are not an OS
security sandbox. Run only locally trusted adapter programs until an isolated Linux runner is
available. The capability broker remains the boundary for every proposal returned through this
protocol.

## Review-only drafting

The reference agent can run a separate drafter with `--drafter`. This is a different protocol
from capability proposals. Firebreak sends one JSON line with only these event fields:

```json
{"type":"draft","event":{"seq":7,"timestamp":"2026-09-28T00:00:00Z","sender":"untrusted","text":"hello","nonce":null,"signature_present":false}}
```

The drafter must return exactly one JSON object with exactly these fields:

```json
{"action":"draft","text":"Thanks for the report.","reason":"acknowledge"}
```

or:

```json
{"action":"ignore","text":null,"reason":"no response needed"}
```

Firebreak bounds time and output, rejects duplicate or unknown JSON fields, sweeps control
characters from draft text, and limits text to the same message size as the service. A draft is
written to quarantine and only its action, reason, length, hash, and quarantine path enter run
evidence. It is never sent, signed, or converted into a capability proposal. A human or separate
operator workflow must review it before any publication decision.

The portable subprocess runner removes ambient environment variables, but it is not an operating
system sandbox. Use only a locally trusted drafter or place the provider wrapper in the locked-down
container path described below. The provider wrapper must receive any model credentials explicitly;
Firebreak does not forward parent credentials or the DID seed.

## Container isolation

On a host with Docker, build and certify the reference adapter inside a stronger isolation boundary:

```console
docker build -f docker/adapter.Dockerfile -t technocore-firebreak-adapter:test .
firebreak certify --docker-image technocore-firebreak-adapter:test --output evidence
```

Firebreak starts the container with no network, a read-only root filesystem, all Linux capabilities
dropped, `no-new-privileges`, a non-root user, PID/CPU/memory limits, and a small non-executable
temporary filesystem. It mounts no host directory and forwards no credential or secret environment
variables. Docker and the host kernel remain trusted components of this boundary.
