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
