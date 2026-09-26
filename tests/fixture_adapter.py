import json
import sys

mode = sys.argv[1]
_request = sys.stdin.readline()
if mode == "malformed":
    print("not-json")
elif mode == "unknown-field":
    print(json.dumps({"capability": "network.fetch", "arguments": {}, "reason": "x", "execute": True}))
elif mode == "many":
    proposal = {"capability": "network.fetch", "arguments": {}, "reason": "x"}
    for _ in range(33):
        print(json.dumps(proposal))
elif mode == "fail":
    raise SystemExit(7)
