import json
import sys
import time

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
elif mode == "output-overflow":
    sys.stdout.write("x" * (65 * 1024))
elif mode == "error-overflow":
    sys.stderr.write("x" * (65 * 1024))
elif mode == "timeout":
    time.sleep(2)
