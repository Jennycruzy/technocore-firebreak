import json
import os
import sys
import time

request = json.loads(sys.stdin.readline())
mode = sys.argv[1]
event = request["event"]

if mode == "draft":
    print(
        json.dumps(
            {
                "action": "draft",
                "text": "Thanks for the report.",
                "reason": "acknowledge",
            }
        )
    )
elif mode == "ignore":
    print(
        json.dumps({"action": "ignore", "text": None, "reason": "no response needed"})
    )
elif mode == "projection":
    print(
        json.dumps(
            {"action": "draft", "text": ",".join(sorted(event)), "reason": "fields"}
        )
    )
elif mode == "echo":
    print(json.dumps({"action": "draft", "text": event["text"], "reason": "echo"}))
elif mode == "secret":
    print(
        json.dumps(
            {
                "action": "draft",
                "text": "FIREBREAK_PARENT_SECRET" in os.environ,
                "reason": "secret",
            }
        )
    )
elif mode == "malformed":
    print("not-json")
elif mode == "unknown-field":
    print(json.dumps({"action": "draft", "text": "hello", "reason": "x", "send": True}))
elif mode == "duplicate-key":
    print('{"action":"draft","action":"ignore","text":null,"reason":"x"}')
elif mode == "many":
    print("{}\n{}")
elif mode == "timeout":
    time.sleep(2)
elif mode == "output-overflow":
    sys.stdout.write("x" * (65 * 1024))
elif mode == "fail":
    raise SystemExit(7)
