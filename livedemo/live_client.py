#!/usr/bin/env python3
"""Exercise the NockGuard stdio proxy with a local MCP server.

Run ``nockguard keygen --agent demo`` once before the demo. Set
NOCKGUARD_UPSTREAM to use another stdio MCP server that provides the demo tools.
The default server is local and needs no credentials or private paths.
"""

import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import threading


TOOLS = ("demo_status", "demo_list_notes", "demo_read_note", "demo_usage",
         "demo_sessions", "demo_delete_note", "demo_private_notes")


def stub():
    for line in sys.stdin:
        request = json.loads(line)
        if "id" not in request:
            continue
        method = request.get("method")
        if method == "initialize":
            result = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                      "serverInfo": {"name": "demo-stub", "version": "1"}}
        elif method == "tools/list":
            result = {"tools": [{"name": name, "inputSchema": {"type": "object"}}
                                for name in TOOLS]}
        elif method == "tools/call":
            result = {"content": [{"type": "text", "text": "demo response"}]}
        else:
            continue
        print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}),
              flush=True)


def main():
    script = Path(__file__).resolve()
    upstream = os.environ.get("NOCKGUARD_UPSTREAM") or shlex.join(
        [sys.executable, "-u", str(script), "--stub"])
    proc = subprocess.Popen(
        [os.environ.get("NOCKGUARD_BIN", "nockguard"), "proxy", "--upstream", upstream,
         "--agent", "demo", "--policy", str(script.with_name("policy.yaml"))],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, bufsize=1,
    )
    # Drain stderr so the proxy cannot block on a full pipe.
    def drain_stderr():
        for _ in proc.stderr:
            pass

    threading.Thread(target=drain_stderr, daemon=True).start()

    def send(obj):
        proc.stdin.write(json.dumps(obj) + "\n")
        proc.stdin.flush()

    def read_resp(want_id):
        for line in proc.stdout:
            msg = json.loads(line)
            if msg.get("id") == want_id:
                return msg
        raise RuntimeError(f"proxy exited before response {want_id}")

    def call(cid, name, args=None):
        send({"jsonrpc": "2.0", "id": cid, "method": "tools/call",
              "params": {"name": name, "arguments": args or {}}})
        response = read_resp(cid)
        verdict = "BLOCKED" if "error" in response else "ALLOWED"
        print(f"{cid}: {name}: {verdict}")
        return response

    try:
        send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": "nockguard-livedemo", "version": "1"}}})
        assert "result" in read_resp(1)
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        visible = {tool["name"] for tool in read_resp(2)["result"]["tools"]}
        assert "demo_read_note" in visible and "demo_delete_note" not in visible
        print(f"tools/list: {len(visible)} visible")

        for cid, name in enumerate(TOOLS[:5], start=3):
            assert "result" in call(cid, name)
        assert "rate limit" in call(8, "demo_read_note", {"id": "1"})["error"]["message"]
        assert "denied by policy" in call(9, "demo_delete_note", {"id": "1"})["error"]["message"]
        assert "denied by policy" in call(10, "demo_private_notes")["error"]["message"]
        fake_secret = "gh" + "p_" + "0123456789abcdef" * 2 + "0123"
        assert "input validation" in call(11, "demo_read_note", {"id": fake_secret})["error"]["message"]
        assert "input validation" in call(12, "demo_read_note", {"id": "1 OR 1=1; DROP TABLE notes--"})["error"]["message"]
    finally:
        proc.stdin.close()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.terminate()
            proc.wait(timeout=5)
    print("PASS: allowed, hidden, denied, rate-limited, and validated calls")


if __name__ == "__main__":
    if sys.argv[1:] == ["--stub"]:
        stub()
    else:
        main()
