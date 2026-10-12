#!/usr/bin/env python3
"""Exercise the README init/keygen/proxy/verify flow with filesystem tool names."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def stub(root):
    root = Path(root).resolve()
    for line in sys.stdin:
        request = json.loads(line)
        if "id" not in request:
            continue
        method = request.get("method")
        if method == "initialize":
            result = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                      "serverInfo": {"name": "filesystem-stub", "version": "1"}}
        elif method == "tools/list":
            result = {"tools": [{"name": name, "inputSchema": {"type": "object"}}
                                for name in ("read_file", "read_text_file", "write_file")]}
        elif method == "tools/call":
            params = request["params"]
            path = Path(params["arguments"]["path"]).resolve()
            if not path.is_relative_to(root):
                raise ValueError("path outside fixture directory")
            if params["name"] in ("read_file", "read_text_file"):
                result = {"content": [{"type": "text", "text": path.read_text()}]}
            elif params["name"] == "write_file":
                path.write_text(params["arguments"]["content"])
                result = {"content": [{"type": "text", "text": "written"}]}
            else:
                raise ValueError("unknown tool")
        else:
            raise ValueError("unknown method")
        print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}), flush=True)


def main():
    repo = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory(prefix="nockguard-quickstart-", dir="/tmp") as temp:
        home = Path(temp)
        project = home / "project"
        project.mkdir()
        (project / "hello.txt").write_text("NockGuard read succeeded\n")
        binary = home / "nockguard"
        subprocess.run(["go", "build", "-o", str(binary), "./cmd/nockguard"], cwd=repo, check=True)
        env = {key: value for key, value in os.environ.items()
               if not key.startswith("NOCKGUARD_AGENT_")}
        env["HOME"] = str(home)

        # These are the README's four CLI commands, with the local stub replacing
        # the npx filesystem server so CI needs no npm network access.
        subprocess.run([str(binary), "init"], env=env, check=True)
        subprocess.run([str(binary), "keygen", "--agent", "coder"], env=env, check=True)
        upstream = f"python3 scripts/quickstart-acceptance.py --stub {project}"
        control = {"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {
            "name": "write_file", "arguments": {
                "path": str(project / "control.txt"), "content": "stub write works"}}}
        subprocess.run([sys.executable, __file__, "--stub", str(project)],
                       input=json.dumps(control) + "\n", text=True,
                       capture_output=True, check=True)
        assert (project / "control.txt").read_text() == "stub write works"
        requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                        "clientInfo": {"name": "quickstart-test", "version": "1"}}},
            {"jsonrpc": "2.0", "id": 5, "method": "tools/list", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": "read_file", "arguments": {"path": str(project / "hello.txt")}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
             "params": {"name": "read_text_file", "arguments": {"path": str(project / "hello.txt")}}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "write_file", "arguments": {
                 "path": str(project / "blocked.txt"), "content": "must not exist"}}},
        ]
        result = subprocess.run(
            [str(binary), "proxy", "--upstream", upstream, "--agent", "coder"],
            input="".join(json.dumps(request) + "\n" for request in requests),
            text=True, capture_output=True, env=env, cwd=repo, timeout=20, check=True,
        )
        responses = {item["id"]: item for line in result.stdout.splitlines()
                     if (item := json.loads(line)).get("id") is not None}
        names = {tool["name"] for tool in responses[5]["result"]["tools"]}
        assert names == {"read_file", "read_text_file"}, names
        assert "NockGuard read succeeded" in json.dumps(responses[2]["result"]), responses
        assert "NockGuard read succeeded" in json.dumps(responses[4]["result"]), responses
        assert "error" in responses[3] and "denied" in responses[3]["error"]["message"], responses
        assert not (project / "blocked.txt").exists(), "blocked write reached upstream"

        verified = subprocess.run([str(binary), "verify", "--agent", "coder"],
                                  text=True, capture_output=True, env=env, check=True)
        assert "PROTECTED" in verified.stdout, verified.stdout
        trail = home / ".nockguard" / "logs" / "coder.audit.jsonl"
        decisions = {(row["tool"], row["decision"]) for row in
                     (json.loads(line) for line in trail.read_text().splitlines())}
        assert {("read_file", "allow"), ("read_text_file", "allow"),
                ("write_file", "deny")} <= decisions, decisions
        print("PASS: reads allowed; write_file denied and absent; verify PROTECTED; decisions audited")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--stub":
        stub(sys.argv[2])
    else:
        main()
