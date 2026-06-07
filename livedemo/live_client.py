#!/usr/bin/env python3
"""Real stdio MCP client: drives genuine NockCC tool calls through the NockGuard
proxy. Real server, real responses, real policy decisions — isolated client."""
import json, subprocess, sys, time, os, threading

NOCKGUARD = "/tmp/nockguard"
UPSTREAM = "bash /Users/kevin/Dev/claude-remote-manager/agents/mira/scripts/mcp-nockcc.sh"
POLICY = "/Users/kevin/Dev/nockguard/livedemo/policy.yaml"

proc = subprocess.Popen(
    [NOCKGUARD, "proxy", "--upstream", UPSTREAM, "--agent", "mira", "--policy", POLICY],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    text=True, bufsize=1, env=os.environ.copy(),
)

# drain stderr so the proxy never blocks on a full pipe
def drain_err():
    for line in proc.stderr:
        pass
threading.Thread(target=drain_err, daemon=True).start()

def send(obj):
    proc.stdin.write(json.dumps(obj) + "\n"); proc.stdin.flush()

def read_resp(want_id, timeout=25):
    """Read newline JSON-RPC until we see a response with matching id."""
    end = time.time() + timeout
    while time.time() < end:
        line = proc.stdout.readline()
        if not line:
            return None
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except Exception:
            continue
        if msg.get("id") == want_id:
            return msg
    return None

def call(cid, name, args=None, label=""):
    send({"jsonrpc": "2.0", "id": cid, "method": "tools/call",
          "params": {"name": name, "arguments": args or {}}})
    r = read_resp(cid)
    if r is None:
        print(f"  [{cid}] {name:32s} {label:14s} -> (no response/timeout)")
        return
    if "error" in r:
        print(f"  [{cid}] {name:32s} {label:14s} -> BLOCKED: {r['error'].get('message','')[:60]}")
    else:
        c = r.get("result", {}).get("content", [])
        txt = (c[0].get("text","") if c else "")[:48].replace("\n"," ")
        print(f"  [{cid}] {name:32s} {label:14s} -> ALLOWED ({txt}...)")

# 1. handshake
send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
    "protocolVersion":"2024-11-05","capabilities":{},
    "clientInfo":{"name":"nockguard-livedemo","version":"1.0"}}})
init = read_resp(1)
print("initialize:", "OK" if init and "result" in init else f"FAILED ({init})")
send({"jsonrpc":"2.0","method":"notifications/initialized"})
time.sleep(0.3)

# 2. tools/list (denied tools get 'hide' decisions)
send({"jsonrpc":"2.0","id":2,"method":"tools/list"})
tl = read_resp(2)
ntools = len(tl.get("result",{}).get("tools",[])) if tl and "result" in tl else "?"
print(f"tools/list: {ntools} tools visible (denied tools hidden)\n")

print("Driving real traffic through the firewall:")
# 5 allowed real calls (consume the rate-limit budget of 5/1m)
call(3,  "nockcc_fleet_status",   {},                         "allow")
call(4,  "nockcc_nock_list",      {"limit":2},                "allow")
call(5,  "nockcc_diary_recent",   {"limit":2},                "allow")
call(6,  "nockcc_spend_summary",  {},                         "allow")
call(7,  "nockcc_sessions_active",{},                         "allow")
# 6th allowed call -> rate limit trips
call(8,  "nockcc_nock_list",      {"limit":2},                "-> ratelimit")
# destructive / boundary tools -> denied BEFORE reaching the server
call(9,  "nockcc_kill_switch_set",{"halt_new_spawns":True},   "-> deny")
call(10, "nockcc_nock_archive",   {"id":1},                   "-> deny")
call(11, "nockcc_private_list",   {},                         "-> deny")
# args carrying a secret / SQLi -> input-validation block
call(12, "nockcc_nock_get",       {"id":"ghp_aB3xK9mQ1234567890abcdefXYZ0987654321"}, "-> block(secret)")
call(13, "nockcc_nock_get",       {"id":"1 OR 1=1; DROP TABLE nocks--"},              "-> block(sqli)")

time.sleep(0.5)
proc.stdin.close()
try:
    proc.wait(timeout=5)
except Exception:
    proc.terminate()
print("\ndone.")
