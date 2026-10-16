# HTTP egress proxy

`nockguard egress-proxy --listen 127.0.0.1:8899 --agent coder --policy policy.yaml`
observes HTTP requests and HTTPS CONNECT destinations when a client is
configured to use it. Add `--enforce` to return 403 for a denied host;
otherwise policy denials are logged but allowed. An SSRF guard rejects
private/unsafe destinations in both modes. Source: [cmd/nockguard/main.go](../../cmd/nockguard/main.go),
`internal/proxy/forwardhttp/forwardhttp.go`.

`--listen` accepts loopback hosts by default (`127.0.0.1`, `localhost`, or
`::1`); `localhost` binds IPv4 loopback. A non-loopback or wildcard bind requires
`--allow-remote` and prints a warning. This does not add caller authentication;
restrict remote access with external network controls.

This path is an explicit forward proxy, not transparent interception. Clients
that ignore it bypass its policy. For filesystem, network and secret fences
outside MCP, see the [README coverage scope](../../README.md#coverage-scope).
