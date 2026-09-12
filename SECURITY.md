# Security policy

NockGuard is a security control. A bug that lets a denied tool call through, lets a verifier forge or hide an audit entry, or leaks a secret into the trail is a vulnerability, not a defect.

## Reporting

Use GitHub's private reporting: **Security → Report a vulnerability** on this repository (it opens a private advisory only maintainers can see). Include:

- the version or commit,
- a minimal policy file and the MCP message(s) that reproduce it,
- what the firewall did and what it should have done.

You will get an acknowledgement within 3 business days. Please give us a reasonable window to ship a fix before publishing details; we will credit you in the release notes unless you ask otherwise.

Do not open a public GitHub issue for a suspected vulnerability.

## Scope

In scope: `nockguard proxy`, `mcp-http`, `mcp-listen`, `egress-proxy`, the policy engine, input validation, rate limiting and spend caps, the audit trail and its HMAC / Ed25519 signing, `verify`, `selftest`, and `nockguard-wall`.

Out of scope by design (see the README's "Coverage scope"): direct HTTP calls an agent makes that never pass through the proxy, and MCP servers not wired through `nockguard proxy`.

## Supported versions

The latest tagged release and `main`.
