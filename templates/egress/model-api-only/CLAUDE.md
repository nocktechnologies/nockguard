# Model API Only Egress Profile

This agent session is expected to send HTTP and HTTPS traffic through
NockGuard's egress proxy (observe-only unless started with `--enforce`).

Use the configured `HTTP_PROXY` and `HTTPS_PROXY` values for outbound model/API
requests. The proxy records every destination host in the signed audit chain.
In observe mode a denied host is warning-only (`WOULD-BLOCK`) and the request
still goes through. With `--enforce` a denied host gets a 403. Private and
unsafe destinations are always refused by the SSRF guard.
