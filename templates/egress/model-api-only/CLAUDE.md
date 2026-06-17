# Model API Only Egress Profile

This agent session is expected to send HTTP and HTTPS traffic through
NockGuard's observe-only egress proxy.

Use the configured `HTTP_PROXY` and `HTTPS_PROXY` values for outbound model/API
requests. The proxy records every destination host in the signed audit chain.
During Phase 1, a denied host is warning-only and must not be interpreted as a
blocked request.
