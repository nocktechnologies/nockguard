# Changelog

All notable changes to NockGuard are documented here.

## Unreleased

### Added
- `nockguard selftest` — proof-of-block self-test (N9070). Proves the live
  enforcement path actually **blocks**: a policy-denied canary tool is denied at
  the proxy gate, and a synthetic secret-shaped argument is caught by input
  validation. Distinct from `audit verify`, which proves audit-**trail**
  integrity. Each check runs a positive control (the probe must forward *without*
  the control under test) so a block is real, not a setup error; a positive-
  control miss is `SKIP`, never `PASS`. Exit `0` = enforcement proven, `2` = a
  gap, `1` = inconclusive (including no active policy). Supports `--json`.
- `policy.LoadBytes` — parse a policy from raw YAML through the same loader and
  validation as `policy.Load`.
- Auditable references (observe mode) — extracted NockCC card IDs and GitHub PR
  references now appear in audit trail entries, linked to the specific tool calls
  that acted for them. New audit-row fields `nock_id`, `pr`, `review_id`, and
  `parent_audit_seq` are populated by declared extractors for known MCP tools
  (nockcc_nock_claim, nockcc_nock_update, nockcc_nock_get, nockcc_nock_release).
  These fields are included in the Ed25519 signature chain, so they are tamper-evident.
  Extraction is conservative: unknown tools and malformed arguments yield no fields.
  Session-scoped "current card" stamp carries the card across calls within a
  single proxy session so rows that don't name the card in their own arguments
  still link to it. Released when nockcc_nock_release is forwarded. See README
  "Auditable References" section for examples.
