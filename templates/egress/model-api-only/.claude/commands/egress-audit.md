# Egress Audit Verify

Run:

```bash
nockguard audit verify \
  --ed25519-pub-env NOCKGUARD_AUDIT_ED25519_PUB \
  --audit .nockguard/logs/egress-audit.jsonl
```

Expected result: `OK` with the number of signed egress entries verified.
