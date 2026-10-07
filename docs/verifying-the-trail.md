# Verify a Live Wall export offline

Run the Wall with the trail's Ed25519 public key **and signing key**, supplied
through environment variables. With `--agent`, the Wall uses that agent's
standard `NOCKGUARD_AGENT_<AGENT>_ED25519_PUB` and `_KEY` variables; for a
global trail, it uses `NOCKGUARD_AUDIT_ED25519_PUB` and `_KEY`. The key stays on
the exporter's machine. Select a time range and click **PROOF**. The downloaded
`nockguard-wall.proof.json` contains only selected signed audit rows, each
row's preceding hash-chain link, the signed checkpoint head, and a receipt
signed by the same trail key. The Wall signs that receipt only after it has
verified the checkpointed trail and selected the rows.
An unmatched default signing key disables PROOF with a Wall warning; an
explicitly selected mismatched signing key stops startup.
If an append lands between the checkpoint and trail reads, the Wall refuses
that snapshot; retry the export.

```bash
export NOCKGUARD_AUDIT_ED25519_PUB='<public key from the trail signer>'
nockguard verify --export nockguard-wall.proof.json \
  --ed25519-pub-env NOCKGUARD_AUDIT_ED25519_PUB
```

`VERDICT: PROTECTED — complete time window` means the selected rows are byte
identical to the signed canonical audit rows and consecutive in the hash chain.
The signed receipt binds the resolved time bounds, selected row indexes,
preceding links, and signed checkpoint head. It attests that the Wall checked
the full trail for matching rows and timestamp order. Changing or deleting a
selected row, or narrowing the declared range, fails verification. An empty
window is a signed zero-row attestation.
With no filters, the same check reports `complete trail`.

Severity, decision, and text filters deliberately produce `integrity verified;
not a complete window`: their selected rows are genuine, but those filters
skip chain entries. The CSV and older `?format=json` downloads retain their
display-oriented `verification` labels; use **PROOF** when handing evidence to
someone who has only the export and public key. HMAC and unsigned trails cannot
produce a public-key offline proof.

The auditor timestamps rows with the host clock. If a clock regression makes
the matching rows noncontiguous in the chain, the Wall refuses a complete
time-window proof. The recipient authenticates the full-trail selection
through the receipt rather than inspecting omitted rows. Keep the export
signing key protected: anyone holding it can sign false receipts, just as they
can sign false audit rows.
As with ordinary trail verification, rolling both the trail and signed head
back to an earlier genuine state needs an external anchor to detect.
