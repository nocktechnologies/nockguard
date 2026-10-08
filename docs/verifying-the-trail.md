# Verify a Live Wall export offline

Run the Wall with the trail's Ed25519 public key and explicitly opt in to
receipt signing with `--proof-signing-key-env <ENV>`. With `--agent`, the Wall
uses that agent's standard `NOCKGUARD_AGENT_<AGENT>_ED25519_PUB` public key;
point the proof flag at its matching `_KEY` variable. For a global trail, use
`NOCKGUARD_AUDIT_ED25519_PUB` and `_KEY`. The private key stays on the
exporter's machine. Select a time range and click **PROOF**. The downloaded
`nockguard-wall.proof.json` contains only selected signed audit rows, each
row's preceding hash-chain link, the signed checkpoint head, and a receipt
signed by the same trail key. The Wall signs that receipt only after it has
verified the checkpointed trail and selected the rows.

```bash
nockguard-wall --agent coder \
  --proof-signing-key-env NOCKGUARD_AGENT_CODER_ED25519_KEY
```

Without the proof flag, the Wall holds only the public key and PROOF is
unavailable. An unset or mismatched explicitly selected signing key stops startup.
Proof exports hold the trail lock through the checkpoint and trail reads, so
an append waits until the snapshot finishes. Other verified exports can refuse
a snapshot crossed by an append; retry those exports.

```bash
export NOCKGUARD_AUDIT_ED25519_PUB='<public key from the trail signer>'
nockguard verify --export nockguard-wall.proof.json \
  --ed25519-pub-env NOCKGUARD_AUDIT_ED25519_PUB
```

`VERDICT: PROTECTED — complete time window` means the selected rows are byte
identical to the signed canonical audit rows and consecutive in the hash chain.
The signed receipt binds the UTC `captured_at` time, resolved time bounds, selected row indexes,
preceding links, and signed checkpoint head. It attests that the Wall checked
the full trail for matching rows and timestamp order. Changing or deleting a
selected row, or narrowing the declared range, fails verification. An empty
window is a signed zero-row attestation. The Wall holds a shared trail lock
while capturing the checkpoint and rows. Because audit timestamps have
one-second resolution, it signs the earlier of the requested `until` and the
last fully elapsed second before `captured_at` as the effective upper bound.
If no upper bound was requested, it uses that safe bound. The offline verifier
rejects a receipt whose upper bound exceeds the safe bound derived from its
signed `captured_at` time.
The verdict prints the effective bound and covers the checkpointed snapshot;
rows appended after that snapshot require a new proof.
Version 2 receipts carry `captured_at`. Older version 1 receipts still verify
the authenticity of their selected rows, but receive only an integrity verdict
because they do not sign a separate capture time.

Severity, decision, and text filters deliberately produce `integrity verified;
not a complete window`: their selected rows are genuine, but those filters
skip chain entries. The CSV and older `?format=json` downloads retain their
display-oriented `verification` labels; use **PROOF** when handing evidence to
someone who has only the export and public key. HMAC and unsigned trails cannot
produce a public-key offline proof.

The auditor timestamps signed rows after taking the exclusive append lock, so
concurrent writers stamp rows in append order. It uses the host clock. If a clock regression makes
the matching rows noncontiguous in the chain, the Wall refuses a complete
time-window proof. The recipient authenticates the full-trail selection
through the receipt rather than inspecting omitted rows. Keep the export
signing key protected: anyone holding it can sign false receipts, just as they
can sign false audit rows.
As with ordinary trail verification, rolling both the trail and signed head
back to an earlier genuine state needs an external anchor to detect.
