package audit

// VerificationResult preserves the low-level verifier's verified-prefix count
// and reports the checkpoint from the same verification snapshot.
type VerificationResult struct {
	EntriesVerified   int
	CheckpointCount   int
	CheckpointPresent bool
}

// TrailVerdict describes whether a verified trail is complete through its
// signed checkpoint. Cryptographic verification remains the responsibility of
// Verify / VerifyEd25519 and their snapshot variants.
type TrailVerdict string

const (
	TrailProtected  TrailVerdict = "PROTECTED"
	TrailTampered   TrailVerdict = "TAMPERED"
	TrailNoRows     TrailVerdict = "NO_ROWS"
	TrailUnanchored TrailVerdict = "UNANCHORED"
)

// ClassifyTrail is the shared completeness verdict used by the CLI, sessions,
// and Wall. A clean signature walk is PROTECTED only when the trail is
// non-empty and the signed checkpoint covers every row. Counts above the trail
// length are tampering; rows beyond a valid checkpoint are unanchored.
func ClassifyTrail(result VerificationResult) TrailVerdict {
	switch {
	case result.EntriesVerified == 0:
		return TrailNoRows
	case !result.CheckpointPresent || result.CheckpointCount < result.EntriesVerified:
		return TrailUnanchored
	case result.CheckpointCount > result.EntriesVerified:
		return TrailTampered
	default:
		return TrailProtected
	}
}

func verificationResult(entries int, hwm *highWaterMark) VerificationResult {
	result := VerificationResult{EntriesVerified: entries}
	if hwm != nil {
		result.CheckpointCount = hwm.Count
		result.CheckpointPresent = true
	}
	return result
}
