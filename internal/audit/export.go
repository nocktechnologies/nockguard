package audit

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/nocktechnologies/nockguard/internal/forward"
)

// ExportFilters records resolved, inclusive RFC3339 bounds and the Wall filters.
type ExportFilters struct {
	Since    string `json:"since,omitempty"`
	Until    string `json:"until,omitempty"`
	Severity string `json:"severity,omitempty"`
	Decision string `json:"decision,omitempty"`
	Query    string `json:"q,omitempty"`
}

// ExportRow is an original canonical audit line and its immediate chain link.
type ExportRow struct {
	Index       int    `json:"index"`
	PreviousSig string `json:"previous_sig"`
	Raw         string `json:"raw"`
}

// ExportProof is signed by the audit key after the Wall verifies the full trail.
// The receipt binds the filter, selected rows, and signed chain head, so the
// recipient needs only this file and the public key.
type ExportProof struct {
	Schema         string          `json:"schema"`
	Agent          string          `json:"agent,omitempty"`
	CapturedAt     string          `json:"captured_at,omitempty"`
	Filters        ExportFilters   `json:"filters"`
	CompleteWindow bool            `json:"complete_window"`
	Rows           []ExportRow     `json:"rows"`
	Head           json.RawMessage `json:"head"`
	ReceiptSig     string          `json:"receipt_sig"`
}

// MaxExportProofBytes is shared by the Wall writer and offline CLI reader.
const MaxExportProofBytes = 256 << 20

func (p ExportProof) receiptMessage() []byte {
	p.ReceiptSig = ""
	data, _ := json.Marshal(p)
	return append([]byte("nockguard-export-v1\n"), data...)
}

func verifyExportHead(data []byte, pub ed25519.PublicKey) (*highWaterMark, error) {
	mark, err := parseHighWaterMark(data, "(export)")
	if err != nil {
		return nil, err
	}
	canonical, _ := json.Marshal(mark)
	if !bytes.Equal(bytes.TrimSpace(data), canonical) {
		return nil, fmt.Errorf("signed chain head is not canonical JSON")
	}
	sig, err := hex.DecodeString(mark.Sig)
	if err != nil || !ed25519.Verify(pub, chainedMessage(hwmSignedBytes(mark.Count, mark.LastSig), ""), sig) {
		return nil, fmt.Errorf("signed chain head invalid")
	}
	if mark.Count < 1 {
		return nil, fmt.Errorf("empty signed chain head")
	}
	return mark, nil
}

func (f ExportFilters) completeWindow() bool {
	return f.Severity == "" && f.Decision == "" && f.Query == ""
}

func (f ExportFilters) validate() error {
	var since, until time.Time
	var err error
	if f.Since != "" {
		since, err = time.Parse(time.RFC3339, f.Since)
		if err != nil {
			return fmt.Errorf("invalid since: %w", err)
		}
	}
	if f.Until != "" {
		until, err = time.Parse(time.RFC3339, f.Until)
		if err != nil {
			return fmt.Errorf("invalid until: %w", err)
		}
	}
	if !since.IsZero() && !until.IsZero() && since.After(until) {
		return fmt.Errorf("since is after until")
	}
	return nil
}

func (f ExportFilters) match(ev Event) (bool, error) {
	ts, err := time.Parse(time.RFC3339, ev.Time)
	if err != nil {
		return false, fmt.Errorf("invalid signed timestamp %q: %w", ev.Time, err)
	}
	if f.Since != "" {
		since, _ := time.Parse(time.RFC3339, f.Since)
		if ts.Before(since) {
			return false, nil
		}
	}
	if f.Until != "" {
		until, _ := time.Parse(time.RFC3339, f.Until)
		if ts.After(until) {
			return false, nil
		}
	}
	if f.Decision != "" && ev.Decision != f.Decision {
		return false, nil
	}
	if f.Query != "" && !strings.Contains(strings.ToLower(ev.Agent+" "+ev.Tool), strings.ToLower(strings.TrimSpace(f.Query))) {
		return false, nil
	}
	if f.Severity != "" {
		sev := forward.Severity(ev.Decision, ev.Reason)
		if f.Severity == "threat" {
			return sev != forward.ThreatNone, nil
		}
		return sev == f.Severity, nil
	}
	return true, nil
}

// MakeExportProof verifies the signed checkpoint snapshot before attesting to
// its selection. A checkpoint behind the captured trail cannot prove a window.
func MakeExportProof(trail, head []byte, pub ed25519.PublicKey, priv ed25519.PrivateKey, filters ExportFilters, capturedAt time.Time) ([]byte, error) {
	if err := filters.validate(); err != nil {
		return nil, err
	}
	if capturedAt.IsZero() {
		return nil, fmt.Errorf("capture time required for offline export")
	}
	if filters.Until != "" {
		until, _ := time.Parse(time.RFC3339, filters.Until)
		if until.After(capturedAt.Truncate(time.Second).Add(-time.Nanosecond)) {
			return nil, fmt.Errorf("until exceeds safe capture bound")
		}
	}
	if len(priv) != ed25519.PrivateKeySize || !bytes.Equal(priv.Public().(ed25519.PublicKey), pub) {
		return nil, fmt.Errorf("receipt signing key does not match trail public key")
	}
	if len(head) == 0 {
		return nil, fmt.Errorf("signed checkpoint required for offline export")
	}
	mark, err := verifyExportHead(head, pub)
	if err != nil {
		return nil, err
	}
	proof := ExportProof{Schema: "nockguard-export/v2", CapturedAt: capturedAt.UTC().Format(time.RFC3339Nano), Filters: filters, CompleteWindow: filters.completeWindow(), Rows: []ExportRow{}, Head: json.RawMessage(head)}
	count, previousSig := 0, ""
	sc := bufio.NewScanner(bytes.NewReader(trail))
	sc.Buffer(make([]byte, 0, 64*1024), MaxTrailLineBytes)
	for sc.Scan() {
		count++
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			return nil, fmt.Errorf("blank audit line cannot be exported")
		}
		var ev Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			return nil, err
		}
		if count == 1 {
			proof.Agent = ev.Agent
		} else if ev.Agent != proof.Agent {
			proof.Agent = ""
		}
		match, err := filters.match(ev)
		if err != nil {
			return nil, err
		}
		if match {
			proof.Rows = append(proof.Rows, ExportRow{Index: count, PreviousSig: previousSig, Raw: sc.Text()})
		}
		previousSig = ev.Sig
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if count != mark.Count {
		return nil, fmt.Errorf("captured trail has %d rows but signed checkpoint has %d", count, mark.Count)
	}
	if _, err := VerifyEd25519Bytes(trail, head, pub); err != nil {
		return nil, err
	}
	proof.ReceiptSig = hex.EncodeToString(ed25519.Sign(priv, proof.receiptMessage()))
	data, err := json.Marshal(proof)
	if err != nil {
		return nil, err
	}
	if _, _, err := VerifyExport(data, pub, ""); err != nil {
		return nil, err
	}
	return data, nil
}

// VerifyExport authenticates the receipt and checkpoint, verifies every selected
// row's canonical bytes and chain link, and checks time-window contiguity.
func VerifyExport(data []byte, pub ed25519.PublicKey, expectedAgent string) (int, bool, error) {
	var proof ExportProof
	if err := json.Unmarshal(data, &proof); err != nil {
		return 0, false, err
	}
	canonicalProof, _ := json.Marshal(proof)
	if !bytes.Equal(bytes.TrimSpace(data), canonicalProof) {
		return 0, false, fmt.Errorf("export proof is not canonical JSON")
	}
	legacy := proof.Schema == "nockguard-export/v1"
	if (!legacy && proof.Schema != "nockguard-export/v2") || len(proof.Head) == 0 {
		return 0, false, fmt.Errorf("invalid export proof")
	}
	if err := proof.Filters.validate(); err != nil {
		return 0, false, err
	}
	receiptSig, err := hex.DecodeString(proof.ReceiptSig)
	if err != nil || !ed25519.Verify(pub, proof.receiptMessage(), receiptSig) {
		return 0, false, fmt.Errorf("export receipt signature invalid")
	}
	if legacy {
		if proof.CapturedAt != "" {
			return 0, false, fmt.Errorf("v1 proof cannot claim a capture time")
		}
	} else {
		capturedAt, err := time.Parse(time.RFC3339Nano, proof.CapturedAt)
		if err != nil {
			return 0, false, fmt.Errorf("invalid signed capture time: %w", err)
		}
		if proof.Filters.Until != "" {
			until, _ := time.Parse(time.RFC3339, proof.Filters.Until)
			if until.After(capturedAt.Truncate(time.Second).Add(-time.Nanosecond)) {
				return 0, false, fmt.Errorf("signed upper bound exceeds safe capture time")
			}
		}
	}
	if expectedAgent != "" && proof.Agent != expectedAgent {
		return 0, false, fmt.Errorf("export belongs to agent %q, expected %q", proof.Agent, expectedAgent)
	}

	mark, err := verifyExportHead(proof.Head, pub)
	if err != nil {
		return 0, false, err
	}
	if proof.CompleteWindow && !proof.Filters.completeWindow() {
		return 0, false, fmt.Errorf("selective filter cannot claim a complete window")
	}
	if proof.CompleteWindow && proof.Filters.Since == "" && proof.Filters.Until == "" && len(proof.Rows) != mark.Count {
		return 0, false, fmt.Errorf("complete trail does not reach signed chain head")
	}

	var previous Event
	for i, row := range proof.Rows {
		if row.Index < 1 || row.Index > mark.Count || (i > 0 && row.Index <= proof.Rows[i-1].Index) {
			return 0, false, fmt.Errorf("export row index invalid")
		}
		var ev Event
		if err := json.Unmarshal([]byte(row.Raw), &ev); err != nil {
			return 0, false, fmt.Errorf("row %d: %w", i, err)
		}
		canonical, err := json.Marshal(ev)
		if err != nil || !bytes.Equal([]byte(row.Raw), canonical) {
			return 0, false, fmt.Errorf("row %d is not byte-identical to its signed canonical row", i)
		}
		if expectedAgent != "" && ev.Agent != expectedAgent {
			return 0, false, fmt.Errorf("row %d belongs to agent %q", i, ev.Agent)
		}
		match, err := proof.Filters.match(ev)
		if err != nil || !match {
			return 0, false, fmt.Errorf("row %d is outside declared filters", i)
		}
		if i > 0 && row.Index == proof.Rows[i-1].Index+1 && row.PreviousSig != previous.Sig {
			return 0, false, fmt.Errorf("row %d breaks chain contiguity", i)
		}
		if proof.CompleteWindow && i > 0 && row.Index != proof.Rows[i-1].Index+1 {
			return 0, false, fmt.Errorf("time window has a missing row")
		}
		if row.Index == 1 && row.PreviousSig != "" {
			return 0, false, fmt.Errorf("genesis row has a preceding link")
		}
		if row.Index > 1 && row.PreviousSig == "" {
			return 0, false, fmt.Errorf("row %d has no preceding link", i)
		}
		sig, err := hex.DecodeString(ev.Sig)
		if err != nil {
			return 0, false, fmt.Errorf("row %d has invalid signature", i)
		}
		gotSig := ev.Sig
		ev.Sig = ""
		payload, _ := json.Marshal(ev)
		if !ed25519.Verify(pub, chainedMessage(payload, row.PreviousSig), sig) {
			return 0, false, fmt.Errorf("row %d signature invalid", i)
		}
		previous = ev
		previous.Sig = gotSig
	}
	return len(proof.Rows), proof.CompleteWindow && !legacy, nil
}
