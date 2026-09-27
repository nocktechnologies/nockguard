package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/nocktechnologies/nockguard/internal/audit"
	"github.com/nocktechnologies/nockguard/internal/extract"
	"github.com/nocktechnologies/nockguard/internal/jsonrpc"
	"github.com/nocktechnologies/nockguard/internal/proxy/forwardhttp"
)

const auditBeforeForwardError = "nockguard: audit unavailable; request was not forwarded"
const auditAfterForwardError = "nockguard: audit failed after forwarding; tool may have executed; do not retry automatically"
const unverifiedToolResponseError = "nockguard: upstream response could not be verified; tool may have executed; do not retry automatically"

func (p *StdioProxy) recordAudit(ev audit.Event) {
	var err error
	if p.requiredAudit {
		err = p.auditor.RecordRequired(ev)
	} else {
		err = p.auditor.Record(ev)
	}
	if err != nil {
		p.logger.Printf("AUDIT-ERROR agent=%s tool=%s: %v", p.agent, ev.Tool, err)
	}
}

func (l *HTTPListener) forwardRequiredToolSSE(w http.ResponseWriter, resp *http.Response, request []byte, seq uint64, tool string, refs *extract.References, resolved *bool) {
	// Bound the wait for the matching result, including heartbeats and unrelated
	// events. Required listeners serialize requests, so an endless stream must
	// not keep this gate busy forever. Close unblocks a pending body read.
	timer := time.AfterFunc(l.streamResponseTimeout, func() { _ = resp.Body.Close() })
	defer timer.Stop()
	forwardhttp.RemoveHopByHopHeaders(resp.Header)
	for _, key := range []string{"Content-Length", "ETag", "Content-MD5", "Digest"} {
		resp.Header.Del(key)
	}
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	err := l.streamMCPResponse(w, resp.Body, request, func(payload []byte) ([]byte, error) {
		l.commitToolResult(request, payload, seq, tool, refs)
		*resolved = true
		l.gate.resolveAudit(seq)
		if err := l.auditError(); err != nil {
			return nil, err
		}
		return payload, nil
	}, func() {})
	if err != nil {
		*resolved = true
		l.gate.resolveAudit(seq)
		var msg jsonrpc.Message
		_ = json.Unmarshal(request, &msg)
		reason := unverifiedToolResponseError
		if l.auditError() != nil {
			reason = auditAfterForwardError
		}
		_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", jsonrpc.ErrorResponse(msg.ID, -32603, reason))
		_ = http.NewResponseController(w).Flush()
	}
}

func (l *HTTPListener) auditError() error {
	if !l.requiredAudit {
		return nil
	}
	return l.gate.auditor.RequiredError()
}

func (l *HTTPListener) writeAuditError(w http.ResponseWriter, request []byte, forwarded bool) {
	reason := auditBeforeForwardError
	if forwarded {
		reason = auditAfterForwardError
	}
	l.writeRequestError(w, request, reason)
}

func (l *HTTPListener) writeRequestError(w http.ResponseWriter, request []byte, reason string) {
	var msg jsonrpc.Message
	_ = json.Unmarshal(request, &msg)
	// An HTTP error gives notifications a failure signal without inventing a
	// JSON-RPC response ID. Requests receive the explicit non-retryable outcome.
	if msg.ID == nil {
		http.Error(w, reason, http.StatusInternalServerError)
		return
	}
	l.writeJSONRPCError(w, msg.ID, -32603, reason)
}

// validToolResponse checks the JSON-RPC response envelope, separately from
// whether its result is successful enough to commit card state. Matching
// JSON-RPC errors must still reach the caller, but malformed envelopes must not.
func validToolResponse(request, response []byte) bool {
	var members map[string]json.RawMessage
	if json.Unmarshal(response, &members) != nil {
		return false
	}
	var version string
	if json.Unmarshal(members["jsonrpc"], &version) != nil || version != "2.0" || !jsonRPCIDMatches(request, members["id"]) {
		return false
	}
	if _, hasMethod := members["method"]; hasMethod {
		return false
	}
	_, hasResult := members["result"]
	errRaw, hasError := members["error"]
	if hasResult == hasError {
		return false // exactly one of result and error is required
	}
	if hasError {
		var fields map[string]json.RawMessage
		if json.Unmarshal(errRaw, &fields) != nil {
			return false
		}
		var code *int
		var message *string
		return json.Unmarshal(fields["code"], &code) == nil && code != nil &&
			json.Unmarshal(fields["message"], &message) == nil && message != nil
	}
	return true
}

// commitToolResult preserves the existing state rule: only a matching genuine
// JSON-RPC success can change the session's current card. Audit allow rows are
// policy decisions, not proof that an upstream action succeeded.
func (l *HTTPListener) commitToolResult(request, response []byte, seq uint64, tool string, refs *extract.References) {
	var msg jsonrpc.Message
	var members map[string]json.RawMessage
	if json.Unmarshal(response, &msg) != nil || json.Unmarshal(response, &members) != nil {
		return
	}
	_, hasError := members["error"]
	resultRaw, hasResult := members["result"]
	if msg.JSONRPC != "2.0" || msg.Method != "" || hasError || !hasResult || !jsonRPCIDMatches(request, msg.ID) {
		return
	}
	var result map[string]interface{}
	if json.Unmarshal(resultRaw, &result) == nil {
		if failed, ok := result["isError"].(bool); ok && failed {
			return
		}
	}
	l.gate.updateCardState(seq, tool, refs)
}
