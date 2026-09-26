package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/nocktechnologies/nockguard/internal/jsonrpc"
	"github.com/nocktechnologies/nockguard/internal/proxy/forwardhttp"
)

// Discovery must be inspected before delivery. Bound each JSON response or SSE
// event, while keeping an SSE stream incremental and preserving its event IDs.
// resolveAudit resolves the audit sequence exactly once (the caller guards it
// with sync.Once); the SSE path calls it as soon as the matching discovery
// event has been filtered and flushed so a stream the upstream keeps open
// afterwards never blocks a later request's audit. The JSON path leaves
// resolveAudit to the caller, unchanged from before.
func (l *HTTPListener) forwardToolList(w http.ResponseWriter, resp *http.Response, request []byte, id json.RawMessage, seq uint64, resolveAudit func()) {
	forwardhttp.RemoveHopByHopHeaders(resp.Header)
	for _, key := range []string{"Content-Length", "ETag", "Content-MD5", "Digest"} {
		resp.Header.Del(key) // these describe the unfiltered representation
	}
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	invalid := func() []byte { return jsonrpc.ErrorResponse(id, -32603, "nockguard: invalid tools/list response") }
	ct, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if encoding := resp.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		w.Header().Del("Content-Encoding")
		ct = "" // the transport normally handles gzip; refuse other encodings
	}
	if ct == "text/event-stream" {
		w.WriteHeader(resp.StatusCode)
		if err := l.streamToolList(w, resp.Body, request, seq, resolveAudit); err != nil {
			l.logger.Printf("UPSTREAM-STREAM-ERROR agent=%s: tools/list stream failed", l.gate.agent)
			_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", invalid())
			_ = http.NewResponseController(w).Flush()
		}
		return
	}
	var out []byte
	status := resp.StatusCode
	if ct == "application/json" {
		body, err := io.ReadAll(io.LimitReader(resp.Body, httpListenerBodyCap+1))
		if err == nil && len(body) <= httpListenerBodyCap {
			var msg jsonrpc.Message
			if json.Unmarshal(body, &msg) == nil && msg.Method == "" && jsonRPCIDMatches(request, msg.ID) {
				out = l.gate.filterToolListResponse(body, seq)
			}
		}
	}
	if out == nil {
		out = invalid()
		status = http.StatusOK
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(out)
}

// streamToolList relays an SSE tools/list response event by event, filtering
// only the event that matches the forwarded request. resolveAudit is called
// right after that matching event is filtered, written and flushed — not at
// EOF — so an upstream that keeps the stream open past discovery (a
// keep-alive or unrelated follow-on traffic) never delays the audit sequence
// this response reserved. resolveAudit is a no-op past the first call.
func (l *HTTPListener) streamToolList(w http.ResponseWriter, body io.Reader, request []byte, seq uint64, resolveAudit func()) error {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 4096), httpListenerBodyCap+1)
	// SSE accepts LF, CRLF and bare CR. Consume CR immediately so an upstream
	// flushing a bare-CR event need not send the next event to release this one.
	skipLF := false
	scanner.Split(func(data []byte, eof bool) (int, []byte, error) {
		if len(data) == 0 {
			return 0, nil, nil
		}
		start := 0
		if skipLF {
			skipLF = false
			if data[0] == '\n' {
				start = 1
			}
		}
		if i := bytes.IndexAny(data[start:], "\r\n"); i >= 0 {
			i += start
			advance := i + 1
			if data[i] == '\r' {
				if advance < len(data) && data[advance] == '\n' {
					advance++
				} else if advance == len(data) {
					skipLF = true
				}
			}
			return advance, data[start:i], nil
		}
		if eof {
			return len(data), nil, nil
		} // discard unterminated event
		return start, nil, nil
	})
	var lines, data []string
	size := 0
	first := true
	// answered tracks whether a response matching request's id has already
	// been delivered on this stream. JSON-RPC allows exactly one response per
	// id: a well-behaved upstream never sends a second one, but a misbehaving
	// one must not get a second bite at tools/list filtering. Handling a
	// repeat match would either forward the raw, unfiltered second result past
	// policy (a leak) or re-queue its hide audits onto a seq the audit queue
	// has already flushed past (silent audit loss) — so any later matching
	// response is dropped outright instead.
	answered := false
	for scanner.Scan() {
		line := scanner.Text()
		if first {
			line = strings.TrimPrefix(line, "\ufeff")
			first = false
		}
		size += len(line) + 1
		if size > httpListenerBodyCap {
			return fmt.Errorf("SSE event exceeds discovery limit")
		}
		if line != "" {
			lines = append(lines, line)
			field, value, _ := strings.Cut(line, ":")
			if field == "data" {
				data = append(data, strings.TrimPrefix(value, " "))
			}
			continue
		}
		// An empty data buffer dispatches no event under the SSE specification.
		matched := false
		drop := false
		if payload := []byte(strings.Join(data, "\n")); len(payload) > 0 {
			var msg jsonrpc.Message
			if json.Unmarshal(payload, &msg) != nil {
				return fmt.Errorf("invalid SSE JSON-RPC message")
			}
			if msg.Method == "" && jsonRPCIDMatches(request, msg.ID) {
				if answered {
					drop = true
				} else {
					matched = true
					answered = true
					filtered := l.gate.filterToolListResponse(payload, seq)
					kept := make([]string, 0, len(lines))
					for _, raw := range lines {
						field, _, _ := strings.Cut(raw, ":")
						if field != "data" {
							kept = append(kept, raw)
						}
					}
					lines = append(kept, "data: "+string(filtered))
				}
			}
		}
		if drop {
			// Never forward the repeat and never re-run it through
			// filterToolListResponse: that would either leak the unfiltered
			// duplicate to the connector or append hide audits onto a seq the
			// audit queue has already flushed past.
			l.logger.Printf("UPSTREAM-DUPLICATE-RESPONSE agent=%s: dropped repeated tools/list result", l.gate.agent)
			lines, data, size = nil, nil, 0
			continue
		}
		if _, err := io.WriteString(w, strings.Join(lines, "\n")+"\n\n"); err != nil {
			return err
		}
		_ = http.NewResponseController(w).Flush()
		if matched {
			// The discovery result has been filtered, written and flushed to the
			// connector — resolve the audit sequence now rather than waiting for
			// this stream to end, so an upstream that keeps it open (keep-alive,
			// unrelated later events) cannot stall every later request's audit.
			resolveAudit()
		}
		lines, data, size = nil, nil, 0
	}
	return scanner.Err()
}
