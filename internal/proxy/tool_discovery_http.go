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
func (l *HTTPListener) forwardToolList(w http.ResponseWriter, resp *http.Response, request []byte, id json.RawMessage, seq uint64) {
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
		if err := l.streamToolList(w, resp.Body, request, seq); err != nil {
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

func (l *HTTPListener) streamToolList(w http.ResponseWriter, body io.Reader, request []byte, seq uint64) error {
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
		if payload := []byte(strings.Join(data, "\n")); len(payload) > 0 {
			var msg jsonrpc.Message
			if json.Unmarshal(payload, &msg) != nil {
				return fmt.Errorf("invalid SSE JSON-RPC message")
			}
			if msg.Method == "" && jsonRPCIDMatches(request, msg.ID) {
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
		if _, err := io.WriteString(w, strings.Join(lines, "\n")+"\n\n"); err != nil {
			return err
		}
		_ = http.NewResponseController(w).Flush()
		lines, data, size = nil, nil, 0
	}
	return scanner.Err()
}
