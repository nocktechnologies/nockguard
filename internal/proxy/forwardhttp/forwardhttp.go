package forwardhttp

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/nocktechnologies/nockguard/internal/audit"
	"github.com/nocktechnologies/nockguard/internal/policy"
)

type Proxy struct {
	listen  string
	agent   string
	engine  *policy.Engine
	auditor *audit.Auditor
	logger  *log.Logger
	client  *http.Transport
}

func New(listen, agent string, engine *policy.Engine, auditor *audit.Auditor, logger *log.Logger) *Proxy {
	return &Proxy{
		listen:  listen,
		agent:   agent,
		engine:  engine,
		auditor: auditor,
		logger:  logger,
		client:  &http.Transport{Proxy: nil},
	}
}

func (p *Proxy) Run(ctx context.Context) error {
	srv := &http.Server{
		Addr:              p.listen,
		Handler:           p,
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return err
		}
		err := <-errCh
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handleHTTP(w, r)
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	host := destinationHost(r.Host)
	if host == "" && r.URL != nil {
		host = destinationHost(r.URL.Host)
	}
	p.observe(host)
	if isBlockedHost(host) {
		http.Error(w, "blocked: SSRF guard", http.StatusForbidden)
		return
	}

	out := r.Clone(r.Context())
	out.RequestURI = ""
	if out.URL.Scheme == "" {
		out.URL.Scheme = "http"
	}
	if out.URL.Host == "" {
		out.URL.Host = r.Host
	}
	removeHopByHopHeaders(out.Header)

	resp, err := p.client.RoundTrip(out)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	removeHopByHopHeaders(resp.Header)
	for k, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := destinationHost(r.Host)
	p.observe(host)
	if isBlockedHost(host) {
		http.Error(w, "blocked: SSRF guard", http.StatusForbidden)
		return
	}

	targetConn, err := net.DialTimeout("tcp", r.Host, 30*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = targetConn.Close()
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, rw, err := hj.Hijack()
	if err != nil {
		_ = targetConn.Close()
		return
	}
	if _, err := io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = clientConn.Close()
		_ = targetConn.Close()
		return
	}
	go tunnel(clientConn, targetConn)
	go tunnel(targetConn, flushReaderConn{Reader: rw.Reader, Conn: clientConn})
}

func (p *Proxy) observe(host string) {
	dec := p.engine.Evaluate(p.agent, host)
	decision := "deny"
	if dec.Verdict == policy.Allow {
		decision = "allow"
	}
	if p.auditor.Enabled() {
		if err := p.auditor.Record(audit.Event{Agent: p.agent, Tool: "egress:" + host, Decision: decision, Reason: dec.Reason}); err != nil {
			p.logger.Printf("AUDIT-ERROR agent=%s tool=egress:%s: %v", p.agent, host, err)
		}
	}
	if decision == "deny" {
		p.logger.Printf("WARN WOULD-BLOCK (observe-only) agent=%s host=%s reason=%q", p.agent, host, dec.Reason)
		return
	}
	p.logger.Printf("ALLOW agent=%s host=%s reason=%q", p.agent, host, dec.Reason)
}

func tunnel(dst io.WriteCloser, src io.ReadCloser) {
	_, _ = io.Copy(dst, src)
	_ = dst.Close()
	_ = src.Close()
}

type flushReaderConn struct {
	*bufio.Reader
	net.Conn
}

func (c flushReaderConn) Read(p []byte) (int, error) {
	if c.Reader != nil && c.Reader.Buffered() > 0 {
		return c.Reader.Read(p)
	}
	return c.Conn.Read(p)
}

func destinationHost(authority string) string {
	authority = strings.TrimSpace(authority)
	if authority == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(authority); err == nil {
		return normalizeHost(h)
	}
	return normalizeHost(authority)
}

func normalizeHost(host string) string {
	return strings.ToLower(strings.Trim(host, "[]"))
}

func removeHopByHopHeaders(h http.Header) {
	for _, k := range []string{
		"Connection",
		"Proxy-Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		h.Del(k)
	}
}

// isBlockedHost returns true if the host (IP or well-known name) refers to a
// loopback, link-local, or cloud-metadata address. These are hard-blocked by
// the SSRF guard regardless of policy or observe mode: an agent should never be
// able to reach the host's own services or cloud-provider metadata endpoints
// through the egress proxy (N8182 finding #3).
func isBlockedHost(host string) bool {
	if strings.ToLower(host) == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

func ValidateConfig(listen, agent string, engine *policy.Engine) error {
	if listen == "" {
		return fmt.Errorf("--listen is required")
	}
	if agent == "" {
		return fmt.Errorf("--agent is required")
	}
	if engine == nil {
		return fmt.Errorf("policy engine is required")
	}
	return nil
}
