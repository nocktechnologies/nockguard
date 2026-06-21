package forwardhttp

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
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
		// DialContext routes every plain-HTTP forward dial through the SSRF guard,
		// which resolves the host and connects to the VALIDATED IP — never the raw
		// host string RoundTrip would otherwise re-resolve (closes the
		// check-vs-dial divergence and the DNS-rebinding window).
		client: &http.Transport{Proxy: nil, DialContext: guardedDial},
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

	// Dial through the SSRF guard so the tunnel connects to the VALIDATED IP, not
	// the raw r.Host (which the up-front isBlockedHost check normalized but did not
	// dial). This closes the check-vs-dial divergence on CONNECT.
	targetConn, err := guardedDial(r.Context(), "tcp", r.Host)
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

// --- SSRF guard (N8182 finding #3, hardened per N8269) ---
//
// The old guard string-matched net.ParseIP(host) and let the OS re-resolve the
// RAW host at dial time. That failed OPEN on encoded IPv4 (2130706433 decimal,
// 0x7f000001 hex, 127.1 short), the unspecified address (0.0.0.0 / ::), and any
// check-vs-dial divergence (the bytes checked were not the bytes dialed). The
// guard now normalizes every numeric IPv4 encoding, classifies the concrete IP,
// and — via guardedDial — connects to the VALIDATED IP, which also closes the
// DNS-rebinding window.

// cloud-metadata IPs that are not otherwise caught by IsLinkLocal/IsPrivate
// (Alibaba's 100.100.100.200 is CGNAT, AWS' v6 IMDS is a ULA).
var blockedExactIPs = func() []net.IP {
	out := make([]net.IP, 0, 3)
	for _, s := range []string{"169.254.169.254", "100.100.100.200", "fd00:ec2::254"} {
		if ip := net.ParseIP(s); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}()

var cgnatNet = func() *net.IPNet {
	_, n, _ := net.ParseCIDR("100.64.0.0/10") // RFC 6598 carrier-grade NAT
	return n
}()

// classifyIP reports whether a concrete IP is an SSRF-unsafe target.
func classifyIP(ip net.IP) bool {
	if ip == nil {
		return true // fail closed
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsPrivate() {
		return true
	}
	if cgnatNet != nil && cgnatNet.Contains(ip) {
		return true
	}
	for _, b := range blockedExactIPs {
		if b.Equal(ip) {
			return true
		}
	}
	return false
}

// parseNumericIPv4 normalizes the non-canonical IPv4 encodings that net.ParseIP
// rejects but the libc resolver (inet_aton) accepts: decimal (2130706433), hex
// (0x7f000001), octal (0177.0.0.1) and short forms (127.1, 0). Returns nil when
// host is not a numeric IPv4 in any of these encodings (i.e. it is a real name).
func parseNumericIPv4(host string) net.IP {
	parts := strings.Split(host, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return nil
	}
	vals := make([]uint64, len(parts))
	for i, p := range parts {
		if p == "" {
			return nil
		}
		v, err := strconv.ParseUint(p, 0, 64) // base 0: 0x->hex, 0->octal, else decimal
		if err != nil {
			return nil
		}
		vals[i] = v
	}
	var addr uint32
	switch len(parts) {
	case 1:
		if vals[0] > 0xffffffff {
			return nil
		}
		addr = uint32(vals[0])
	case 2: // a.b -> a . (b as low 24 bits)
		if vals[0] > 0xff || vals[1] > 0xffffff {
			return nil
		}
		addr = uint32(vals[0])<<24 | uint32(vals[1])
	case 3: // a.b.c -> a . b . (c as low 16 bits)
		if vals[0] > 0xff || vals[1] > 0xff || vals[2] > 0xffff {
			return nil
		}
		addr = uint32(vals[0])<<24 | uint32(vals[1])<<16 | uint32(vals[2])
	case 4:
		for _, v := range vals {
			if v > 0xff {
				return nil
			}
		}
		addr = uint32(vals[0])<<24 | uint32(vals[1])<<16 | uint32(vals[2])<<8 | uint32(vals[3])
	}
	return net.IPv4(byte(addr>>24), byte(addr>>16), byte(addr>>8), byte(addr))
}

// classifyHostLiteral does the cheap, no-DNS classification: literal IPs, every
// numeric IPv4 encoding, and the well-known blocked hostnames. isLiteral=false
// means host is a name needing DNS — guardedDial validates it at dial time.
func classifyHostLiteral(host string) (blocked, isLiteral bool) {
	host = normalizeHost(host)
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") ||
		host == "metadata.google.internal" {
		return true, true
	}
	if ip := net.ParseIP(host); ip != nil {
		return classifyIP(ip), true
	}
	if ip := parseNumericIPv4(host); ip != nil {
		return classifyIP(ip), true
	}
	return false, false // a real name — defer to dial-time DNS validation
}

// isBlockedHost is the up-front 403 check (and the guard's test surface). It
// catches every literal/encoded form instantly; hostnames that need DNS pass
// here and are validated authoritatively at dial time in guardedDial.
func isBlockedHost(host string) bool {
	blocked, _ := classifyHostLiteral(host)
	return blocked
}

// guardedDial resolves addr's host and connects to the VALIDATED IP (never the
// raw string). Literal/encoded forms are classified without DNS; names are
// resolved and EVERY resolved IP must pass (a name with one internal A record is
// blocked). Used as the Transport DialContext (plain HTTP) and by CONNECT.
func guardedDial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("blocked: SSRF guard (bad address %q)", addr)
	}
	host = normalizeHost(host)
	dialer := &net.Dialer{Timeout: 30 * time.Second}

	if blocked, isLiteral := classifyHostLiteral(host); isLiteral {
		if blocked {
			return nil, fmt.Errorf("blocked: SSRF guard")
		}
		ip := net.ParseIP(host)
		if ip == nil {
			ip = parseNumericIPv4(host)
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("blocked: SSRF guard (unresolved %q)", host)
	}
	var safe net.IP
	for _, ip := range ips {
		if classifyIP(ip) {
			return nil, fmt.Errorf("blocked: SSRF guard (resolved to internal address)")
		}
		if safe == nil {
			safe = ip
		}
	}
	return dialer.DialContext(ctx, network, net.JoinHostPort(safe.String(), port))
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
