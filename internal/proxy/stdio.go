package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/nocktechnologies/nockguard/internal/approval"
	"github.com/nocktechnologies/nockguard/internal/audit"
	"github.com/nocktechnologies/nockguard/internal/forward"
	"github.com/nocktechnologies/nockguard/internal/jsonrpc"
	"github.com/nocktechnologies/nockguard/internal/policy"
	"github.com/nocktechnologies/nockguard/internal/ratelimit"
	"github.com/nocktechnologies/nockguard/internal/trust"
	"github.com/nocktechnologies/nockguard/internal/validate"
)

type StdioProxy struct {
	upstream  []string
	agent     string
	engine    *policy.Engine
	validator *validate.Validator
	limiter   *ratelimit.Limiter
	auditor   *audit.Auditor
	forwarder *forward.Forwarder
	trust     *trust.Accumulator
	approver  approval.Approver // Phase 5; nil = no approval gate (Phase 1-4 behavior)
	logger    *log.Logger

	// agentOut is the agent-facing write channel for rejections/errors. nil means
	// os.Stdout (production). Probe overrides it with a buffer so the `selftest`
	// command can drive a message through the real gate without reject bytes
	// leaking onto os.Stdout.
	agentOut io.Writer

	// agentMu serializes ALL writes to the agent-facing channel (os.Stdout).
	// agentToUpstream (error/reject responses) and upstreamToAgent (upstream
	// traffic) run in separate goroutines and both write there; without this lock
	// their JSON-RPC lines could interleave and corrupt the stream.
	agentMu sync.Mutex
}

// writeAgentLine writes one newline-terminated line to the agent-facing channel
// under agentMu, so the two proxy goroutines never interleave output on it. w is
// the agent writer (os.Stdout in production; injectable for tests).
func (p *StdioProxy) writeAgentLine(w io.Writer, line []byte) error {
	p.agentMu.Lock()
	defer p.agentMu.Unlock()
	_, err := fmt.Fprintf(w, "%s\n", line)
	return err
}

// agentWriter returns the agent-facing write channel, defaulting to os.Stdout
// when unset (production). Probe swaps in a buffer so rejection bytes are
// captured instead of printed.
func (p *StdioProxy) agentWriter() io.Writer {
	if p.agentOut != nil {
		return p.agentOut
	}
	return os.Stdout
}

// Probe drives a single JSON-RPC message through the SAME enforcement path live
// agent traffic takes — the agentToUpstream gate: policy evaluation plus Phase 2
// input validation — and reports whether the message was FORWARDED to the
// upstream. It is the seam the `nockguard selftest` command uses to prove the
// wired firewall actually blocks a denied call or a secret-bearing argument: the
// bytes flow through the real gate, not a mock. Agent-facing rejections are
// captured in reply rather than written to os.Stdout. forwarded is true iff the
// message cleared every gate and reached the upstream writer.
//
// Probe swaps agentOut without holding agentMu, so it must NOT run concurrently
// with Run() (the selftest builds single-use proxies with no live goroutines).
func (p *StdioProxy) Probe(line []byte) (forwarded bool, reply []byte, err error) {
	var upstream, agentReply bytes.Buffer
	prev := p.agentOut
	p.agentOut = &agentReply
	defer func() { p.agentOut = prev }()
	// agentToUpstream reads with a bufio.Scanner, which yields the final line
	// even without a trailing newline — so the raw bytes need no terminator.
	perr := p.agentToUpstream(bytes.NewReader(line), &upstream, &sync.Map{})
	return upstream.Len() > 0, agentReply.Bytes(), perr
}

// WithApprover wires the Phase 5 interactive approval gate. nil (the default)
// disables the gate entirely, preserving Phase 1-4 behavior. Returns the proxy
// for chaining off NewStdioProxy.
func (p *StdioProxy) WithApprover(a approval.Approver) *StdioProxy {
	p.approver = a
	return p
}

func (p *StdioProxy) WithTrust(t *trust.Accumulator) *StdioProxy {
	p.trust = t
	if p.limiter != nil && t.Enabled() {
		p.limiter.WithMaxCallsFunc(t.RateLimitFor)
	}
	return p
}

func NewStdioProxy(upstream []string, agent string, engine *policy.Engine, validator *validate.Validator, limiter *ratelimit.Limiter, auditor *audit.Auditor, forwarder *forward.Forwarder, logger *log.Logger) *StdioProxy {
	return &StdioProxy{
		upstream:  upstream,
		agent:     agent,
		engine:    engine,
		validator: validator,
		limiter:   limiter,
		auditor:   auditor,
		forwarder: forwarder,
		logger:    logger,
	}
}

// audit records a policy decision to the local trail and, for enforcement
// decisions, forwards it to the NockCC ops-log. Both sinks are independent and
// fail-open: a write or forward problem is logged but never blocks or fails the
// tool call.
func (p *StdioProxy) audit(tool, decision, reason string) {
	if p.trust.Enabled() {
		if outcome, ok := trust.DecisionToOutcome(decision); ok {
			p.trust.ApplyOutcome(outcome)
		}
	}
	if p.auditor.Enabled() {
		if err := p.auditor.Record(audit.Event{Agent: p.agent, Tool: tool, Decision: decision, Reason: reason}); err != nil {
			p.logger.Printf("AUDIT-ERROR agent=%s tool=%s: %v", p.agent, tool, err)
		}
	}
	if p.forwarder.Enabled() && isEnforcement(decision) {
		p.forwarder.Enqueue(forward.Event{Agent: p.agent, Tool: tool, Decision: decision, Reason: reason})
	}
}

// isEnforcement reports whether a decision is a policy action worth surfacing in
// the NockCC ops-log. Allowed calls and tool-list hides are excluded to keep the
// centralized feed to notable enforcement or shadow-enforcement signal.
func isEnforcement(decision string) bool {
	switch decision {
	case "deny", "block", "ratelimit", "approval-granted", "approval-denied", "would-deny":
		// approval-* are the highest-signal events NockGuard captures: a human
		// had to intervene on a consequential call, so both outcomes surface.
		return true
	default:
		return false
	}
}

func (p *StdioProxy) Run() error {
	cmd := exec.Command(p.upstream[0], p.upstream[1:]...)
	cmd.Stderr = os.Stderr
	// Isolate proxy-only secrets from the policed agent. The upstream child would
	// otherwise inherit the proxy's full environment and could read it from its own
	// /proc/self/environ. Two secret sets are stripped:
	//   1. The audit signing seed (Ed25519/HMAC) — a child that read it could forge
	//      the audit trail, defeating non-repudiation against the very party it
	//      targets. Already parsed into the Auditor at startup; the child never needs it.
	//   2. The Phase 5 approval-gate credentials (dedicated Telegram bot token + chat
	//      id, and the e2e test seam) — a child that read the token could drive the
	//      Telegram approve/callback APIs to SELF-APPROVE a human-gated call, defeating
	//      the approval gate. The approver runs IN the proxy process (buildApprover's
	//      os.Getenv is unaffected by this child-only sanitize), so the child never needs them.
	// The two strip sets compose; sanitizedEnv only touches the CHILD's cmd.Env.
	strip := append(p.engine.SigningKeyEnvNamesFor(p.agent), approval.CredEnvNames()...)
	cmd.Env = sanitizedEnv(strip)

	upstreamIn, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}
	upstreamOut, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start upstream: %w", err)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	pendingCalls := &sync.Map{}

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := p.agentToUpstream(os.Stdin, upstreamIn, pendingCalls); err != nil {
			errCh <- fmt.Errorf("agent->upstream: %w", err)
		}
		upstreamIn.Close()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := p.upstreamToAgent(upstreamOut, os.Stdout, pendingCalls); err != nil {
			errCh <- fmt.Errorf("upstream->agent: %w", err)
		}
	}()

	wg.Wait()
	close(errCh)

	if waitErr := cmd.Wait(); waitErr != nil {
		return fmt.Errorf("upstream exit: %w", waitErr)
	}

	for e := range errCh {
		return e
	}
	return nil
}

func (p *StdioProxy) agentToUpstream(r io.Reader, w io.Writer, pending *sync.Map) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()

		// Canonicalize the TOP-LEVEL message before doing anything else. Unmarshal
		// into a map so any duplicate top-level keys (method, id, params, ...)
		// collapse to Go's last-wins value, then re-marshal: the bytes the proxy
		// gates and the bytes the upstream receives are now identical, so a
		// first-key-wins upstream cannot read a different "method" (e.g. a second
		// "method":"tools/list" hiding a "method":"tools/call"). A line that is not
		// a single JSON object (batch array, malformed) fails here → fail CLOSED.
		var topLevel map[string]json.RawMessage
		if err := json.Unmarshal(line, &topLevel); err != nil {
			p.logger.Printf("REJECT agent=%s reason=undecodable-or-batch", p.agent)
			errResp := jsonrpc.ErrorResponse(json.RawMessage("null"), -32700,
				"nockguard: rejected — only single well-formed JSON-RPC objects are accepted (batch arrays are not gated)")
			if writeErr := p.writeAgentLine(p.agentWriter(), errResp); writeErr != nil {
				return writeErr
			}
			continue
		}
		canonicalLine, err := json.Marshal(topLevel)
		if err != nil {
			p.handleFailModeAsk("", nil, "canonical-marshal-failed")
			p.logger.Printf("REJECT agent=%s reason=canonical-marshal-failed", p.agent)
			errResp := jsonrpc.ErrorResponse(json.RawMessage("null"), -32603,
				"nockguard: rejected — message could not be canonicalized")
			if writeErr := p.writeAgentLine(p.agentWriter(), errResp); writeErr != nil {
				return writeErr
			}
			continue
		}
		msg, err := jsonrpc.Decode(canonicalLine)
		if err != nil {
			// canonicalLine is a valid JSON object, so Decode into the Message
			// struct should not fail; if it somehow does, fail CLOSED.
			p.logger.Printf("REJECT agent=%s reason=undecodable-after-canonicalize", p.agent)
			errResp := jsonrpc.ErrorResponse(json.RawMessage("null"), -32700,
				"nockguard: rejected — message is not a well-formed JSON-RPC object")
			if writeErr := p.writeAgentLine(p.agentWriter(), errResp); writeErr != nil {
				return writeErr
			}
			continue
		}

		// Gate tools/call by METHOD, regardless of id: a notification-form call
		// (no id) must NOT slip past the gates. params are ALSO canonicalized so
		// what we gate is exactly what we forward — closing duplicate-key and
		// other parser-differential bypasses at both the top level and in params.
		if msg.Method == "tools/call" {
			toolName, canonicalParams, ok := canonicalToolCall(msg.Params)
			if !ok || toolName == "" {
				// A tools/call whose name we cannot extract fails CLOSED — the
				// upstream might still resolve a name the proxy could not see.
				dec := p.engine.FailModeVerdict(p.agent, "unextractable-name")
				if dec.Verdict == policy.Ask && p.approveAsk("", canonicalLine, dec) {
					if _, writeErr := fmt.Fprintf(w, "%s\n", canonicalLine); writeErr != nil {
						return writeErr
					}
				} else {
					p.logger.Printf("DENY agent=%s reason=unextractable-name", p.agent)
					p.audit("", "deny", "unextractable-name")
					if werr := p.rejectToAgent(msg.ID, -32600,
						"nockguard: tools/call rejected — tool name could not be extracted"); werr != nil {
						return werr
					}
				}
				continue
			}

			// Evaluate once: the verdict gates the call, and the basis (which rule
			// matched) is recorded in the audit trail so a denial is explainable
			// rather than an opaque "policy". The matched rule is kept OUT of the
			// agent-facing error on purpose — revealing it would let a hostile
			// agent map the policy surface — so it lands only in the log + audit.
			dec := p.engine.Evaluate(p.agent, toolName)
			if dec.Verdict == policy.Deny {
				p.logger.Printf("DENY agent=%s tool=%s reason=%q", p.agent, toolName, dec.Reason)
				p.audit(toolName, "deny", dec.Reason)
				if werr := p.rejectToAgent(msg.ID, -32600,
					fmt.Sprintf("nockguard: tool %q denied by policy", toolName)); werr != nil {
					return werr
				}
				continue
			}
			// N8328: legacy require_approval is promoted to a hard `ask` and
			// FAILS CLOSED when no approver is wired — identical to a native `ask`
			// rule. Previously it set allowWithoutApprover=true here, which made the
			// gate fail OPEN (a require_approval-covered call was treated as
			// approval SUCCESS with no human in the loop). The default must be safe:
			// no approver -> the call is blocked, not silently forwarded.
			if dec.Verdict == policy.Allow && p.engine.RequiresApproval(p.agent, toolName) {
				dec.Verdict = policy.Ask
			}

			// Phase 2: input validation on the canonical tool-call arguments
			// (the bytes that will actually be forwarded).
			if p.validator.Enabled() {
				if hit := p.validator.CheckParams(canonicalParams); hit != "" {
					p.logger.Printf("BLOCK agent=%s tool=%s rule=%s", p.agent, toolName, hit)
					p.audit(toolName, "block", hit)
					if werr := p.rejectToAgent(msg.ID, -32600,
						fmt.Sprintf("nockguard: tool %q arguments blocked by input validation (%s)", toolName, hit)); werr != nil {
						return werr
					}
					continue
				}
			}

			// Phase 3: rate limiting + spend caps. Checked only for calls that
			// have cleared policy and validation (i.e. would reach upstream), so
			// denied/blocked calls never consume budget.
			if p.limiter.Enabled() {
				if reason, ok := p.limiter.Allow(); !ok {
					p.logger.Printf("RATELIMIT agent=%s tool=%s reason=%s", p.agent, toolName, reason)
					p.audit(toolName, "ratelimit", reason)
					if werr := p.rejectToAgent(msg.ID, -32600,
						fmt.Sprintf("nockguard: tool %q blocked: %s exceeded", toolName, limitLabel(reason))); werr != nil {
						return werr
					}
					continue
				}
			}

			if dec.Verdict == policy.Ask && !p.approveAsk(toolName, canonicalParams, dec) {
				if werr := p.rejectToAgent(msg.ID, -32600,
					fmt.Sprintf("nockguard: tool %q denied by approval gate", toolName)); werr != nil {
					return werr
				}
				continue
			}

			// Cleared every gate — forward CANONICAL bytes, never the raw line.
			// Swap the canonical params back into the (already top-level-canonical)
			// message map and re-marshal, so the upstream sees exactly the name we
			// gated, once, with every other top-level field preserved verbatim.
			topLevel["params"] = canonicalParams
			out, mErr := json.Marshal(topLevel)
			if mErr != nil {
				p.handleFailModeAsk(toolName, canonicalParams, "canonical-marshal-failed")
				p.logger.Printf("DENY agent=%s tool=%s reason=canonical-marshal-failed", p.agent, toolName)
				p.audit(toolName, "deny", "canonical-marshal-failed")
				if werr := p.rejectToAgent(msg.ID, -32603,
					"nockguard: tools/call rejected — could not canonicalize message"); werr != nil {
					return werr
				}
				continue
			}
			p.logger.Printf("ALLOW agent=%s tool=%s", p.agent, toolName)
			if dec.ShadowWouldDeny {
				p.audit(toolName, "would-deny", dec.Reason)
			}
			p.audit(toolName, "allow", dec.Reason)
			if _, writeErr := fmt.Fprintf(w, "%s\n", out); writeErr != nil {
				return writeErr
			}
			continue
		}

		// tools/list (always a request) — track the id so the response can be
		// filtered, then forward below.
		if msg.IsRequest() && msg.Method == "tools/list" {
			pending.Store(string(msg.ID), true)
		}

		// Non-tools/call traffic (initialize, tools/list, responses, other
		// notifications) is not gated, but we forward the CANONICAL top-level
		// bytes (not the raw line) so duplicate-key collapsing reaches upstream —
		// a shadow "method" can't differ between the proxy's view and upstream's.
		if _, writeErr := fmt.Fprintf(w, "%s\n", canonicalLine); writeErr != nil {
			return writeErr
		}
	}
	return scanner.Err()
}

// approveAsk holds an `ask`-verdict call (native ask rules AND legacy
// require_approval, which is promoted to ask) for a human verdict. It FAILS
// CLOSED: with no approver wired (p.approver == nil) the call is denied, never
// forwarded. N8328 removed the prior allowWithoutApprover escape hatch that made
// legacy require_approval fail OPEN.
func (p *StdioProxy) approveAsk(tool string, params json.RawMessage, dec policy.Decision) bool {
	if p.approver == nil {
		p.logger.Printf("APPROVAL-DENIED agent=%s tool=%s reason=no-approver-configured (fail-closed)", p.agent, tool)
		p.audit(tool, "approval-denied", "no-approver-configured")
		return false
	}
	v := p.approver.Ask(approval.Request{Agent: p.agent, Tool: tool, Params: params})
	if !v.Approved {
		p.logger.Printf("APPROVAL-DENIED agent=%s tool=%s reason=%s", p.agent, tool, v.Reason)
		p.audit(tool, "approval-denied", v.Reason)
		return false
	}
	p.logger.Printf("APPROVAL-GRANTED agent=%s tool=%s reason=%s", p.agent, tool, v.Reason)
	p.audit(tool, "approval-granted", v.Reason)
	p.applyWithheld(tool, dec.Withheld)
	return true
}

func (p *StdioProxy) handleFailModeAsk(tool string, params json.RawMessage, reason string) bool {
	dec := p.engine.FailModeVerdict(p.agent, reason)
	if dec.Verdict != policy.Ask {
		return false
	}
	return p.approveAsk(tool, params, dec)
}

func (p *StdioProxy) applyWithheld(tool string, writes []policy.StateWrite) {
	for _, write := range writes {
		reason := write.Reason()
		p.logger.Printf("STATE-WRITE agent=%s tool=%s reason=%q", p.agent, tool, reason)
		p.audit(tool, "state-write", reason)
	}
}

// rejectToAgent returns a JSON-RPC error to the agent for a denied REQUEST
// (id present). A notification (no id) has no response channel in JSON-RPC, so a
// denied notification is simply dropped — nothing is forwarded upstream and
// nothing is written back to the agent.
func (p *StdioProxy) rejectToAgent(id json.RawMessage, code int, message string) error {
	if id == nil {
		return nil
	}
	errResp := jsonrpc.ErrorResponse(id, code, message)
	return p.writeAgentLine(p.agentWriter(), errResp)
}

func (p *StdioProxy) upstreamToAgent(r io.Reader, w io.Writer, pending *sync.Map) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		msg, err := jsonrpc.Decode(line)
		if err != nil {
			if writeErr := p.writeAgentLine(w, line); writeErr != nil {
				return writeErr
			}
			continue
		}

		if msg.IsResponse() && msg.ID != nil {
			if _, loaded := pending.LoadAndDelete(string(msg.ID)); loaded {
				filtered := p.filterToolListResponse(line)
				if filtered != nil {
					line = filtered
				}
			}
		}

		if writeErr := p.writeAgentLine(w, line); writeErr != nil {
			return writeErr
		}
	}
	return scanner.Err()
}

func (p *StdioProxy) filterToolListResponse(line []byte) []byte {
	var resp struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  *struct {
			Tools []struct {
				Name        string          `json:"name"`
				Description string          `json:"description,omitempty"`
				InputSchema json.RawMessage `json:"inputSchema,omitempty"`
			} `json:"tools"`
		} `json:"result,omitempty"`
	}
	if err := json.Unmarshal(line, &resp); err != nil || resp.Result == nil {
		return nil
	}

	var filtered []struct {
		Name        string          `json:"name"`
		Description string          `json:"description,omitempty"`
		InputSchema json.RawMessage `json:"inputSchema,omitempty"`
	}
	for _, t := range resp.Result.Tools {
		if dec := p.engine.Evaluate(p.agent, t.Name); dec.Allowed() {
			filtered = append(filtered, t)
		} else {
			p.logger.Printf("HIDE agent=%s tool=%s reason=%q", p.agent, t.Name, dec.Reason)
			p.audit(t.Name, "hide", dec.Reason)
		}
	}

	resp.Result.Tools = filtered
	out, err := json.Marshal(resp)
	if err != nil {
		return nil
	}
	return out
}

// limitLabel turns a limiter reason code into a human-readable phrase for the
// JSON-RPC error returned to the agent.
func limitLabel(reason string) string {
	switch reason {
	case "spend-cap":
		return "spend cap"
	case "rate":
		return "rate limit"
	default:
		return reason
	}
}

// sanitizedEnv returns the proxy's environment with the named variables removed.
// Used to strip the audit signing seed before spawning the upstream child so the
// policed agent cannot read it. Variables not in strip are inherited unchanged;
// an empty strip list returns the full environment.
func sanitizedEnv(strip []string) []string {
	if len(strip) == 0 {
		return os.Environ()
	}
	stripSet := make(map[string]struct{}, len(strip))
	for _, name := range strip {
		stripSet[name] = struct{}{}
	}
	parent := os.Environ()
	env := make([]string, 0, len(parent))
	for _, kv := range parent {
		name := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			name = kv[:i]
		}
		if _, drop := stripSet[name]; drop {
			continue
		}
		env = append(env, kv)
	}
	return env
}

// canonicalToolCall interprets a tools/call params object in Go's canonical
// last-value-wins form and returns the extracted tool name plus the re-marshaled
// canonical params. ok is false when params is absent or not a JSON object — a
// call the proxy cannot interpret, which the caller fails closed. Top-level
// duplicate keys collapse to the last value (the value the name gate sees), so
// the forwarded bytes carry exactly one of each key and the upstream cannot
// resolve a shadow name. Nested "arguments" are kept verbatim as RawMessage, so
// numbers inside tool arguments are never re-encoded (no float-precision risk).
func canonicalToolCall(params json.RawMessage) (name string, canonical json.RawMessage, ok bool) {
	if len(params) == 0 {
		return "", nil, false
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(params, &obj); err != nil {
		return "", nil, false
	}
	rawName, present := obj["name"]
	if !present {
		return "", nil, false
	}
	if err := json.Unmarshal(rawName, &name); err != nil {
		return "", nil, false
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return "", nil, false
	}
	return name, out, true
}
