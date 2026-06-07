package proxy

import (
	"bufio"
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
	approver  approval.Approver // Phase 5; nil = no approval gate (Phase 1-4 behavior)
	logger    *log.Logger
}

// WithApprover wires the Phase 5 interactive approval gate. nil (the default)
// disables the gate entirely, preserving Phase 1-4 behavior. Returns the proxy
// for chaining off NewStdioProxy.
func (p *StdioProxy) WithApprover(a approval.Approver) *StdioProxy {
	p.approver = a
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
// centralized feed to genuine enforcement signal.
func isEnforcement(decision string) bool {
	switch decision {
	case "deny", "block", "ratelimit", "approval-granted", "approval-denied":
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
	// Isolate the audit signing seed from the policed agent. The upstream child
	// would otherwise inherit the proxy's full environment — including the
	// configured Ed25519/HMAC signing variable — and could read it to forge the
	// audit trail, defeating non-repudiation against the very party it targets.
	// The key is already parsed into the Auditor at startup, so the child never
	// needs it.
	cmd.Env = sanitizedEnv(p.engine.SigningKeyEnvNames())

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
		msg, err := jsonrpc.Decode(line)
		if err != nil {
			if _, writeErr := fmt.Fprintf(w, "%s\n", line); writeErr != nil {
				return writeErr
			}
			continue
		}

		if msg.IsRequest() && msg.Method == "tools/call" {
			toolName := extractToolName(msg.Params)
			if toolName != "" && !p.engine.Check(p.agent, toolName) {
				p.logger.Printf("DENY agent=%s tool=%s", p.agent, toolName)
				p.audit(toolName, "deny", "policy")
				errResp := jsonrpc.ErrorResponse(msg.ID, -32600, fmt.Sprintf("nockguard: tool %q denied by policy", toolName))
				if _, writeErr := fmt.Fprintf(os.Stdout, "%s\n", errResp); writeErr != nil {
					return writeErr
				}
				continue
			}

			// Phase 2: input validation on the tool-call arguments.
			if p.validator.Enabled() {
				if hit := p.validator.CheckParams(msg.Params); hit != "" {
					p.logger.Printf("BLOCK agent=%s tool=%s rule=%s", p.agent, toolName, hit)
					p.audit(toolName, "block", hit)
					errResp := jsonrpc.ErrorResponse(msg.ID, -32600, fmt.Sprintf("nockguard: tool %q arguments blocked by input validation (%s)", toolName, hit))
					if _, writeErr := fmt.Fprintf(os.Stdout, "%s\n", errResp); writeErr != nil {
						return writeErr
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
					errResp := jsonrpc.ErrorResponse(msg.ID, -32600, fmt.Sprintf("nockguard: tool %q blocked: %s exceeded", toolName, limitLabel(reason)))
					if _, writeErr := fmt.Fprintf(os.Stdout, "%s\n", errResp); writeErr != nil {
						return writeErr
					}
					continue
				}
			}

			// Phase 5: interactive approval gate. The call has cleared policy,
			// validation and limits, so it WOULD be allowed — but a tool matching
			// require_approval is HELD for a human nod first. Fail-safe: the
			// approver returns Approved=false on timeout/transport error, so a
			// missed prompt never auto-approves a consequential call.
			if p.approver != nil && p.engine.RequiresApproval(p.agent, toolName) {
				v := p.approver.Ask(approval.Request{Agent: p.agent, Tool: toolName, Params: msg.Params})
				if !v.Approved {
					p.logger.Printf("APPROVAL-DENIED agent=%s tool=%s reason=%s", p.agent, toolName, v.Reason)
					p.audit(toolName, "approval-denied", v.Reason)
					errResp := jsonrpc.ErrorResponse(msg.ID, -32600, fmt.Sprintf("nockguard: tool %q denied by approval gate (%s)", toolName, v.Reason))
					if _, writeErr := fmt.Fprintf(os.Stdout, "%s\n", errResp); writeErr != nil {
						return writeErr
					}
					continue
				}
				p.logger.Printf("APPROVAL-GRANTED agent=%s tool=%s reason=%s", p.agent, toolName, v.Reason)
				p.audit(toolName, "approval-granted", v.Reason)
			}

			p.logger.Printf("ALLOW agent=%s tool=%s", p.agent, toolName)
			p.audit(toolName, "allow", "")
		}

		if msg.IsRequest() && msg.Method == "tools/list" {
			pending.Store(string(msg.ID), true)
		}

		if _, writeErr := fmt.Fprintf(w, "%s\n", line); writeErr != nil {
			return writeErr
		}
	}
	return scanner.Err()
}

func (p *StdioProxy) upstreamToAgent(r io.Reader, w io.Writer, pending *sync.Map) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		msg, err := jsonrpc.Decode(line)
		if err != nil {
			if _, writeErr := fmt.Fprintf(w, "%s\n", line); writeErr != nil {
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

		if _, writeErr := fmt.Fprintf(w, "%s\n", line); writeErr != nil {
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
		if p.engine.Check(p.agent, t.Name) {
			filtered = append(filtered, t)
		} else {
			p.logger.Printf("HIDE agent=%s tool=%s", p.agent, t.Name)
			p.audit(t.Name, "hide", "")
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

func extractToolName(params json.RawMessage) string {
	var p struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ""
	}
	return p.Name
}
