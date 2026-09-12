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
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/nocktechnologies/nockguard/internal/approval"
	"github.com/nocktechnologies/nockguard/internal/audit"
	"github.com/nocktechnologies/nockguard/internal/extract"
	"github.com/nocktechnologies/nockguard/internal/forward"
	"github.com/nocktechnologies/nockguard/internal/jsonrpc"
	"github.com/nocktechnologies/nockguard/internal/policy"
	"github.com/nocktechnologies/nockguard/internal/ratelimit"
	"github.com/nocktechnologies/nockguard/internal/secrets"
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

	// Phase 6: credential injection (opt-in). resolver handles secret schemes;
	// scrubber redacts injected values from upstream responses. Nil resolver
	// falls back to the default chain (env + file schemes).
	resolver secrets.Resolver
	scrubber *scrubSet

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
	// currentCard is the NockCC card (nock id) from the most recent forwarded
	// nockcc_nock_claim call in this stdio session. It is stamped onto subsequent
	// audit rows so they are linked to the claimed card even if the tool arguments
	// do not name it explicitly. Protected by mu (shared with the two proxy goroutines).
	currentCard int        // 0 = no card claimed yet
	cardMu      sync.Mutex // serializes currentCard updates

	// Audit ordering: track request sequence to ensure audits are emitted in request order
	auditSeq      uint64                    // atomic: incremented for each request to assign sequence numbers
	auditTodo     map[uint64][]*audit.Event // buffered audits awaiting emission in sequence order
	auditMutex    sync.Mutex
	auditNext     uint64              // next sequence number ready to emit
	auditResolved map[uint64]struct{} // tracks which sequences are ready to flush
	cardAfterSeq  map[uint64]int      // seq -> card state after that commit
}

// writeAgentLine writes one newline-terminated line to the agent-facing channel
// under agentMu, so the two proxy goroutines never interleave output on it. w is
// the agent writer (os.Stdout in production; injectable for tests).
// The line is scrubbed to redact any injected secret values before writing.
func (p *StdioProxy) writeAgentLine(w io.Writer, line []byte) error {
	p.agentMu.Lock()
	defer p.agentMu.Unlock()
	// Scrub any injected secret values from the line
	scrubbed := line
	if p.scrubber != nil {
		scrubbed = p.scrubber.scrub(line)
	}
	_, err := fmt.Fprintf(w, "%s\n", scrubbed)
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
//
// For Probe, deferred audits (would-deny, allow for forwarded calls) are emitted
// immediately after agentToUpstream returns, since there's no upstream response path.
func (p *StdioProxy) Probe(line []byte) (forwarded bool, reply []byte, err error) {
	var upstream, agentReply bytes.Buffer
	prev := p.agentOut
	p.agentOut = &agentReply
	defer func() { p.agentOut = prev }()

	// Use a map to capture pending data (audits, state updates)
	pending := &sync.Map{}

	// agentToUpstream reads with a bufio.Scanner, which yields the final line
	// even without a trailing newline — so the raw bytes need no terminator.
	perr := p.agentToUpstream(bytes.NewReader(line), &upstream, pending)

	// For Probe, emit any deferred audits immediately since there's no response path
	pending.Range(func(key, val interface{}) bool {
		if cardVal, ok := val.(pendingCard); ok {
			// Emit deferred audits (assume success since this is a probe)
			for _, aud := range cardVal.audits {
				p.audit(cardVal.auditToolName, aud.decision, aud.reason, cardVal.auditRefs)
			}
		}
		return true
	})

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

// WithResolver sets a custom secret resolver. nil means the default chain
// (env + file schemes). Returns the proxy for chaining.
func (p *StdioProxy) WithResolver(r secrets.Resolver) *StdioProxy {
	p.resolver = r
	return p
}

func NewStdioProxy(upstream []string, agent string, engine *policy.Engine, validator *validate.Validator, limiter *ratelimit.Limiter, auditor *audit.Auditor, forwarder *forward.Forwarder, logger *log.Logger) *StdioProxy {
	resolver := secrets.Chain()
	return &StdioProxy{
		upstream:      upstream,
		agent:         agent,
		engine:        engine,
		validator:     validator,
		limiter:       limiter,
		auditor:       auditor,
		forwarder:     forwarder,
		logger:        logger,
		resolver:      resolver,
		scrubber:      newScrubSet(256), // LRU capped at 256 secret values
		auditTodo:     make(map[uint64][]*audit.Event),
		auditResolved: make(map[uint64]struct{}),
		cardAfterSeq:  make(map[uint64]int),
	}
}

// appendAudit queues an audit event for later emission in request-order.
// The event is queued but NOT stamped with currentCard yet; stamping happens
// at flush time to ensure deferred audits see card state from a preceding claim.
func (p *StdioProxy) appendAudit(seq uint64, tool, decision, reason string, refs *extract.References) {
	p.auditMutex.Lock()
	defer p.auditMutex.Unlock()

	// Build the audit event (no card stamp yet — that happens at flush time).
	// Allocate on the heap so the pointer remains valid after this function returns
	ev := &audit.Event{
		Agent:    p.agent,
		Tool:     tool,
		Decision: decision,
		Reason:   reason,
	}

	// Set extracted references if provided.
	if refs != nil {
		if refs.NockID > 0 {
			ev.NockID = refs.NockID
		}
		if refs.PR != "" {
			ev.PR = refs.PR
		}
		if refs.ReviewID != "" {
			ev.ReviewID = refs.ReviewID
		}
	}

	// Queue the event for later emission.
	if p.auditTodo[seq] == nil {
		p.auditTodo[seq] = make([]*audit.Event, 0, 1)
	}
	p.auditTodo[seq] = append(p.auditTodo[seq], ev)

	// Apply trust outcome and forward to ops-log immediately (not deferred).
	if p.trust.Enabled() {
		if outcome, ok := trust.DecisionToOutcome(decision); ok {
			p.trust.ApplyOutcome(outcome)
		}
	}
	if p.forwarder.Enabled() && isEnforcement(decision) {
		p.forwarder.Enqueue(forward.Event{Agent: p.agent, Tool: tool, Decision: decision, Reason: reason})
	}
}

// resolveAudit marks a sequence as ready to flush. Stamping of currentCard
// happens later at flush time to ensure deferred audits see card state from
// preceding claim/release commits.
func (p *StdioProxy) resolveAudit(seq uint64) {
	p.auditMutex.Lock()
	defer p.auditMutex.Unlock()

	// Idempotent: a seq below the flush frontier has already been emitted and its
	// auditResolved entry deleted. Re-marking it would reinsert a key that
	// flushAuditsLocked never revisits (it only deletes at p.auditNext), leaking one
	// entry per repeat. Callers legitimately resolve the same seq twice — decide()
	// resolves a policy-denied call and the HTTP/stdio handler resolves it again — so
	// a repeat of an already-flushed seq is a no-op, not an error.
	if seq < p.auditNext {
		return
	}

	// Mark this sequence as resolved.
	p.auditResolved[seq] = struct{}{}

	// Flush any consecutive sequences that are resolved.
	p.flushAuditsLocked()
}

// flushAuditsLocked emits queued audits in sequence order, stamping currentCard
// at flush time using the card state recorded by preceding commits.
// Must be called under auditMutex.
func (p *StdioProxy) flushAuditsLocked() {
	for {
		if _, resolved := p.auditResolved[p.auditNext]; !resolved {
			break // No more consecutive resolved sequences
		}

		audits, exists := p.auditTodo[p.auditNext]
		if !exists || audits == nil {
			// Shouldn't happen, but handle it gracefully
			delete(p.auditResolved, p.auditNext)
			p.auditNext++
			continue
		}

		// Stamp audits that don't have an extracted NockID with the card state from
		// the highest committed seq <= p.auditNext. Iterate the (pruned, small) map
		// rather than scanning 0..p.auditNext, which is O(auditNext) per flush and
		// O(N^2) over a long-lived session.
		var latestCard int
		var latestCardSeq uint64
		haveLatest := false
		for s, card := range p.cardAfterSeq {
			if s <= p.auditNext && (!haveLatest || s > latestCardSeq) {
				latestCardSeq = s
				latestCard = card
				haveLatest = true
			}
		}
		for _, ev := range audits {
			if ev.NockID == 0 && latestCard > 0 {
				ev.NockID = latestCard
			}
		}

		// Emit all audits for this sequence.
		for _, ev := range audits {
			// Record to audit trail
			if p.auditor.Enabled() {
				if err := p.auditor.Record(*ev); err != nil {
					p.logger.Printf("AUDIT-ERROR agent=%s tool=%s: %v", p.agent, ev.Tool, err)
				}
			}
		}

		// Clean up and move to next sequence.
		// NOTE: Do NOT delete cardAfterSeq entries here - they are kept for the entire session
		// because later seqs need to reference earlier card state updates.
		// Prune cardAfterSeq to avoid unbounded growth: keep only the single
		// latest entry with key < p.auditNext, which allows later seqs to still
		// reference the card state in effect at that point.
		var latestSeq uint64
		for seq := range p.cardAfterSeq {
			if seq < p.auditNext && seq > latestSeq {
				latestSeq = seq
			}
		}
		// Delete all entries with key < p.auditNext except the latest one
		for seq := range p.cardAfterSeq {
			if seq < p.auditNext && seq != latestSeq {
				delete(p.cardAfterSeq, seq)
			}
		}

		delete(p.auditTodo, p.auditNext)
		delete(p.auditResolved, p.auditNext)
		p.auditNext++
	}
}

// audit records a policy decision to the local trail with auditable references,
// and for enforcement decisions, forwards it to the NockCC ops-log. Both sinks are
// independent and fail-open: a write or forward problem is logged but never blocks or
// fails the tool call. refs may be nil (non-tools/call traffic or unknown tools).
//
// For request-path audits (denied, blocked, ratelimited), we track sequence order
// to ensure they're emitted after any preceding deferred audits.
func (p *StdioProxy) audit(tool, decision, reason string, refs *extract.References) {
	if p.trust.Enabled() {
		if outcome, ok := trust.DecisionToOutcome(decision); ok {
			p.trust.ApplyOutcome(outcome)
		}
	}

	// Build the audit event with extracted references and current card stamp.
	ev := audit.Event{
		Agent:    p.agent,
		Tool:     tool,
		Decision: decision,
		Reason:   reason,
	}

	// Set extracted references if provided.
	if refs != nil {
		if refs.NockID > 0 {
			ev.NockID = refs.NockID
		}
		if refs.PR != "" {
			ev.PR = refs.PR
		}
		if refs.ReviewID != "" {
			ev.ReviewID = refs.ReviewID
		}
	}

	// Stamp the current card onto this row if it's not already set by extraction.
	// Only stamp if the card was set by a forwarded nockcc_nock_claim (not denied).
	if ev.NockID == 0 {
		p.cardMu.Lock()
		currentCard := p.currentCard
		p.cardMu.Unlock()
		if currentCard > 0 {
			ev.NockID = currentCard
		}
	}

	if p.auditor.Enabled() {
		if err := p.auditor.Record(ev); err != nil {
			p.logger.Printf("AUDIT-ERROR agent=%s tool=%s: %v", p.agent, tool, err)
		}
	}
	if p.forwarder.Enabled() && isEnforcement(decision) {
		p.forwarder.Enqueue(forward.Event{Agent: p.agent, Tool: tool, Decision: decision, Reason: reason})
	}
}

// The current card is stamped onto rows that don't explicitly carry a NockID.

// updateCardState updates the session-scoped current card based on a forwarded claim or release.
// This is called only after the transport has confirmed the forward succeeded, ensuring
// state commits don't happen for failed forwards. tool and refs must match what was audited.
// Also records the new card state in cardAfterSeq for use at flush time.
func (p *StdioProxy) updateCardState(seq uint64, tool string, refs *extract.References) {
	if refs == nil || refs.NockID == 0 {
		return
	}

	// If this is a forwarded nockcc_nock_claim, set the current card.
	if tool == "nockcc_nock_claim" {
		p.cardMu.Lock()
		p.currentCard = refs.NockID
		p.cardMu.Unlock()
		// Record this card state for flush-time stamping
		p.auditMutex.Lock()
		p.cardAfterSeq[seq] = refs.NockID
		p.auditMutex.Unlock()
		return
	}

	// If this is a forwarded nockcc_nock_release for the current card, clear it.
	if tool == "nockcc_nock_release" {
		p.cardMu.Lock()
		matched := p.currentCard == refs.NockID
		if matched {
			p.currentCard = 0
		}
		p.cardMu.Unlock()
		// Record the cleared state for flush-time stamping ONLY when the release
		// matched the current card. A mismatched release leaves the card claimed, so
		// recording 0 would drop the still-active stamp from later audit rows.
		if matched {
			p.auditMutex.Lock()
			p.cardAfterSeq[seq] = 0
			p.auditMutex.Unlock()
		}
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

// drainAudits flushes all buffered audits whose responses never arrived.
// Called when the response loop exits (upstream closed or crashed).
// Marks all still-pending sequences as resolved and calls flushAuditsLocked
// to emit everything in order, stamped with card state at flush time.
func (p *StdioProxy) drainAudits() {
	p.auditMutex.Lock()
	defer p.auditMutex.Unlock()

	// Collect unresolved sequences for logging
	var unresolved []uint64
	for seq := range p.auditTodo {
		if _, isResolved := p.auditResolved[seq]; !isResolved {
			unresolved = append(unresolved, seq)
		}
	}
	sort.Slice(unresolved, func(i, j int) bool { return unresolved[i] < unresolved[j] })

	// Mark all pending sequences as resolved so flushAuditsLocked can emit them
	for seq := range p.auditTodo {
		if _, isResolved := p.auditResolved[seq]; !isResolved {
			p.auditResolved[seq] = struct{}{}
		}
	}

	// Log the drain for unresolved sequences only
	for _, seq := range unresolved {
		if audits, exists := p.auditTodo[seq]; exists && len(audits) > 0 {
			p.logger.Printf("AUDIT-DRAIN seq=%d tool=%s reason=upstream-closed", seq, audits[0].Tool)
		}
	}

	// Flush everything now that all sequences are marked resolved
	p.flushAuditsLocked()
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
	strip = append(strip, p.engine.InjectEnvNames()...)
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

	// Drain any unresolved audits before checking upstream exit
	p.drainAudits()

	if waitErr := cmd.Wait(); waitErr != nil {
		return fmt.Errorf("upstream exit: %w", waitErr)
	}

	for e := range errCh {
		return e
	}
	return nil
}

// mcpDecision is the transport-independent verdict for one inbound JSON-RPC
// message run through the enforcement gate. Both the stdio proxy and the HTTP
// listener consume it: the stdio proxy frames the fields as newline lines on
// stdio; the listener frames them as an upstream POST or a JSON-RPC HTTP error.
// Producing an mcpDecision (via decide) performs the gate's side effects —
// audit append, ops-log forward, approval prompt, logging — exactly once; it
// writes no transport bytes itself.
// pendingCard holds tool name and extracted references for a forwarded call
// waiting for its JSON-RPC response to decide whether to commit card state.
type deferredAudit struct {
	decision string
	reason   string
}

type pendingCard struct {
	tool          string
	refs          extract.References  // for card state updates (claim/release only) - COPY, not pointer
	audits        []deferredAudit     // audit decisions to emit after response is verified
	auditToolName string              // tool name for auditing
	auditRefs     *extract.References // extracted refs for auditing (all tools) - NOTE: used immediately in response processing
	auditSeq      uint64              // sequence number for audit ordering
}
type toolsListSeq struct {
	seq uint64
}

type mcpDecision struct {
	// forward, when non-nil, is the canonical bytes to send upstream (a cleared
	// tools/call, or non-gated traffic like initialize/tools/list). Mutually
	// exclusive with reject.
	forward []byte

	// reject is true when the message was denied/blocked/rate-limited/etc. When
	// rejectID is non-nil it names the JSON-RPC request id to answer with an
	// error; a nil rejectID marks a denied NOTIFICATION (no response channel in
	// JSON-RPC — the stdio proxy drops it silently, the listener acks 202).
	reject     bool
	rejectID   json.RawMessage
	rejectCode int
	rejectMsg  string

	// toolsListID is non-nil for a tools/list REQUEST, so the caller can track
	// the id and filter the paired response. tool is the extracted tool name for
	// a tools/call (informational; empty otherwise).
	toolsListID json.RawMessage
	tool        string
	// forwardID is the JSON-RPC request id (for requests only). Set for tool calls
	// that forward, so upstreamToAgent can correlate the response.
	forwardID json.RawMessage
	// cardStateUpdate stores tool name and extracted refs for updateCardState()
	// after the JSON-RPC response is verified as successful. nil means no state update needed.
	toolForState string              // tool name, empty if no state update needed
	refsForState *extract.References // extracted references, nil if no state update needed

	// deferredAudits holds audit decisions (would-deny, allow) that are emitted
	// in the response path after JSON-RPC success is confirmed. This ensures
	// audit stamping happens after card state is committed.
	deferredAudits []deferredAudit
	// refsForAudit holds extracted references for deferred audits (same as refsForState for card-state tools)
	refsForAudit *extract.References
}

func (p *StdioProxy) agentToUpstream(r io.Reader, w io.Writer, pending *sync.Map) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)
	for scanner.Scan() {
		// Assign sequence number to this request for audit ordering
		seq := atomic.AddUint64(&p.auditSeq, 1) - 1
		deferred := false

		d := p.decide(scanner.Bytes(), seq)
		if d.toolsListID != nil {
			// tools/list (always a request) — track the id so the response can be
			// filtered by upstreamToAgent. Mark as deferred so we don't resolve
			// until after filtering and appending hide audits.
			pending.Store(string(d.toolsListID), toolsListSeq{seq: seq})
			deferred = true
		}
		if d.reject {
			// A denied REQUEST returns a JSON-RPC error; a denied NOTIFICATION
			// (rejectID nil) is dropped — rejectToAgent no-ops on a nil id.
			if werr := p.rejectToAgent(d.rejectID, d.rejectCode, d.rejectMsg); werr != nil {
				return werr
			}
		}
		if d.forward != nil {
			if _, writeErr := fmt.Fprintf(w, "%s\n", d.forward); writeErr != nil {
				return writeErr
			}
			// Store pending data (state update + audits) to be processed after verifying the JSON-RPC response.
			// Notifications (no id) have no response to correlate, so don't store them.
			if d.forwardID != nil {
				// Copy refs to avoid storing pointer to local variable in decideToolCall
				var refsCopy extract.References
				if d.refsForState != nil {
					refsCopy = *d.refsForState
				}
				pending.Store(string(d.forwardID), pendingCard{
					tool:          d.toolForState,
					refs:          refsCopy,
					audits:        d.deferredAudits,
					auditToolName: d.tool,         // tool name for auditing
					auditRefs:     d.refsForAudit, // extracted refs for auditing
					auditSeq:      seq,            // sequence number for audit ordering
				})
			}
		}
		// Only resolve immediately for rejected calls, non-forwarded calls, or forwarded notifications (no id).
		// Forwarded requests with responses defer resolution to the response path.
		if !deferred && (d.reject || d.forward == nil || d.forwardID == nil) {
			p.resolveAudit(seq)
		}
	}
	return scanner.Err()
}

// decide drives one inbound JSON-RPC line through the enforcement gate and
// returns a transport-independent mcpDecision. It is the single source of
// enforcement shared by the stdio proxy (agentToUpstream) and the HTTP listener
// (HTTPListener.ServeHTTP) — the ordering deny → require_approval → validate →
// rate-limit → approval and every audit/log side effect live here once, so the
// two transports can never drift.
func (p *StdioProxy) decide(line []byte, seq uint64) mcpDecision {
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
		return mcpDecision{reject: true, rejectID: json.RawMessage("null"), rejectCode: -32700,
			rejectMsg: "nockguard: rejected — only single well-formed JSON-RPC objects are accepted (batch arrays are not gated)"}
	}
	canonicalLine, err := json.Marshal(topLevel)
	if err != nil {
		p.handleFailModeAsk("", nil, "canonical-marshal-failed", seq)
		p.logger.Printf("REJECT agent=%s reason=canonical-marshal-failed", p.agent)
		return mcpDecision{reject: true, rejectID: json.RawMessage("null"), rejectCode: -32603,
			rejectMsg: "nockguard: rejected — message could not be canonicalized"}
	}
	msg, err := jsonrpc.Decode(canonicalLine)
	if err != nil {
		// canonicalLine is a valid JSON object, so Decode into the Message
		// struct should not fail; if it somehow does, fail CLOSED.
		p.logger.Printf("REJECT agent=%s reason=undecodable-after-canonicalize", p.agent)
		return mcpDecision{reject: true, rejectID: json.RawMessage("null"), rejectCode: -32700,
			rejectMsg: "nockguard: rejected — message is not a well-formed JSON-RPC object"}
	}

	// Gate tools/call by METHOD, regardless of id: a notification-form call
	// (no id) must NOT slip past the gates. params are ALSO canonicalized so
	// what we gate is exactly what we forward — closing duplicate-key and
	// other parser-differential bypasses at both the top level and in params.
	if msg.Method == "tools/call" {
		return p.decideToolCall(msg, topLevel, canonicalLine, seq)
	}

	// Non-tools/call traffic (initialize, tools/list, responses, other
	// notifications) is not gated, but we forward the CANONICAL top-level bytes
	// (not the raw line) so duplicate-key collapsing reaches upstream — a shadow
	// "method" can't differ between the proxy's view and upstream's.
	d := mcpDecision{forward: canonicalLine}
	if msg.IsRequest() && msg.Method == "tools/list" {
		d.toolsListID = msg.ID
	}
	return d
}

// decideToolCall runs the enforcement gate for a tools/call message. topLevel is
// the already-top-level-canonicalized message map and canonicalLine its
// re-marshaled bytes (used verbatim on the fail-closed unextractable-name path).
func (p *StdioProxy) decideToolCall(msg *jsonrpc.Message, topLevel map[string]json.RawMessage, canonicalLine []byte, seq uint64) mcpDecision {
	toolName, canonicalParams, ok := canonicalToolCall(msg.Params)
	// Extract auditable references from tool arguments.
	refs := extract.FromToolCall(toolName, canonicalParams)
	if !ok || toolName == "" {
		// A tools/call whose name we cannot extract fails CLOSED — the
		// upstream might still resolve a name the proxy could not see.
		dec := p.engine.FailModeVerdict(p.agent, "unextractable-name")
		if dec.Verdict == policy.Ask && p.approveAsk("", canonicalLine, nil, dec, seq) {
			return mcpDecision{forward: canonicalLine}
		}
		p.logger.Printf("DENY agent=%s reason=unextractable-name", p.agent)
		p.appendAudit(seq, "", "deny", "unextractable-name", nil)
		p.resolveAudit(seq)
		return mcpDecision{reject: true, rejectID: msg.ID, rejectCode: -32600,
			rejectMsg: "nockguard: tools/call rejected — tool name could not be extracted"}
	}

	// Evaluate once: the verdict gates the call, and the basis (which rule
	// matched) is recorded in the audit trail so a denial is explainable
	// rather than an opaque "policy". The matched rule is kept OUT of the
	// agent-facing error on purpose — revealing it would let a hostile
	// agent map the policy surface — so it lands only in the log + audit.
	dec := p.engine.Evaluate(p.agent, toolName)
	if dec.Verdict == policy.Deny {
		p.logger.Printf("DENY agent=%s tool=%s reason=%q", p.agent, toolName, dec.Reason)
		p.appendAudit(seq, toolName, "deny", dec.Reason, &refs)
		p.resolveAudit(seq)
		return mcpDecision{reject: true, rejectID: msg.ID, rejectCode: -32600, tool: toolName,
			rejectMsg: fmt.Sprintf("nockguard: tool %q denied by policy", toolName)}
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
			p.appendAudit(seq, toolName, "block", hit, &refs)
			p.resolveAudit(seq)
			return mcpDecision{reject: true, rejectID: msg.ID, rejectCode: -32600, tool: toolName,
				rejectMsg: fmt.Sprintf("nockguard: tool %q arguments blocked by input validation (%s)", toolName, hit)}
		}
	}

	// Phase 3: rate limiting + spend caps. Checked only for calls that
	// have cleared policy and validation (i.e. would reach upstream), so
	// denied/blocked calls never consume budget.
	if p.limiter.Enabled() {
		if reason, ok := p.limiter.Allow(); !ok {
			p.logger.Printf("RATELIMIT agent=%s tool=%s reason=%s", p.agent, toolName, reason)
			p.appendAudit(seq, toolName, "ratelimit", reason, &refs)
			p.resolveAudit(seq)
			return mcpDecision{reject: true, rejectID: msg.ID, rejectCode: -32600, tool: toolName,
				rejectMsg: fmt.Sprintf("nockguard: tool %q blocked: %s exceeded", toolName, limitLabel(reason))}
		}
	}

	if dec.Verdict == policy.Ask && !p.approveAsk(toolName, canonicalParams, &refs, dec, seq) {
		return mcpDecision{reject: true, rejectID: msg.ID, rejectCode: -32600, tool: toolName,
			rejectMsg: fmt.Sprintf("nockguard: tool %q denied by approval gate", toolName)}
	}

	// Phase 6: credential injection (opt-in). Inject only happens on allowed calls,
	// after every other gate has cleared. Exactly one resolution per rule, at
	// forward time. Fail-closed: any resolution error or unsettable arg path
	// rejects the call.
	injectRules := p.engine.InjectRulesFor(p.agent, toolName)
	var injectedParams json.RawMessage
	if len(injectRules) > 0 {
		var rejectReason string
		var ok bool
		injectedParams, rejectReason, ok = p.applyInject(toolName, canonicalParams, injectRules, seq)
		if !ok {
			p.logger.Printf("DENY agent=%s tool=%s reason=%s", p.agent, toolName, rejectReason)
			return mcpDecision{reject: true, rejectID: msg.ID, rejectCode: -32600, tool: toolName,
				rejectMsg: rejectReason}
		}
	} else {
		injectedParams = canonicalParams
	}

	// Cleared every gate — forward CANONICAL bytes, never the raw line.
	// Swap the canonical params back into the (already top-level-canonical)
	// message map and re-marshal, so the upstream sees exactly the name we
	// gated, once, with every other top-level field preserved verbatim.
	topLevel["params"] = injectedParams
	out, mErr := json.Marshal(topLevel)
	if mErr != nil {
		p.handleFailModeAsk(toolName, canonicalParams, "canonical-marshal-failed", seq)
		p.logger.Printf("DENY agent=%s tool=%s reason=canonical-marshal-failed", p.agent, toolName)
		p.appendAudit(seq, toolName, "deny", "canonical-marshal-failed", &refs)
		p.resolveAudit(seq)
		return mcpDecision{reject: true, rejectID: msg.ID, rejectCode: -32603, tool: toolName,
			rejectMsg: "nockguard: tools/call rejected — could not canonicalize message"}
	}
	p.logger.Printf("ALLOW agent=%s tool=%s", p.agent, toolName)

	// Collect audits to be emitted after response verification (in response path).
	// This defers audit stamping until after card state is committed, ensuring
	// that generic tools see the current card from a preceding claim's response.
	audits := []deferredAudit{}
	if dec.ShadowWouldDeny {
		audits = append(audits, deferredAudit{"would-deny", dec.Reason})
		p.appendAudit(seq, toolName, "would-deny", dec.Reason, &refs)
	}
	audits = append(audits, deferredAudit{"allow", dec.Reason})
	p.appendAudit(seq, toolName, "allow", dec.Reason, &refs)

	// Only set card state for tools that actually update card state (claim/release).
	// This ensures updateCardState is only called on JSON-RPC success.
	var toolForState string
	var refsForState *extract.References
	if toolName == "nockcc_nock_claim" || toolName == "nockcc_nock_release" {
		toolForState, refsForState = toolName, &refs
	}

	return mcpDecision{forward: out, tool: toolName, forwardID: msg.ID, toolForState: toolForState, refsForState: refsForState, deferredAudits: audits, refsForAudit: &refs}
}

// approveAsk holds an `ask`-verdict call (native ask rules AND legacy
// require_approval, which is promoted to ask) for a human verdict. It FAILS
// CLOSED: with no approver wired (p.approver == nil) the call is denied, never
// forwarded. N8328 removed the prior allowWithoutApprover escape hatch that made
// legacy require_approval fail OPEN.
func (p *StdioProxy) approveAsk(tool string, params json.RawMessage, refs *extract.References, dec policy.Decision, seq uint64) bool {
	if p.approver == nil {
		p.logger.Printf("APPROVAL-DENIED agent=%s tool=%s reason=no-approver-configured (fail-closed)", p.agent, tool)
		p.appendAudit(seq, tool, "approval-denied", "no-approver-configured", refs)
		p.resolveAudit(seq)
		return false
	}
	v := p.approver.Ask(approval.Request{Agent: p.agent, Tool: tool, Params: params})
	if !v.Approved {
		p.logger.Printf("APPROVAL-DENIED agent=%s tool=%s reason=%s", p.agent, tool, v.Reason)
		p.appendAudit(seq, tool, "approval-denied", v.Reason, refs)
		p.resolveAudit(seq)
		return false
	}
	p.logger.Printf("APPROVAL-GRANTED agent=%s tool=%s reason=%s", p.agent, tool, v.Reason)
	p.appendAudit(seq, tool, "approval-granted", v.Reason, refs)
	p.applyWithheld(tool, dec.Withheld, seq)
	return true
}

func (p *StdioProxy) handleFailModeAsk(tool string, params json.RawMessage, reason string, seq uint64) bool {
	dec := p.engine.FailModeVerdict(p.agent, reason)
	if dec.Verdict != policy.Ask {
		return false
	}
	return p.approveAsk(tool, params, nil, dec, seq)
}

func (p *StdioProxy) applyWithheld(tool string, writes []policy.StateWrite, seq uint64) {
	if len(writes) == 0 {
		return
	}
	for _, write := range writes {
		reason := write.Reason()
		p.logger.Printf("STATE-WRITE agent=%s tool=%s reason=%q", p.agent, tool, reason)
		p.appendAudit(seq, tool, "state-write", reason, nil)
	}
	p.resolveAudit(seq)
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
			val, loaded := pending.LoadAndDelete(string(msg.ID))
			if loaded {
				// Check if this is a tools/list filter or a pending card state update.
				if toolListVal, ok := val.(toolsListSeq); ok {
					// tools/list response — filter it
					filtered := p.filterToolListResponse(line, toolListVal.seq)
					// Resolve the tools/list audits
					p.resolveAudit(toolListVal.seq)
					if filtered != nil {
						line = filtered
					}
				} else if cardVal, ok := val.(pendingCard); ok {
					// Pending forward — check JSON-RPC success before committing state or auditing
					shouldCommit := true
					if msg.Error != nil {
						// JSON-RPC error — don't commit state or audit
						shouldCommit = false
					} else if msg.Result != nil {
						// Check for tool-level isError (MCP tool result failure).
						// Tool errors travel as successful JSON-RPC responses with result.isError=true.
						var result map[string]interface{}
						if err := json.Unmarshal(msg.Result, &result); err == nil {
							if toolErr, ok := result["isError"].(bool); ok && toolErr {
								shouldCommit = false
							}
						}
					}
					// Only commit state if JSON-RPC succeeded.
					// Audits are resolved unconditionally to ensure the queue doesn't stall.
					if shouldCommit {
						p.updateCardState(cardVal.auditSeq, cardVal.tool, &cardVal.refs)
					}
					// Resolve audits unconditionally - even if shouldCommit is false.
					// Appended audits will be emitted in order by flushAuditsLocked.
					p.resolveAudit(cardVal.auditSeq)
				}
			}
		}

		if writeErr := p.writeAgentLine(w, line); writeErr != nil {
			return writeErr
		}
	}
	return scanner.Err()
}

func (p *StdioProxy) filterToolListResponse(line []byte, seq uint64) []byte {
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
			p.appendAudit(seq, t.Name, "hide", dec.Reason, nil)
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
