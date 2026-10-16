package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

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

type auditSequenceRange struct {
	start uint64
	end   uint64
}

type StdioProxy struct {
	upstream      []string
	agent         string
	engine        *policy.Engine
	validator     *validate.Validator
	limiter       *ratelimit.Limiter
	auditor       *audit.Auditor
	requiredAudit bool // enabled by default when the local audit trail is on
	forwarder     *forward.Forwarder
	trust         *trust.Accumulator
	approver      approval.Approver // Phase 5; nil = no approval gate (Phase 1-4 behavior)
	logger        *log.Logger

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
	auditSeq      uint64                    // next request sequence, protected by auditMutex
	auditTodo     map[uint64][]*audit.Event // buffered audits awaiting emission in sequence order
	auditMutex    sync.Mutex
	auditNext     uint64               // next sequence number ready to emit
	auditResolved []auditSequenceRange // compact sorted ranges of resolved sequences
	auditPending  map[uint64]struct{}  // allocated sequences whose audit lifecycle is unsettled
	auditFailed   map[uint64]struct{}  // action sequences with a row rejected before append
	cardAfterSeq  map[uint64]int       // seq -> card state after that commit
	requestIDMu   sync.Mutex
	activeIDs     map[uint64]json.RawMessage // request ids held until their agent-facing response is delivered
	actionPairing bool
	actionRunID   string
	actionInitErr error
	actionSeq     uint64
	actionIDs     map[uint64]string // audit request sequence -> generated action id
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

	// For Probe, resolve queued forwarded-call audits immediately since there's no
	// upstream response path. This exercises the same audit queue as live traffic.
	pending.Range(func(key, val interface{}) bool {
		if cardVal, ok := val.(*pendingCard); ok {
			if cardVal.stateTool != "" {
				p.updateCardState(cardVal.auditSeq, cardVal.stateTool, &cardVal.stateRefs)
			}
			if cardVal.actionID != "" {
				p.markActionUnknown(cardVal, "upstream_exit")
			}
			p.resolveAudit(cardVal.auditSeq)
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

// WithBestEffortAudit explicitly restores logging without a forwarding gate.
func (p *StdioProxy) WithBestEffortAudit() *StdioProxy {
	p.requiredAudit = false
	if p.actionPairing {
		p.actionInitErr = fmt.Errorf("audit.action_pairing requires required auditing and cannot use --audit-best-effort")
	}
	p.auditor.ClearFailureStatus()
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
	p := &StdioProxy{
		upstream:      upstream,
		agent:         agent,
		engine:        engine,
		validator:     validator,
		limiter:       limiter,
		auditor:       auditor,
		requiredAudit: auditor.Enabled(),
		forwarder:     forwarder,
		logger:        logger,
		resolver:      resolver,
		scrubber:      newScrubSet(256), // LRU capped at 256 secret values
		auditTodo:     make(map[uint64][]*audit.Event),
		auditPending:  make(map[uint64]struct{}),
		auditFailed:   make(map[uint64]struct{}),
		cardAfterSeq:  make(map[uint64]int),
		activeIDs:     make(map[uint64]json.RawMessage),
		actionIDs:     make(map[uint64]string),
	}
	if engine.ActionPairingEnabled() {
		p.actionPairing = true
		if !auditor.Enabled() {
			p.actionInitErr = fmt.Errorf("audit.action_pairing requires an available durable audit writer")
			return p
		}
		var runID [16]byte
		if _, err := rand.Read(runID[:]); err != nil {
			p.actionInitErr = fmt.Errorf("initialize action audit run id: %w", err)
		} else {
			p.actionRunID = hex.EncodeToString(runID[:])
		}
	}
	return p
}

// appendAudit queues an audit event for later emission in request-order. The
// event is stamped at flush time from the latest card state already committed
// at or before this sequence. Action pairing may flush a later call while an
// earlier claim is still pending; that row intentionally keeps the prior card
// (or no card), and a later claim commit never rewrites it.
func (p *StdioProxy) appendAudit(seq uint64, tool, decision, reason string, refs *extract.References) {
	p.appendAuditWithApprovalActor(seq, tool, decision, reason, refs, "")
}

// appendAuditWithApprovalActor adds an approver identity only when a local
// approver supplied it from Unix peer credentials. Other approval backends and
// normal tool-call audit rows leave the field absent.
func (p *StdioProxy) appendAuditWithApprovalActor(seq uint64, tool, decision, reason string, refs *extract.References, approvalActor string) {
	p.auditMutex.Lock()
	defer p.auditMutex.Unlock()

	// Build the audit event (no card stamp yet — that happens at flush time).
	// Allocate on the heap so the pointer remains valid after this function returns
	ev := &audit.Event{
		Agent:         p.agent,
		Tool:          tool,
		Decision:      decision,
		Reason:        reason,
		ApprovalActor: approvalActor,
	}
	if actionID := p.actionIDs[seq]; actionID != "" {
		p.setActionFields(ev, actionID)
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

// reserveAuditSequence assigns request order and tracks the pending lifecycle
// before the request can commit card state or produce audit rows.
func (p *StdioProxy) reserveAuditSequence() uint64 {
	p.auditMutex.Lock()
	seq := p.auditSeq
	p.auditSeq++
	p.auditPending[seq] = struct{}{}
	p.auditMutex.Unlock()
	return seq
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

	// Mark this sequence resolved. Ranges keep a long run of completions behind
	// one slow request to constant size instead of retaining one map entry each.
	p.markAuditSequenceResolvedLocked(seq)

	// Action replies depend on their own decision, dispatch, and observation rows,
	// not on every earlier request finishing. Persist an action's rows now; the
	// request-order frontier will skip this sequence when it catches up.
	if p.actionPairing && p.actionIDs[seq] != "" {
		p.flushAuditSequenceLocked(seq)
		delete(p.actionIDs, seq)
	}
	delete(p.auditPending, seq)
	p.pruneCardHistoryLocked()

	// Flush any consecutive sequences that are resolved.
	p.flushAuditsLocked()
}

func (p *StdioProxy) auditSequenceResolvedLocked(seq uint64) bool {
	i := sort.Search(len(p.auditResolved), func(i int) bool {
		return p.auditResolved[i].end >= seq
	})
	return i < len(p.auditResolved) && p.auditResolved[i].start <= seq
}

func (p *StdioProxy) markAuditSequenceResolvedLocked(seq uint64) {
	merged := auditSequenceRange{start: seq, end: seq}
	ranges := make([]auditSequenceRange, 0, len(p.auditResolved)+1)
	inserted := false
	for _, current := range p.auditResolved {
		if current.end < merged.start && current.end+1 < merged.start {
			ranges = append(ranges, current)
			continue
		}
		if merged.end < current.start && merged.end+1 < current.start {
			if !inserted {
				ranges = append(ranges, merged)
				inserted = true
			}
			ranges = append(ranges, current)
			continue
		}
		merged.start = min(merged.start, current.start)
		merged.end = max(merged.end, current.end)
	}
	if !inserted {
		ranges = append(ranges, merged)
	}
	p.auditResolved = ranges
}

func (p *StdioProxy) consumeAuditSequenceLocked(seq uint64) {
	if len(p.auditResolved) == 0 || p.auditResolved[0].start != seq {
		return
	}
	if p.auditResolved[0].end == seq {
		p.auditResolved = p.auditResolved[1:]
	} else {
		p.auditResolved[0].start++
	}
}

// flushAuditSequenceLocked writes one resolved sequence without waiting for an
// earlier unresolved request. Action observations use this path so a slow call
// does not hold unrelated replies. Must be called under auditMutex.
func (p *StdioProxy) flushAuditSequenceLocked(seq uint64) {
	audits, exists := p.auditTodo[seq]
	if !exists {
		return
	}

	// Stamp audits from the highest committed card state at or before this
	// request. A later response may have committed a different card first.
	var latestCard int
	var latestCardSeq uint64
	haveLatest := false
	for s, card := range p.cardAfterSeq {
		if s <= seq && (!haveLatest || s > latestCardSeq) {
			latestCardSeq = s
			latestCard = card
			haveLatest = true
		}
	}
	for _, ev := range audits {
		if ev.NockID == 0 && latestCard > 0 {
			ev.NockID = latestCard
		}
		if err := p.recordAudit(*ev); err != nil && ev.ActionID != "" {
			p.markAuditFailureLocked(seq)
		}
	}
	delete(p.auditTodo, seq)
}

func (p *StdioProxy) markAuditFailureLocked(seq uint64) {
	if p.auditFailed == nil {
		p.auditFailed = make(map[uint64]struct{})
	}
	p.auditFailed[seq] = struct{}{}
}

// flushAuditsLocked emits queued audits in sequence order, stamping currentCard
// at flush time using the card state recorded by preceding commits.
// Must be called under auditMutex.
func (p *StdioProxy) flushAuditsLocked() {
	for p.auditSequenceResolvedLocked(p.auditNext) {
		// Action sequences may already have been emitted out of order.
		p.flushAuditSequenceLocked(p.auditNext)
		p.advanceAuditFrontierLocked()
	}
}

// advanceAuditFrontierLocked cleans up the emitted sequence and prunes card
// history while preserving pending requests' predecessors. Must hold auditMutex.
func (p *StdioProxy) advanceAuditFrontierLocked() {
	seq := p.auditNext
	p.consumeAuditSequenceLocked(seq)
	delete(p.auditPending, seq)
	delete(p.actionIDs, seq)
	p.auditNext++
	p.pruneCardHistoryLocked()
}

// pruneCardHistoryLocked keeps the latest card state and the predecessor needed
// by each unsettled sequence, including requests whose audit rows are not queued yet.
func (p *StdioProxy) pruneCardHistoryLocked() {
	if len(p.cardAfterSeq) <= 1 {
		return
	}
	cardSeqs := make([]uint64, 0, len(p.cardAfterSeq))
	for seq := range p.cardAfterSeq {
		cardSeqs = append(cardSeqs, seq)
	}
	sort.Slice(cardSeqs, func(i, j int) bool { return cardSeqs[i] < cardSeqs[j] })
	keep := map[uint64]struct{}{cardSeqs[len(cardSeqs)-1]: {}}
	pendingSeqs := make([]uint64, 0, len(p.auditPending)+len(p.auditTodo))
	for seq := range p.auditPending {
		pendingSeqs = append(pendingSeqs, seq)
	}
	for seq := range p.auditTodo {
		pendingSeqs = append(pendingSeqs, seq)
	}
	sort.Slice(pendingSeqs, func(i, j int) bool { return pendingSeqs[i] < pendingSeqs[j] })
	cardIndex := 0
	for _, seq := range pendingSeqs {
		for cardIndex < len(cardSeqs) && cardSeqs[cardIndex] <= seq {
			cardIndex++
		}
		if cardIndex > 0 {
			keep[cardSeqs[cardIndex-1]] = struct{}{}
		}
	}
	for seq := range p.cardAfterSeq {
		if _, ok := keep[seq]; !ok {
			delete(p.cardAfterSeq, seq)
		}
	}
}

// audit records a policy decision to the local trail with auditable references,
// and for enforcement decisions, forwards it to the NockCC ops-log. Both sinks are
// independent. Local writes use required mode when selected by the HTTP listener;
// remote forwarding remains best-effort. refs may be nil (non-tools/call traffic
// or unknown tools).
//
// For request-path audits (denied, blocked, ratelimited), we track sequence order
// to ensure they're emitted after any preceding deferred audits.
func (p *StdioProxy) audit(tool, decision, reason string, refs *extract.References, actionIDs ...string) {
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
	if len(actionIDs) > 0 && actionIDs[0] != "" {
		p.setActionFields(&ev, actionIDs[0])
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

	p.recordAudit(ev)
	if p.forwarder.Enabled() && isEnforcement(decision) {
		p.forwarder.Enqueue(forward.Event{Agent: p.agent, Tool: tool, Decision: decision, Reason: reason})
	}
}

// auditMethod records only method metadata. Non-tool traffic must not change
// tool trust scores or acquire references from params or session card state.
func (p *StdioProxy) auditMethod(method, decision, reason string) {
	p.recordAudit(audit.Event{Agent: p.agent, Tool: method, Decision: decision, Reason: reason})
	if p.forwarder.Enabled() && isEnforcement(decision) {
		p.forwarder.Enqueue(forward.Event{Agent: p.agent, Tool: method, Decision: decision, Reason: reason})
	}
}

func (p *StdioProxy) setActionFields(ev *audit.Event, actionID string) {
	ev.SchemaVersion = 2
	ev.RecordType = "decision"
	ev.RunID = p.actionRunID
	ev.ActionID = actionID
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
	case "deny", "method-deny", "block", "ratelimit", "approval-granted", "approval-denied", "would-deny":
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

	// Collect unresolved sequences for logging and mark them ready to flush.
	var unresolved []uint64
	for seq := range p.auditTodo {
		if !p.auditSequenceResolvedLocked(seq) {
			unresolved = append(unresolved, seq)
			p.markAuditSequenceResolvedLocked(seq)
		}
	}
	sort.Slice(unresolved, func(i, j int) bool { return unresolved[i] < unresolved[j] })

	// Include requests that have not produced audit rows yet.
	for seq := range p.auditPending {
		if !p.auditSequenceResolvedLocked(seq) {
			p.markAuditSequenceResolvedLocked(seq)
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

// The leader wait and idle output drain use this shutdown bound. After the
// leader exits, progress can renew the output drain up to its absolute cap.
// Audit draining gets another 500ms after the group is killed and reaped, so
// a forced shutdown has time to record unanswered calls. Forced kills return
// a nonzero upstream exit. Unread output is dropped at the idle deadline.
const upstreamShutdownBound = time.Second
const upstreamOutputDrainCap = 10 * time.Second
const auditDrainBound = 500 * time.Millisecond

func (p *StdioProxy) Run() error {
	if p.actionInitErr != nil {
		return p.actionInitErr
	}

	cmd := exec.Command(p.upstream[0], p.upstream[1:]...)
	cmd.Stderr = os.Stderr
	// Isolate proxy-only secrets from the policed agent. The upstream child would
	// otherwise inherit the proxy's full environment and could read it from its own
	// /proc/self/environ. These secret sets are stripped:
	//   1. The audit signing seed (Ed25519/HMAC) — a child that read it could forge
	//      the audit trail, defeating non-repudiation against the very party it
	//      targets. Already parsed into the Auditor at startup; the child never needs it.
	//   2. The Phase 5 approval-gate credentials (dedicated Telegram bot token + chat
	//      id, and the e2e test seam) — a child that read the token could drive the
	//      Telegram approve/callback APIs to SELF-APPROVE a human-gated call, defeating
	//      the approval gate. The approver runs IN the proxy process (buildApprover's
	//      os.Getenv is unaffected by this child-only sanitize), so the child never needs them.
	//   3. The NockCC vault endpoint and agent token — the proxy uses them to
	//      resolve nockcc: refs, so the upstream child must not inherit them.
	//   4. The configured audit-forwarder API key, used only by the proxy.
	// The strip sets compose; sanitizedEnv only touches the CHILD's cmd.Env.
	strip := append(p.engine.SigningKeyEnvNamesFor(p.agent), approval.CredEnvNames()...)
	strip = append(strip, p.engine.InjectEnvNames()...)
	strip = append(strip, p.engine.ForwarderKeyEnvNames()...)
	strip = append(strip, "NOCKCC_BASE_URL", "NOCKGUARD_VAULT_AGENT_TOKEN")
	cmd.Env = sanitizedEnv(strip)
	// Own process group, so a cutoff can kill grandchildren that inherited stdout.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	upstreamIn, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}
	// An *os.File stdout (not StdoutPipe) so cmd.Wait neither closes the read
	// end nor waits on a grandchild that inherited it.
	upstreamOut, upstreamOutW, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	defer upstreamOut.Close()
	cmd.Stdout = upstreamOutW
	// A closed client stdout must surface as EPIPE so Run can clean up the
	// upstream group instead of exiting immediately on SIGPIPE. Notify installs
	// a caught handler, which exec resets in the upstream child.
	brokenPipeSignals := make(chan os.Signal, 1)
	if !signal.Ignored(syscall.SIGPIPE) {
		signal.Notify(brokenPipeSignals, syscall.SIGPIPE)
		defer signal.Stop(brokenPipeSignals)
	}
	signals := make(chan os.Signal, 1)
	for _, sig := range []os.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT} {
		if !signal.Ignored(sig) {
			signal.Notify(signals, sig)
		}
	}
	defer signal.Stop(signals)

	err = cmd.Start()
	upstreamOutW.Close()
	if err != nil {
		return fmt.Errorf("start upstream: %w", err)
	}
	defer upstreamIn.Close()
	waitCh := observeLeaderExit(cmd)

	errCh := make(chan error, 1)
	var agentEOF atomic.Bool
	var outputFailed atomic.Bool
	outputErrCh := make(chan error, 1)
	upstreamDone := make(chan struct{})
	outputProgress := make(chan struct{}, 1)

	pendingCalls := &sync.Map{}
	auditCleanupStarted := false
	defer func() {
		if !auditCleanupStarted {
			p.finishPendingActions(pendingCalls, "shutdown")
			p.drainAudits()
		}
	}()

	go func() {
		if err := p.agentToUpstream(os.Stdin, upstreamIn, pendingCalls); err != nil {
			errCh <- fmt.Errorf("agent->upstream: %w", err)
		} else {
			agentEOF.Store(true)
		}
		upstreamIn.Close()
	}()

	go func() {
		defer close(upstreamDone)
		if err := p.upstreamToAgent(upstreamOut, os.Stdout, pendingCalls, outputProgress, true); err != nil {
			outputFailed.Store(true)
			outputErrCh <- fmt.Errorf("upstream->agent: %w", err)
		}
	}()

	var observed error
	outputComplete := false
	select {
	case <-upstreamDone:
		outputComplete = true
	case observed = <-waitCh:
	case sig := <-signals:
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		return fmt.Errorf("proxy received %s", sig)
	}
	// Clean output EOF bounds the leader wait to one second. When the leader
	// exits first, let a reading client receive output while it keeps flowing,
	// subject to a ten-second absolute cap from that exit.
	shutdownBound := upstreamShutdownBound
	if !outputComplete {
		shutdownBound = upstreamOutputDrainCap
	}
	shutdown, cancel := context.WithTimeout(context.Background(), shutdownBound)
	defer cancel()
	outputTimedOut, shutdownTimedOut := false, false
	var idle *time.Timer
	var idleDeadline <-chan time.Time
	if outputComplete {
		// A clean client EOF may let the leader finish on its own, but that
		// grace must end at the same deadline as every later shutdown wait.
		if outputFailed.Load() || !agentEOF.Load() {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		select {
		case observed = <-waitCh:
		case <-shutdown.Done():
			shutdownTimedOut = true
			p.logger.Print("upstream exited: leader wait deadline reached")
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			observed = <-waitCh
		case sig := <-signals:
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			return fmt.Errorf("proxy received %s", sig)
		}
	} else {
		idle = time.NewTimer(upstreamShutdownBound)
		defer idle.Stop()
		idleDeadline = idle.C
		var drainLimit string
	drainOutput:
		for {
			select {
			case <-upstreamDone:
				break drainOutput
			case <-outputProgress:
				idle.Reset(upstreamShutdownBound)
			case <-idleDeadline:
				// A completed write can race the timer. Drain its notification
				// before treating the client as idle.
				select {
				case <-outputProgress:
					idle.Reset(upstreamShutdownBound)
					continue
				default:
				}
				drainLimit = "idle"
				break drainOutput
			case <-shutdown.Done():
				drainLimit = "absolute cap"
				break drainOutput
			case sig := <-signals:
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				return fmt.Errorf("proxy received %s", sig)
			}
		}
		// If EOF and a deadline became ready together, the completed drain wins.
		if drainLimit != "" {
			select {
			case <-upstreamDone:
				drainLimit = ""
			default:
			}
		}
		if drainLimit != "" {
			outputTimedOut, shutdownTimedOut = true, true
			p.logger.Printf("upstream exited: output drain deadline reached (%s); dropping remaining output", drainLimit)
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			_ = upstreamOut.Close()
		}
		// Pending replies can block on a client that stops reading after the
		// output loop finishes. Give them only the same idle grace.
		idle.Reset(upstreamShutdownBound)
	}
	if !agentEOF.Load() && !outputTimedOut {
		replied := make(chan struct{})
		go func() {
			defer close(replied)
			p.replyPendingAtShutdown(pendingCalls)
		}()
		select {
		case <-replied:
		case <-idleDeadline:
			shutdownTimedOut = true
			p.logger.Print("upstream exited: client reply deadline reached; abandoning remaining replies")
		case <-shutdown.Done():
			shutdownTimedOut = true
			p.logger.Print("upstream exited: client reply deadline reached; abandoning remaining replies")
		case sig := <-signals:
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			return fmt.Errorf("proxy received %s", sig)
		}
	}
	// Linux and macOS waitid leave the leader unreaped until this kill, so
	// the PGID cannot have been reused. Output errors and signals also kill
	// the group before waiting for the leader.
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	waitErr := reapLeader(cmd, observed)
	// A leader that used the whole shutdown bound must not consume the time
	// reserved for deferred audits from unanswered forwarded calls.
	auditShutdown, cancelAudit := context.WithTimeout(context.Background(), auditDrainBound)
	defer cancelAudit()
	audited := make(chan struct{})
	auditCleanupStarted = true
	go func() {
		cause := "upstream_exit"
		if outputTimedOut || shutdownTimedOut {
			cause = "timeout"
		}
		p.finishPendingActions(pendingCalls, cause)
		p.drainAudits()
		close(audited)
	}()
	select {
	case <-audited:
	case <-auditShutdown.Done():
		shutdownTimedOut = true
		p.logger.Print("upstream exited: audit drain deadline reached")
	case sig := <-signals:
		return fmt.Errorf("proxy received %s", sig)
	}
	if !outputTimedOut {
		select {
		case e := <-outputErrCh:
			return e
		default:
		}
	}
	if waitErr != nil {
		return fmt.Errorf("upstream exit: %w", waitErr)
	}
	if !agentEOF.Load() {
		select {
		case e := <-errCh:
			return e
		default:
		}
		return errors.New("upstream exited before the client closed stdin")
	}
	if shutdownTimedOut {
		return errors.New("upstream shutdown deadline reached")
	}
	select {
	case e := <-errCh:
		return e
	default:
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
	tool                 string             // action tool for the terminal observation
	refs                 extract.References // references written on the terminal observation
	stateTool            string             // only claim/release may change current-card state
	stateRefs            extract.References // copied references used by updateCardState
	auditSeq             uint64             // sequence number for audit ordering
	actionID             string
	requestID            json.RawMessage
	mu                   sync.Mutex
	observation          string
	lateResponseRecorded bool
	suppressLateResponse bool
	answered             bool
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
	// forwardID is the JSON-RPC request id for a forwarded request other than
	// tools/list, so upstreamToAgent can correlate its response.
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
	refsForAudit      *extract.References
	notForwardedCause string
}

// actionCard copies only the references permitted in action observations.
func (d mcpDecision) actionCard(seq uint64, actionID string) *pendingCard {
	card := &pendingCard{tool: d.tool, auditSeq: seq, actionID: actionID}
	if d.refsForAudit != nil {
		card.refs = *d.refsForAudit
	}
	return card
}

func (p *StdioProxy) newActionID() (string, error) {
	for {
		current := atomic.LoadUint64(&p.actionSeq)
		if current == ^uint64(0) {
			return "", fmt.Errorf("action sequence exhausted; restart the proxy")
		}
		if atomic.CompareAndSwapUint64(&p.actionSeq, current, current+1) {
			return fmt.Sprintf("%s.%d", p.actionRunID, current+1), nil
		}
	}
}

func (p *StdioProxy) queueActionID(seq uint64, actionID string) {
	p.auditMutex.Lock()
	p.actionIDs[seq] = actionID
	p.auditMutex.Unlock()
}

func (p *StdioProxy) appendActionObservation(seq uint64, card *pendingCard, observation, cause, responseClass string, mcpIsError *bool) error {
	if card == nil || card.actionID == "" {
		return nil
	}
	ev := audit.Event{
		Agent:         p.agent,
		Tool:          card.tool,
		SchemaVersion: 2,
		RecordType:    "action_observation",
		RunID:         p.actionRunID,
		ActionID:      card.actionID,
		Observation:   observation,
		Cause:         cause,
		ResponseClass: responseClass,
		MCPIsError:    mcpIsError,
		PR:            card.refs.PR,
		ReviewID:      card.refs.ReviewID,
	}
	if card.refs.NockID > 0 {
		ev.NockID = card.refs.NockID
	}

	p.auditMutex.Lock()
	if seq < p.auditNext || p.auditSequenceResolvedLocked(seq) {
		p.auditMutex.Unlock()
		err := p.recordAudit(ev)
		if err != nil {
			p.auditMutex.Lock()
			p.markAuditFailureLocked(seq)
			p.auditMutex.Unlock()
		}
		return err
	}
	p.auditTodo[seq] = append(p.auditTodo[seq], &ev)
	p.auditMutex.Unlock()
	p.resolveAudit(seq)
	if p.requiredAudit {
		return p.auditor.RequiredError()
	}
	return nil
}

func (p *StdioProxy) observeAction(card *pendingCard, observation, cause, responseClass string, mcpIsError *bool) error {
	if card == nil || card.actionID == "" {
		return nil
	}
	card.mu.Lock()
	defer card.mu.Unlock()
	if card.observation == "" {
		card.observation = observation
	} else if card.observation == "outcome_unknown" && observation == "response_observed" && !card.lateResponseRecorded {
		observation = "late_response_observed"
		cause = "late_response"
		card.lateResponseRecorded = true
	} else {
		return nil
	}
	return p.appendActionObservation(card.auditSeq, card, observation, cause, responseClass, mcpIsError)
}

func (p *StdioProxy) markActionUnknown(card *pendingCard, cause string) error {
	return p.observeAction(card, "outcome_unknown", cause, "", nil)
}

func cancellationRequestID(msg *jsonrpc.Message) json.RawMessage {
	if msg == nil || msg.Method != "notifications/cancelled" {
		return nil
	}
	var params map[string]json.RawMessage
	if json.Unmarshal(msg.Params, &params) != nil {
		return nil
	}
	return params["requestId"]
}

func pendingIDInUse(pending *sync.Map, requestID json.RawMessage) bool {
	if len(requestID) == 0 {
		return false
	}
	if _, ok := pending.Load(string(requestID)); ok {
		return true
	}
	found := false
	pending.Range(func(key, _ any) bool {
		id, ok := key.(string)
		if ok && jsonRPCIDsEqual([]byte(id), requestID) {
			found = true
			return false
		}
		return true
	})
	return found
}

func (p *StdioProxy) requestIDInUse(pending *sync.Map, requestID json.RawMessage) bool {
	if pendingIDInUse(pending, requestID) {
		return true
	}
	p.requestIDMu.Lock()
	defer p.requestIDMu.Unlock()
	for _, id := range p.activeIDs {
		if jsonRPCIDsEqual(id, requestID) {
			return true
		}
	}
	return false
}

func (p *StdioProxy) trackRequestID(seq uint64, requestID json.RawMessage) {
	if len(requestID) == 0 {
		return
	}
	p.requestIDMu.Lock()
	if p.activeIDs == nil {
		p.activeIDs = make(map[uint64]json.RawMessage)
	}
	p.activeIDs[seq] = append(json.RawMessage(nil), requestID...)
	p.requestIDMu.Unlock()
}

func (p *StdioProxy) releaseRequestID(seq uint64) {
	p.requestIDMu.Lock()
	delete(p.activeIDs, seq)
	p.requestIDMu.Unlock()
}

func loadPendingResponse(pending *sync.Map, responseID json.RawMessage) (any, bool) {
	if value, loaded := pending.LoadAndDelete(string(responseID)); loaded {
		return value, true
	}
	var value any
	var loaded bool
	pending.Range(func(key, candidate any) bool {
		id, ok := key.(string)
		if !ok || !jsonRPCIDsEqual([]byte(id), responseID) {
			return true
		}
		value, loaded = pending.LoadAndDelete(key)
		return false
	})
	return value, loaded
}

func findActionPendingResponse(pending *sync.Map, responseID json.RawMessage) (*pendingCard, bool) {
	if value, loaded := pending.Load(string(responseID)); loaded {
		if card, ok := value.(*pendingCard); ok && card.actionID != "" {
			return card, true
		}
	}
	var card *pendingCard
	pending.Range(func(key, candidate any) bool {
		id, ok := key.(string)
		value, isCard := candidate.(*pendingCard)
		if !ok || !isCard || value.actionID == "" || !jsonRPCIDsEqual([]byte(id), responseID) {
			return true
		}
		card = value
		return false
	})
	return card, card != nil
}

func (c *pendingCard) markLateReplySuppressed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	wasSuppressed := c.suppressLateResponse
	c.suppressLateResponse = true
	return wasSuppressed
}

func (c *pendingCard) lateReplySuppressed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.suppressLateResponse
}

func (c *pendingCard) markAnswered() {
	c.mu.Lock()
	c.answered = true
	c.mu.Unlock()
}

func (c *pendingCard) wasAnswered() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.answered
}

func invalidActionResponseID(line []byte, decodeErr error) (json.RawMessage, bool) {
	dec := json.NewDecoder(bytes.NewReader(line))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, false
	}
	var id, versionRaw, errorRaw json.RawMessage
	var hasID, hasVersion, hasMethod, hasResult, hasError bool
	seenKeys := make(map[string]struct{})
	duplicateKey := false
	for dec.More() {
		tok, err = dec.Token()
		if err != nil {
			return nil, false
		}
		key, ok := tok.(string)
		if !ok {
			return nil, false
		}
		foldedKey := actionResponseKeyFold(key)
		if _, seen := seenKeys[foldedKey]; seen {
			duplicateKey = true
		}
		seenKeys[foldedKey] = struct{}{}
		var value json.RawMessage
		if dec.Decode(&value) != nil {
			return nil, false
		}
		switch {
		case strings.EqualFold(key, "id"):
			id, hasID = value, true
		case strings.EqualFold(key, "jsonrpc"):
			versionRaw, hasVersion = value, true
		case strings.EqualFold(key, "method"):
			hasMethod = true
		case strings.EqualFold(key, "result"):
			hasResult = true
		case strings.EqualFold(key, "error"):
			errorRaw, hasError = value, true
		}
	}
	if _, err = dec.Token(); err != nil {
		return nil, false
	}
	if _, err = dec.Token(); err != io.EOF {
		return nil, false
	}
	if hasMethod && !hasResult && !hasError {
		return nil, false // upstream-initiated JSON-RPC request
	}
	if !hasID || len(id) == 0 {
		return nil, false
	}
	invalid := decodeErr != nil || hasMethod || duplicateKey
	var version string
	if !hasVersion || json.Unmarshal(versionRaw, &version) != nil || version != "2.0" || hasResult == hasError {
		invalid = true
	}
	if hasError && !validJSONRPCError(errorRaw) {
		invalid = true
	}
	return id, invalid
}

// actionResponseKeyFold maps each rune's simple-fold cycle to its lowest rune,
// preserving EqualFold semantics while producing a map key in one pass. ASCII
// keys use the equivalent, cheaper uppercase form.
func actionResponseKeyFold(key string) string {
	ascii := true
	for i := 0; i < len(key); i++ {
		if key[i] >= utf8.RuneSelf {
			ascii = false
			break
		}
	}
	if ascii {
		return strings.ToUpper(key)
	}

	var folded strings.Builder
	folded.Grow(len(key))
	for _, r := range key {
		canonical := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < canonical {
				canonical = next
			}
		}
		folded.WriteRune(canonical)
	}
	return folded.String()
}

func (p *StdioProxy) markCancelledAction(pending *sync.Map, requestID json.RawMessage) {
	if len(requestID) == 0 {
		return
	}
	pending.Range(func(_, value any) bool {
		card, ok := value.(*pendingCard)
		if !ok || card.actionID == "" || !jsonRPCIDsEqual(card.requestID, requestID) {
			return true
		}
		if err := p.markActionUnknown(card, "client_cancel"); err != nil {
			p.logger.Printf("AUDIT-ERROR agent=%s tool=%s: %v", p.agent, card.tool, err)
		}
		return false
	})
}

func (p *StdioProxy) finishPendingActions(pending *sync.Map, cause string) {
	pending.Range(func(_, value any) bool {
		card, ok := value.(*pendingCard)
		if ok && card.actionID != "" {
			if err := p.markActionUnknown(card, cause); err != nil {
				p.logger.Printf("AUDIT-ERROR agent=%s tool=%s: %v", p.agent, card.tool, err)
			}
		}
		return true
	})
}

func (p *StdioProxy) replyPendingAtShutdown(pending *sync.Map) {
	pending.Range(func(key, value any) bool {
		if card, ok := value.(*pendingCard); ok && card.wasAnswered() {
			return true
		}
		if err := p.rejectToAgent(json.RawMessage(key.(string)), -32603, "upstream exited"); err != nil {
			p.logger.Printf("upstream exited: reply for in-flight request failed: %v", err)
		}
		return true
	})
}

func (p *StdioProxy) agentToUpstream(r io.Reader, w io.Writer, pending *sync.Map) error {
	if p.actionInitErr != nil {
		return p.actionInitErr
	}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)
	for scanner.Scan() {
		if p.requiredAudit {
			if err := p.auditor.RequiredError(); err != nil {
				p.logger.Printf("AUDIT-ERROR agent=%s audit failing: calls refused: %v", p.agent, err)
				id := json.RawMessage("null")
				if msg, decodeErr := jsonrpc.Decode(scanner.Bytes()); decodeErr == nil {
					id = msg.ID
				}
				if rejectErr := p.rejectToAgent(id, -32603, AuditBeforeForwardError); rejectErr != nil {
					return rejectErr
				}
				continue
			}
		}
		// Assign sequence number to this request for audit ordering
		seq := p.reserveAuditSequence()
		deferred := false
		actionID := ""
		var canonicalTopLevel map[string]json.RawMessage
		var canonicalLine []byte
		var canonicalFailure canonicalMessageFailure
		var canonicalMsg *jsonrpc.Message
		if p.actionPairing {
			canonicalTopLevel, canonicalLine, canonicalMsg, canonicalFailure = canonicalizeMessage(scanner.Bytes())
			if canonicalFailure == canonicalMessageOK && canonicalMsg != nil && canonicalMsg.Method == "tools/call" {
				var err error
				actionID, err = p.newActionID()
				if err != nil {
					if rejectErr := p.rejectToAgent(canonicalMsg.ID, -32603, AuditBeforeForwardError); rejectErr != nil {
						return rejectErr
					}
					return err
				}
				p.queueActionID(seq, actionID)
			}
		}
		if p.actionPairing && canonicalMsg != nil && canonicalMsg.IsRequest() && p.requestIDInUse(pending, canonicalMsg.ID) {
			if actionID != "" {
				tool, params, _ := canonicalToolCall(canonicalMsg.Params)
				refs := extract.FromToolCall(tool, params)
				p.appendAudit(seq, tool, "block", "duplicate-active-request-id", &refs)
				p.resolveAudit(seq)
				card := &pendingCard{tool: tool, refs: refs, auditSeq: seq, actionID: actionID}
				if err := p.observeAction(card, "not_forwarded", "", "", nil); err != nil {
					p.logger.Printf("AUDIT-ERROR agent=%s tool=%s: %v", p.agent, tool, err)
				}
			}
			p.resolveAudit(seq)
			reason := "nockguard: duplicate active JSON-RPC request id"
			if p.requiredAudit && p.auditor.RequiredError() != nil {
				reason = AuditBeforeForwardError
			}
			if err := p.rejectToAgent(canonicalMsg.ID, -32600, reason); err != nil {
				return err
			}
			continue
		}

		var d mcpDecision
		if p.actionPairing {
			d = p.decideCanonical(canonicalTopLevel, canonicalLine, canonicalMsg, canonicalFailure, seq)
		} else {
			d = p.decide(scanner.Bytes(), seq)
		}
		if p.requiredAudit && p.auditor.RequiredError() != nil {
			p.resolveAudit(seq)
			id := d.rejectID
			if d.forward != nil {
				if msg, err := jsonrpc.Decode(d.forward); err == nil {
					id = msg.ID
				}
			}
			if err := p.rejectToAgent(id, -32603, AuditBeforeForwardError); err != nil {
				return err
			}
			continue
		}
		if d.toolsListID != nil {
			// tools/list (always a request) — track the id so the response can be
			// filtered by upstreamToAgent. Mark as deferred so we don't resolve
			// until after filtering and appending hide audits.
			pending.Store(string(d.toolsListID), toolsListSeq{seq: seq})
			if p.actionPairing {
				p.trackRequestID(seq, d.toolsListID)
			}
			deferred = true
		}
		if d.reject {
			p.resolveAudit(seq)
			if actionID != "" {
				card := d.actionCard(seq, actionID)
				if err := p.observeAction(card, "not_forwarded", d.notForwardedCause, "", nil); err != nil {
					d.rejectCode, d.rejectMsg = -32603, AuditBeforeForwardError
				}
			}
			if p.requiredAudit && p.auditor.RequiredError() != nil {
				d.rejectCode, d.rejectMsg = -32603, AuditBeforeForwardError
			}
			// A denied REQUEST returns a JSON-RPC error; a denied NOTIFICATION
			// (rejectID nil) is dropped — rejectToAgent no-ops on a nil id.
			if werr := p.rejectToAgent(d.rejectID, d.rejectCode, d.rejectMsg); werr != nil {
				return werr
			}
		}
		if d.forward != nil {
			var request jsonrpc.Message
			_ = json.Unmarshal(d.forward, &request)
			if p.actionPairing && request.Method == "notifications/cancelled" {
				p.markCancelledAction(pending, cancellationRequestID(&request))
			}
			if p.requiredAudit && request.Method == "tools/call" {
				p.audit(d.tool, "dispatch", "required-audit-before-forward", d.refsForAudit, actionID)
				if p.auditor.RequiredError() != nil {
					p.resolveAudit(seq)
					if err := p.rejectToAgent(request.ID, -32603, AuditBeforeForwardError); err != nil {
						return err
					}
					continue
				}
			}
			// Register response state before the write: an upstream may reply while
			// Write is still returning, and the response reader must be able to
			// correlate it immediately.
			if d.forwardID != nil {
				if p.actionPairing {
					p.trackRequestID(seq, d.forwardID)
				}
				pendingCard := d.actionCard(seq, actionID)
				pendingCard.stateTool = d.toolForState
				if d.refsForState != nil {
					pendingCard.stateRefs = *d.refsForState
				}
				pendingCard.requestID = append(json.RawMessage(nil), d.forwardID...)
				pending.Store(string(d.forwardID), pendingCard)
			}
			if _, writeErr := fmt.Fprintf(w, "%s\n", d.forward); writeErr != nil {
				id := d.forwardID
				if id == nil {
					id = d.toolsListID
				}
				resolveSeq := true
				if id != nil {
					val, loaded := pending.LoadAndDelete(string(id))
					resolveSeq = loaded
					if card, ok := val.(*pendingCard); ok && card.actionID != "" {
						if auditErr := p.markActionUnknown(card, "transport_lost"); auditErr != nil {
							p.logger.Printf("AUDIT-ERROR agent=%s tool=%s: %v", p.agent, card.tool, auditErr)
						}
					}
				}
				if resolveSeq && id != nil && p.actionPairing {
					p.releaseRequestID(seq)
				}
				if actionID != "" && request.Method == "tools/call" && d.forwardID == nil {
					card := d.actionCard(seq, actionID)
					if auditErr := p.markActionUnknown(card, "transport_lost"); auditErr != nil {
						p.logger.Printf("AUDIT-ERROR agent=%s tool=%s: %v", p.agent, d.tool, auditErr)
					}
				}
				// If the response path already took the entry, it owns resolving
				// the sequence after committing any response-backed state.
				if resolveSeq {
					p.resolveAudit(seq)
				}
				return writeErr
			}
			if actionID != "" && request.Method == "tools/call" && d.forwardID == nil {
				// A tools/call notification has no response id to correlate. Once its
				// bytes are sent, the remote outcome cannot be observed.
				p.resolveAudit(seq)
				card := d.actionCard(seq, actionID)
				if err := p.markActionUnknown(card, ""); err != nil {
					p.logger.Printf("AUDIT-ERROR agent=%s tool=%s: %v", p.agent, d.tool, err)
				}
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

type canonicalMessageFailure int

const (
	canonicalMessageOK canonicalMessageFailure = iota
	canonicalMessageUndecodable
	canonicalMessageAmbiguousKey
	canonicalMessageMarshalFailed
	canonicalMessageDecodeFailed
)

func canonicalizeMessage(line []byte) (map[string]json.RawMessage, []byte, *jsonrpc.Message, canonicalMessageFailure) {
	var topLevel map[string]json.RawMessage
	if err := json.Unmarshal(line, &topLevel); err != nil {
		return nil, nil, nil, canonicalMessageUndecodable
	}
	for _, field := range []string{"params", "method"} {
		_, exactPresent := topLevel[field]
		for key, value := range topLevel {
			if key == field || !strings.EqualFold(key, field) {
				continue
			}
			if _, exists := topLevel[field]; exists {
				if field == "method" && exactPresent {
					delete(topLevel, key)
					continue
				}
				return nil, nil, nil, canonicalMessageAmbiguousKey
			}
			topLevel[field] = value
			delete(topLevel, key)
		}
	}
	canonicalLine, err := json.Marshal(topLevel)
	if err != nil {
		return nil, nil, nil, canonicalMessageMarshalFailed
	}
	msg, err := jsonrpc.Decode(canonicalLine)
	if err != nil {
		return nil, nil, nil, canonicalMessageDecodeFailed
	}
	return topLevel, canonicalLine, msg, canonicalMessageOK
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
	// collapse to Go's last-wins value. Canonicalize case-folded method and params aliases
	// (or reject a conflict) before re-marshaling, so the bytes the proxy
	// gates and the bytes the upstream receives are now identical, so a
	// first-key-wins upstream cannot read a different "method" (e.g. a second
	// "method":"tools/list" hiding a "method":"tools/call"). A line that is not
	// a single JSON object (batch array, malformed) fails here → fail CLOSED.
	topLevel, canonicalLine, msg, failure := canonicalizeMessage(line)
	return p.decideCanonical(topLevel, canonicalLine, msg, failure, seq)
}

func (p *StdioProxy) decideCanonical(topLevel map[string]json.RawMessage, canonicalLine []byte, msg *jsonrpc.Message, failure canonicalMessageFailure, seq uint64) mcpDecision {
	switch failure {
	case canonicalMessageUndecodable:
		p.logger.Printf("REJECT agent=%s reason=undecodable-or-batch", p.agent)
		return mcpDecision{reject: true, rejectID: json.RawMessage("null"), rejectCode: -32700,
			rejectMsg: "nockguard: rejected — only single well-formed JSON-RPC objects are accepted (batch arrays are not gated)"}
	case canonicalMessageAmbiguousKey:
		p.logger.Printf("REJECT agent=%s reason=ambiguous-message-key", p.agent)
		return mcpDecision{reject: true, rejectID: json.RawMessage("null"), rejectCode: -32600,
			rejectMsg: "nockguard: rejected — ambiguous message key"}
	case canonicalMessageMarshalFailed:
		p.handleFailModeAsk("", nil, "canonical-marshal-failed", seq)
		p.logger.Printf("REJECT agent=%s reason=canonical-marshal-failed", p.agent)
		return mcpDecision{reject: true, rejectID: json.RawMessage("null"), rejectCode: -32603,
			rejectMsg: "nockguard: rejected — message could not be canonicalized"}
	case canonicalMessageDecodeFailed:
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

	// Responses have no method and are not new MCP operations. Record only
	// the method for requests and notifications; never inspect their params.
	if msg.Method != "" {
		if p.engine.DeniesMethod(p.agent, msg.Method) {
			p.auditMethod(msg.Method, "method-deny", "deny-method")
			return mcpDecision{reject: true, rejectID: msg.ID, rejectCode: -32601,
				rejectMsg: "nockguard: method denied by policy"}
		}
		p.auditMethod(msg.Method, "method-allow", "method-pass-through")
	}
	// Forward canonical bytes so policy and upstream see the same method.
	d := mcpDecision{forward: canonicalLine}
	if msg.IsRequest() {
		if msg.Method == "tools/list" {
			d.toolsListID = msg.ID
		} else {
			d.forwardID = msg.ID
		}
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
		if !p.actionPairing {
			// Preserve the legacy fail_mode: ask behavior. Pairing mode rejects
			// unextractable calls so every lifecycle row has a tool name.
			dec := p.engine.FailModeVerdict(p.agent, "unextractable-name")
			if dec.Verdict == policy.Ask && p.approveAsk("", canonicalLine, nil, dec, seq) {
				p.resolveAudit(seq)
				return mcpDecision{forward: canonicalLine}
			}
		}
		// A tools/call whose name cannot be extracted fails closed — an upstream
		// may resolve a name the proxy could not see.
		p.logger.Printf("DENY agent=%s reason=unextractable-name", p.agent)
		p.appendAudit(seq, "", "deny", "unextractable-name", nil)
		p.resolveAudit(seq)
		return mcpDecision{reject: true, rejectID: msg.ID, rejectCode: -32600,
			rejectMsg: "nockguard: tools/call rejected — tool name could not be extracted", notForwardedCause: "policy_denied"}
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
			rejectMsg: fmt.Sprintf("nockguard: tool %q denied by policy", toolName), notForwardedCause: "policy_denied"}
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
				rejectMsg: fmt.Sprintf("nockguard: tool %q arguments blocked by input validation (%s)", toolName, hit), notForwardedCause: "validation_blocked"}
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
				rejectMsg: fmt.Sprintf("nockguard: tool %q blocked: %s exceeded", toolName, limitLabel(reason)), notForwardedCause: "limit_reached"}
		}
	}

	if dec.Verdict == policy.Ask && !p.approveAsk(toolName, canonicalParams, &refs, dec, seq) {
		return mcpDecision{reject: true, rejectID: msg.ID, rejectCode: -32600, tool: toolName,
			rejectMsg: fmt.Sprintf("nockguard: tool %q denied by approval gate", toolName), notForwardedCause: "approval_denied"}
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
				rejectMsg: rejectReason, notForwardedCause: "policy_denied"}
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
			rejectMsg: "nockguard: tools/call rejected — could not canonicalize message", notForwardedCause: "policy_denied"}
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
	if dec.Verdict == policy.Ask {
		// Keep approval and withheld state writes before the required dispatch
		// row, while also recording this call's final allow decision.
		p.resolveAudit(seq)
	}

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
	v := p.approver.Ask(approval.Request{Agent: p.agent, Tool: tool, Params: params, Reason: dec.Reason,
		OnRejectedTap: func(reason string) {
			p.logger.Printf("APPROVAL-CALLBACK-BLOCKED agent=%s tool=%s reason=%s", p.agent, tool, reason)
			p.appendAudit(seq, tool, "block", reason, refs)
		},
	})
	if !v.Approved {
		p.logger.Printf("APPROVAL-DENIED agent=%s tool=%s reason=%s", p.agent, tool, v.Reason)
		p.appendAuditWithApprovalActor(seq, tool, "approval-denied", v.Reason, refs, v.ApprovalActor)
		p.resolveAudit(seq)
		return false
	}
	p.logger.Printf("APPROVAL-GRANTED agent=%s tool=%s reason=%s", p.agent, tool, v.Reason)
	p.appendAuditWithApprovalActor(seq, tool, "approval-granted", v.Reason, refs, v.ApprovalActor)
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

func (p *StdioProxy) upstreamToAgent(r io.Reader, w io.Writer, pending *sync.Map, progress chan<- struct{}, finalizeOnEOF ...bool) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)
	upstreamLines := make(chan []byte, 1)
	scanDone := make(chan error, 1)
	stopScanner := make(chan struct{})
	go func() {
		defer close(upstreamLines)
		for scanner.Scan() {
			line := append([]byte(nil), scanner.Bytes()...)
			select {
			case upstreamLines <- line:
			case <-stopScanner:
				return
			}
		}
		scanDone <- scanner.Err()
	}()
	defer func() {
		close(stopScanner)
		if closer, ok := r.(io.Closer); ok {
			_ = closer.Close()
		}
	}()
	for line := range upstreamLines {
		var releaseSeq uint64
		releaseRequest := false
		msg, err := jsonrpc.Decode(line)
		suppressAgentResponse := false
		var answeredCard *pendingCard
		if p.actionPairing {
			if responseID, invalid := invalidActionResponseID(line, err); invalid {
				if card, loaded := findActionPendingResponse(pending, responseID); loaded {
					if card.markLateReplySuppressed() {
						continue
					}
					if markErr := p.markActionUnknown(card, ""); markErr != nil {
						p.logger.Printf("AUDIT-ERROR agent=%s tool=%s: %v", p.agent, card.tool, markErr)
					}
					p.resolveAudit(card.auditSeq)
					line = jsonrpc.ErrorResponse(card.requestID, -32603, unverifiedToolResponseError)
					if p.requiredAudit && p.auditor.RequiredError() != nil {
						line = jsonrpc.ErrorResponse(card.requestID, -32603, auditAfterForwardError)
					}
					if writeErr := p.writeAgentLine(w, line); writeErr != nil {
						return writeErr
					}
					p.clearAuditFailure(card.auditSeq)
					card.markAnswered()
					select {
					case progress <- struct{}{}:
					default:
					}
					continue
				}
				if p.requestIDInUse(pending, responseID) {
					// An invalid duplicate for an action already received or buffered
					// must not create a second client-visible result.
					continue
				}
			}
		}
		if err == nil && msg.IsResponse() && msg.ID != nil {
			val, loaded := loadPendingResponse(pending, msg.ID)
			if !loaded && p.actionPairing && p.requestIDInUse(pending, msg.ID) {
				// A response for an action already received or buffered is a duplicate.
				// Do not let it reach the client as a second apparent result.
				continue
			}
			if loaded {
				// Check if this is a tools/list filter or a pending card state update.
				if toolListVal, ok := val.(toolsListSeq); ok {
					releaseSeq, releaseRequest = toolListVal.seq, true
					// tools/list response — filter it
					filtered := p.filterToolListResponse(line, toolListVal.seq)
					// Resolve the tools/list audits
					p.resolveAudit(toolListVal.seq)
					if filtered != nil {
						line = filtered
					}
				} else if cardVal, ok := val.(*pendingCard); ok {
					releaseSeq, releaseRequest = cardVal.auditSeq, true
					suppressAgentResponse = cardVal.actionID != "" && cardVal.lateReplySuppressed()
					// Pending forward — check JSON-RPC success before committing state or auditing
					validActionResponse := cardVal.actionID == "" || validToolResponseID(cardVal.requestID, line)
					if cardVal.actionID != "" && !validActionResponse {
						if suppressAgentResponse {
							pending.Store(string(cardVal.requestID), cardVal)
							continue
						}
						cardVal.markLateReplySuppressed()
						pending.Store(string(cardVal.requestID), cardVal)
						releaseRequest = false
						answeredCard = cardVal
					}
					shouldCommit := true
					if msg.Error != nil || !validActionResponse || suppressAgentResponse {
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
						p.updateCardState(cardVal.auditSeq, cardVal.stateTool, &cardVal.stateRefs)
					}
					if cardVal.actionID != "" {
						if validActionResponse {
							class, mcpIsError := actionResponseDetails(line)
							if err := p.observeAction(cardVal, "response_observed", "", class, mcpIsError); err != nil {
								p.logger.Printf("AUDIT-ERROR agent=%s tool=%s: %v", p.agent, cardVal.tool, err)
							}
						} else if err := p.markActionUnknown(cardVal, ""); err != nil {
							p.logger.Printf("AUDIT-ERROR agent=%s tool=%s: %v", p.agent, cardVal.tool, err)
						}
					}
					// Resolve audits unconditionally. Action rows flush per sequence;
					// unrelated request-order rows can still wait for earlier sequences.
					p.resolveAudit(cardVal.auditSeq)
					if p.requiredAudit && p.auditor.RequiredError() != nil {
						line = jsonrpc.ErrorResponse(cardVal.requestID, -32603, auditAfterForwardError)
					} else if cardVal.actionID != "" && !suppressAgentResponse &&
						(!validActionResponse || !p.auditSequenceDurable(cardVal.auditSeq)) {
						line = jsonrpc.ErrorResponse(cardVal.requestID, -32603, unverifiedToolResponseError)
					}
				}
			}
		}

		if !suppressAgentResponse {
			if writeErr := p.writeAgentLine(w, line); writeErr != nil {
				return writeErr
			}
			if answeredCard != nil {
				p.clearAuditFailure(answeredCard.auditSeq)
				answeredCard.markAnswered()
			}
		}
		if releaseRequest {
			p.clearAuditFailure(releaseSeq)
			p.releaseRequestID(releaseSeq)
		}
		select {
		case progress <- struct{}{}:
		default:
		}
	}
	scanErr := <-scanDone
	if len(finalizeOnEOF) > 0 && finalizeOnEOF[0] {
		cause := "upstream_exit"
		if scanErr != nil {
			cause = "transport_lost"
		}
		p.finishPendingActions(pending, cause)
		p.drainAudits()
	}
	return scanErr
}

func (p *StdioProxy) auditSequenceDurable(seq uint64) bool {
	p.auditMutex.Lock()
	_, failed := p.auditFailed[seq]
	flushed := seq < p.auditNext
	if !flushed && p.auditSequenceResolvedLocked(seq) {
		_, queued := p.auditTodo[seq]
		flushed = !queued
	}
	p.auditMutex.Unlock()
	return !failed && flushed && (!p.requiredAudit || p.auditor.RequiredError() == nil)
}

func (p *StdioProxy) clearAuditFailure(seq uint64) {
	p.auditMutex.Lock()
	delete(p.auditFailed, seq)
	p.auditMutex.Unlock()
}

func actionResponseDetails(line []byte) (string, *bool) {
	var members map[string]json.RawMessage
	if json.Unmarshal(line, &members) != nil {
		return "", nil
	}
	if _, hasError := members["error"]; hasError {
		return "jsonrpc_error", nil
	}
	var result map[string]json.RawMessage
	if json.Unmarshal(members["result"], &result) == nil {
		if raw, ok := result["isError"]; ok {
			var value bool
			if json.Unmarshal(raw, &value) == nil && (string(raw) == "true" || string(raw) == "false") {
				return "jsonrpc_result", &value
			}
		}
	}
	return "jsonrpc_result", nil
}

// filterToolListResponse replaces only result.tools, retaining extension fields,
// pagination and tool metadata without decoding numbers through float64.
func (p *StdioProxy) filterToolListResponse(line []byte, seq uint64) []byte {
	var resp map[string]json.RawMessage
	if json.Unmarshal(line, &resp) != nil || resp == nil {
		return jsonrpc.ErrorResponse(json.RawMessage("null"), -32603, "nockguard: invalid tools/list response")
	}
	invalid := func() []byte {
		return jsonrpc.ErrorResponse(resp["id"], -32603, "nockguard: invalid tools/list response")
	}
	if _, hasError := resp["error"]; hasError {
		if _, hasResult := resp["result"]; hasResult {
			return invalid()
		}
		return line
	}
	var result map[string]json.RawMessage
	if json.Unmarshal(resp["result"], &result) != nil || result == nil {
		return invalid()
	}
	var tools []map[string]json.RawMessage
	if json.Unmarshal(result["tools"], &tools) != nil || tools == nil {
		return invalid()
	}
	filtered := make([]map[string]json.RawMessage, 0, len(tools))
	for _, tool := range tools {
		var name string
		if json.Unmarshal(tool["name"], &name) != nil || name == "" {
			return invalid()
		}
		if dec := p.engine.Evaluate(p.agent, name); dec.Allowed() || dec.Verdict == policy.Ask {
			filtered = append(filtered, tool)
		} else {
			p.logger.Printf("HIDE agent=%s tool=%s reason=%q", p.agent, name, dec.Reason)
			p.appendAudit(seq, name, "hide", dec.Reason, nil)
		}
	}
	// All values below are validated RawMessages; marshaling cannot fail.
	result["tools"], _ = json.Marshal(filtered)
	resp["result"], _ = json.Marshal(result)
	out, _ := json.Marshal(resp)
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
// resolve a shadow name. Case variants of name are removed when an exact
// name is present. Canonicalize nested objects too: a typed upstream may
// merge duplicate objects that the validator's map decoder replaces. UseNumber
// preserves numeric literals without passing them through float64.
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
	var value map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(params))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		return "", nil, false
	}
	// The exact name is authoritative; remove aliases so typed upstreams
	// cannot select a different name through case-insensitive decoding.
	for key := range value {
		if key != "name" && strings.EqualFold(key, "name") {
			delete(value, key)
		}
	}
	out, err := json.Marshal(value)
	if err != nil {
		return "", nil, false
	}
	return name, out, true
}
