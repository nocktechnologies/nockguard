package evidence

import "github.com/nocktechnologies/nockguard/internal/audit"

// Framework identifies a compliance control set. Adding a new framework is a
// table edit here (a new Framework value plus its entry in frameworks), never a
// code change in evidence.go or render.go — the generator is data-driven.
type Framework string

const (
	// FrameworkSOC2 is the only framework with real control mappings in this
	// first cut. GDPR / PCI / HIPAA are present as stubs (recognized names with
	// empty control sets) so wiring a real map later is purely additive.
	FrameworkSOC2  Framework = "soc2"
	FrameworkGDPR  Framework = "gdpr"
	FrameworkPCI   Framework = "pci"
	FrameworkHIPAA Framework = "hipaa"
)

// Control is one mappable control within a framework. Decisions and Tools are
// the matchers used to bucket audit Events into this control: an Event belongs
// to the control if its Decision is in Decisions (when non-empty) AND its Tool
// is in Tools (when non-empty). An empty matcher set means "match any" for that
// dimension, so a control keyed purely on decision type ignores the tool, and
// vice versa.
type Control struct {
	ID          string   // e.g. "CC6.1"
	Name        string   // human-readable control name
	Description string   // what this control attests, in plain language
	Decisions   []string // audit decision values that evidence this control (empty = any)
	Tools       []string // audit tool names that evidence this control (empty = any)
}

// FrameworkDef is the data definition of a framework: its display name and its
// ordered controls. Order is preserved in the rendered pack.
type FrameworkDef struct {
	ID       Framework
	Name     string
	Controls []Control
}

// frameworks is the canonical, data-only registry. SOC2 is fully mapped; the
// others are intentional stubs (empty Controls) so KnownFramework recognizes
// them and a future PR can fill the table without touching any logic.
var frameworks = map[Framework]FrameworkDef{
	FrameworkSOC2: {
		ID:   FrameworkSOC2,
		Name: "SOC 2 (Trust Services Criteria)",
		Controls: []Control{
			{
				ID:          "CC6.1",
				Name:        "Logical Access Controls",
				Description: "The entity implements logical access security measures to protect against threats from sources outside its system boundaries. Evidenced by access-control decisions: tool calls denied or blocked by policy, and approvals explicitly granted by a human.",
				// Access-control decisions: the firewall denying/blocking a call, or a
				// human approving a gated one. These are the access-decision events.
				Decisions: []string{"deny", "block", "approval-granted", "approval-denied"},
			},
			{
				ID:          "CC7.2",
				Name:        "System Monitoring",
				Description: "The entity monitors system components for anomalies and acts on them. Evidenced by the completeness of the signed, tamper-evident audit trail itself: every tool-call decision (allow, deny, block, rate-limit, hide) is monitored and recorded.",
				// Monitoring / audit-trail completeness: ANY recorded decision is
				// evidence the monitoring control is operating. Empty matchers = match
				// all entries.
			},
			{
				ID:          "CC8.1",
				Name:        "Change Management",
				Description: "The entity authorizes, designs, develops, tests, and approves changes before implementation. Evidenced by rate-limit and hide enforcement that constrains agent behavior, plus the human approval decisions gating sensitive (change-causing) tool calls.",
				Decisions:   []string{"ratelimit", "hide", "approval-granted", "approval-denied"},
			},
		},
	},
	// Stubs — recognized framework names with no mappings yet. Filling these is a
	// follow-on data edit (add Controls), not a code change.
	FrameworkGDPR:  {ID: FrameworkGDPR, Name: "GDPR (General Data Protection Regulation)"},
	FrameworkPCI:   {ID: FrameworkPCI, Name: "PCI DSS (Payment Card Industry Data Security Standard)"},
	FrameworkHIPAA: {ID: FrameworkHIPAA, Name: "HIPAA (Health Insurance Portability and Accountability Act)"},
}

// KnownFramework reports whether name (case-insensitive already normalized by
// the caller) is a framework the generator recognizes — including stubs.
func KnownFramework(f Framework) bool {
	_, ok := frameworks[f]
	return ok
}

// frameworkDef returns the definition for f and whether it is known.
func frameworkDef(f Framework) (FrameworkDef, bool) {
	d, ok := frameworks[f]
	return d, ok
}

// matches reports whether an audit Event evidences this control. An empty
// Decisions or Tools slice means that dimension matches anything; a non-empty
// slice requires membership. Both dimensions must match.
func (c Control) matches(ev audit.Event) bool {
	if len(c.Decisions) > 0 && !contains(c.Decisions, ev.Decision) {
		return false
	}
	if len(c.Tools) > 0 && !contains(c.Tools, ev.Tool) {
		return false
	}
	return true
}

func contains(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}
