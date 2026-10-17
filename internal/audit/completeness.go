package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// RunAssessment describes the recorded observation stream for one run. It is
// independent of the integrity verdict; callers must verify the same trail
// snapshot and its checkpoint before accepting an assessment.
type RunAssessment struct {
	RunID   string `json:"run_id,omitempty"`
	Verdict string `json:"verdict"`
	Reason  string `json:"reason,omitempty"`
}

type actionState struct {
	dispatch  bool
	terminal  bool
	unknown   bool
	decisions int
	late      bool
}

type runState struct {
	assessment RunAssessment
	count      uint64
	head       string
	open       bool
	closed     bool
	latest     time.Time
	future     bool
	broken     bool
	incomplete bool
	actions    map[string]*actionState
}

// AssessRuns analyzes a previously verified, fully checkpointed trail snapshot.
// A false checkpointed argument or an unsigned row yields UNASSESSABLE; this
// function never turns failed integrity verification into a completeness claim.
func AssessRuns(trail []byte, checkpointed bool, now time.Time) []RunAssessment {
	runs := make(map[string]*runState)
	legacy := false
	scan := bufio.NewScanner(bytes.NewReader(trail))
	scan.Buffer(make([]byte, 64*1024), scanBufferCap)
	for scan.Scan() {
		line := bytes.TrimSpace(scan.Bytes())
		if len(line) == 0 {
			continue
		}
		var ev Event
		if err := json.Unmarshal(line, &ev); err != nil || ev.SchemaVersion != 2 {
			legacy = true
			continue
		}
		run := runs[ev.RunID]
		if run == nil {
			run = &runState{assessment: RunAssessment{RunID: ev.RunID}, actions: make(map[string]*actionState)}
			runs[ev.RunID] = run
		}
		if ev.Sig == "" || validateAuditEvent(ev) != nil || run.closed || ev.RunSeq != run.count+1 {
			run.broken = true
		}
		if run.count == 0 && (ev.RecordType != "run" || ev.RunEvent != "open") {
			run.broken = true
		}
		if ev.RecordType == "run" {
			switch ev.RunEvent {
			case "open":
				if run.open {
					run.broken = true
				}
				run.open = true
				fallthrough
			case "heartbeat":
				if !run.open || run.closed {
					run.broken = true
				}
				stamp, err := time.Parse(time.RFC3339, ev.Time)
				if err != nil {
					run.broken = true
				} else {
					if stamp.After(now.UTC().Add(30 * time.Second)) {
						run.future = true
					}
					run.latest = stamp
				}
			case "close":
				if !run.open || ev.RunCount != run.count || ev.RunHead != run.head {
					run.broken = true
				}
				run.closed = true
			default:
				run.broken = true
			}
		} else if ev.ActionID != "" {
			action := run.actions[ev.ActionID]
			if action == nil {
				action = &actionState{}
				run.actions[ev.ActionID] = action
			}
			if ev.RecordType == "decision" {
				action.decisions++
				if action.terminal || (ev.Decision == "dispatch" && action.dispatch) {
					run.broken = true
				}
				if ev.Decision == "dispatch" {
					action.dispatch = true
				}
			} else if ev.RecordType == "action_observation" {
				if ev.Observation == "late_response_observed" {
					if !action.unknown || action.late {
						run.broken = true
					}
					action.late = true
				} else {
					if action.decisions == 0 || action.terminal || (ev.Observation == "not_forwarded") == action.dispatch {
						run.broken = true
					}
					action.terminal = true
					action.unknown = ev.Observation == "outcome_unknown"
				}
			}
		} else if ev.RecordType != "decision" || (ev.Decision != "method-allow" && ev.Decision != "method-deny" && ev.Decision != "hide") {
			run.broken = true
		}
		run.count++
		run.head = ev.Sig
	}
	if scan.Err() != nil {
		checkpointed = false
	}
	if len(runs) == 0 {
		if !checkpointed {
			return []RunAssessment{{Verdict: "UNASSESSABLE", Reason: "trail is not verified and checkpointed"}}
		}
		return []RunAssessment{{Verdict: "UNVERIFIED", Reason: "legacy or empty trail has no run lifecycle"}}
	}
	ids := make([]string, 0, len(runs))
	for id := range runs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result := make([]RunAssessment, 0, len(ids))
	for _, id := range ids {
		run := runs[id]
		for _, action := range run.actions {
			if !action.terminal {
				run.incomplete = true
			}
		}
		a := run.assessment
		switch {
		case !checkpointed || legacy:
			a.Verdict, a.Reason = "UNASSESSABLE", "trail is not exclusively verified and checkpointed v2 rows"
		case run.broken:
			a.Verdict, a.Reason = "BROKEN", "run structure or action transitions are invalid"
		case run.future:
			a.Verdict, a.Reason = "UNASSESSABLE", "open or heartbeat is more than 30 seconds in the future"
		case run.closed && run.incomplete:
			a.Verdict, a.Reason = "INCOMPLETE", "recorded action lacks a terminal observation"
		case run.closed:
			a.Verdict, a.Reason = "LIMITED", "signed recorded observation stream is internally complete"
		case now.UTC().Sub(run.latest) >= 90*time.Second:
			a.Verdict, a.Reason = "INCOMPLETE", "run has no close and its last heartbeat is stale; abnormal end or truncation is unknown"
		default:
			a.Verdict, a.Reason = "IN_PROGRESS", "run has no close and its last heartbeat is recent"
		}
		if !run.open {
			a.Verdict, a.Reason = "BROKEN", fmt.Sprintf("run %s has no open", id)
		}
		result = append(result, a)
	}
	return result
}
