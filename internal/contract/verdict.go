package contract

import "strings"

// Outcome is the three-way result of asking whether a weakness is still
// there. Two outcomes would be enough only if re-checking could never fail.
//
// The zero value is OutcomeInconclusive, and that is a design decision rather
// than an accident of ordering. Every way of getting a verdict wrong in this
// program -- an unset field, a struct returned beside a non-nil error, a
// switch that falls through, a future outcome nobody mapped -- produces the
// zero value. If the zero value were "gone", each of those bugs would close a
// real vulnerability as fixed, and would do it silently, because a fix that
// was never verified and a fix that was verified look identical in the
// report. So the zero value is the one that blocks.
type Outcome string

const (
	// OutcomeInconclusive means the check could not say. It is a
	// verification failure. It is never a pass, and it is the zero value.
	OutcomeInconclusive Outcome = ""

	// OutcomeGone means a check that actually ran looked for this weakness
	// and did not find it.
	OutcomeGone Outcome = "gone"

	// OutcomeStillPresent means the weakness was observed again.
	OutcomeStillPresent Outcome = "still-present"
)

// String renders the outcome, naming the zero value explicitly so a log line
// never shows an empty field where a verdict should be.
func (o Outcome) String() string {
	if o == OutcomeInconclusive {
		return "inconclusive"
	}
	return string(o)
}

// Verdict is an Outcome with the evidence for it. The reason is not
// decoration: an inconclusive verdict is only actionable if it says what
// stopped it, and a "gone" verdict has to carry what looked and found
// nothing, because that sentence is what goes in the pull request.
//
// The fields are unexported so a Verdict cannot be assembled field by field.
// The only ways to make one are the three constructors below, which means
// Gone can never be reached without passing a reason for it.
type Verdict struct {
	outcome Outcome
	reason  string

	// checked names what did the looking: the check or command whose run is
	// the basis for the verdict. Empty for inconclusive.
	checked string
}

// Gone records that a named check ran and no longer reports the weakness.
func Gone(checkedBy, reason string) Verdict {
	return Verdict{outcome: OutcomeGone, reason: reason, checked: checkedBy}
}

// StillPresent records that the weakness was observed again.
func StillPresent(checkedBy, reason string) Verdict {
	return Verdict{outcome: OutcomeStillPresent, reason: reason, checked: checkedBy}
}

// Inconclusive records that the question could not be answered, and why.
func Inconclusive(reason string) Verdict {
	return Verdict{outcome: OutcomeInconclusive, reason: reason}
}

// Outcome returns the verdict outcome.
func (v Verdict) Outcome() Outcome { return v.outcome }

// Reason returns why.
func (v Verdict) Reason() string {
	if v.reason == "" && v.outcome == OutcomeInconclusive {
		// A Verdict{} that reached a report at all is a bug in this program,
		// so it says so rather than printing a blank.
		return "no verification was recorded for this finding, which is a bug in Vibe Giver; " +
			"treating it as unverified"
	}
	return v.reason
}

// CheckedBy names what produced the verdict, or the empty string when
// nothing did.
func (v Verdict) CheckedBy() string { return v.checked }

// ProvesFixed reports whether this verdict is allowed to count as a fix.
//
// Exactly one outcome qualifies. This method exists so that no site in the
// program writes its own version of the test: the brief rule is that
// inconclusive is a verification failure and never a pass, and a condition
// spelled out at each call site is a condition that eventually gets spelled
// as != OutcomeStillPresent by someone in a hurry -- which passes
// inconclusive.
func (v Verdict) ProvesFixed() bool { return v.outcome == OutcomeGone }

// String renders a verdict for a log or a report.
func (v Verdict) String() string {
	var b strings.Builder
	b.WriteString(v.outcome.String())
	if v.checked != "" {
		b.WriteString(" (checked by ")
		b.WriteString(v.checked)
		b.WriteString(")")
	}
	if r := v.Reason(); r != "" {
		b.WriteString(": ")
		b.WriteString(r)
	}
	return b.String()
}

// Gate is the conjunction of every verification a fix must pass.
//
// It is an AND over verdicts in which inconclusive loses, which is the whole
// of the brief fourth section expressed once. A Gate with no verdicts in it
// does not pass: a fix that was never checked is not a fix, and an empty
// slice is the shape that bug takes.
type Gate struct {
	name     string
	verdicts []namedVerdict
}

type namedVerdict struct {
	gate    string
	verdict Verdict
}

// NewGate starts a verification gate for one finding.
func NewGate(name string) *Gate { return &Gate{name: name} }

// Record adds one gate result.
func (g *Gate) Record(gateName string, v Verdict) {
	g.verdicts = append(g.verdicts, namedVerdict{gate: gateName, verdict: v})
}

// Passed reports whether every recorded gate proved the fix, and there was at
// least one.
func (g *Gate) Passed() bool {
	if len(g.verdicts) == 0 {
		return false
	}
	for _, nv := range g.verdicts {
		if !nv.verdict.ProvesFixed() {
			return false
		}
	}
	return true
}

// FirstFailure returns the first gate that did not prove the fix, which is
// what the fix_failed reason is written from.
func (g *Gate) FirstFailure() (gateName string, v Verdict, ok bool) {
	if len(g.verdicts) == 0 {
		return "", Inconclusive("no verification gate was run at all"), true
	}
	for _, nv := range g.verdicts {
		if !nv.verdict.ProvesFixed() {
			return nv.gate, nv.verdict, true
		}
	}
	return "", Verdict{}, false
}

// Results returns every gate result in the order recorded, for the pull
// request body and the run log.
func (g *Gate) Results() []struct {
	Gate    string
	Verdict Verdict
} {
	out := make([]struct {
		Gate    string
		Verdict Verdict
	}, 0, len(g.verdicts))
	for _, nv := range g.verdicts {
		out = append(out, struct {
			Gate    string
			Verdict Verdict
		}{Gate: nv.gate, Verdict: nv.verdict})
	}
	return out
}
