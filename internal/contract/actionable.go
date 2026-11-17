package contract

import (
	"fmt"
	"sort"
)

// Disposition is what Giver intends to do with one finding before it has
// tried anything.
type Disposition string

const (
	// DispositionAttempt means the finding is open, Killer marked it
	// auto-fixable, and this build has a route to verify it.
	DispositionAttempt Disposition = "attempt"

	// DispositionHumanRequired means Killer said a human has to act. A
	// leaked credential is the canonical case: the only real remediation is
	// rotating it and scrubbing history, and an edit that hides it reads as
	// a fix while the credential stays valid.
	DispositionHumanRequired Disposition = "human_required"

	// DispositionNotOpen means the finding was already fixed, accepted or
	// judged a false positive, so it is not Giver's to touch.
	DispositionNotOpen Disposition = "not_open"
)

// Triage is the decision for one finding, with the reason it was reached.
type Triage struct {
	Finding     Finding
	Disposition Disposition
	Reason      string
	Route       VerificationRoute
}

// TriageDocument sorts a document findings into what Giver may attempt and
// what it must hand to a person.
//
// The two conditions for attempting anything come straight from the brief:
// status open AND remediation.fixable_by_giver. Both are required, and
// neither is inferred. In the 53-finding scan this package is tested against,
// all 53 are open and all 53 are marked fixable -- so a filter that silently
// matched everything would look identical to a correct one on that input,
// which is why the test also feeds it findings that must be rejected.
func TriageDocument(d *Document) []Triage {
	out := make([]Triage, 0, len(d.Findings))
	for _, f := range d.Findings {
		out = append(out, TriageFinding(f))
	}
	return out
}

// TriageFinding decides one finding.
func TriageFinding(f Finding) Triage {
	switch {
	case f.Status != StatusOpen:
		return Triage{
			Finding:     f,
			Disposition: DispositionNotOpen,
			Reason: fmt.Sprintf(
				"status is %q, not %q; Vibe Giver only acts on open findings",
				f.Status, StatusOpen),
		}

	case !f.Remediation.FixableByGiver:
		reason := f.Remediation.HumanRequiredReason
		if reason == "" {
			reason = "Killer marked this not auto-fixable and gave no reason, which is itself worth reporting"
		}
		return Triage{
			Finding:     f,
			Disposition: DispositionHumanRequired,
			Reason:      reason,
		}

	default:
		return Triage{
			Finding:     f,
			Disposition: DispositionAttempt,
			Reason:      "status is open and Killer marked it auto-fixable",
			Route:       RouteFor(f),
		}
	}
}

// Attemptable returns only the findings Giver may try to fix, ordered by
// Killer rank descending so the worst is attempted first; rank ties fall back
// to severity and then finding id for a stable order.
func Attemptable(t []Triage) []Triage {
	var out []Triage
	for _, x := range t {
		if x.Disposition == DispositionAttempt {
			out = append(out, x)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i].Finding, out[j].Finding
		if a.Rank != b.Rank {
			return a.Rank > b.Rank
		}
		aw, _ := a.Severity.Weight()
		bw, _ := b.Severity.Weight()
		if aw != bw {
			return aw > bw
		}
		return a.FindingID < b.FindingID
	})
	return out
}

// HumanRequired returns the findings that need a person, for the report in
// the brief seventh section.
func HumanRequired(t []Triage) []Triage {
	var out []Triage
	for _, x := range t {
		if x.Disposition == DispositionHumanRequired {
			out = append(out, x)
		}
	}
	return out
}

// NonCoverageReport is what a run could not speak to, which the brief insists
// is never read as clean. It is reported alongside the findings so that an
// operator looking at "Giver fixed 4 of 4" also sees that eleven checks never
// ran.
type NonCoverageReport struct {
	Trust   CoverageTrust
	Skipped []SkippedCheck
	Failed  []FailedCheck
}

// NonCoverage summarizes what the run did not establish.
func (d *Document) NonCoverage() NonCoverageReport {
	return NonCoverageReport{
		Trust:   d.Trust(),
		Skipped: d.Skipped,
		Failed:  d.Failed,
	}
}

// Silent reports whether the run established full coverage. A run with
// nothing skipped and nothing failed on a 1.1-or-newer envelope is the only
// case in which an absence of findings means anything at all.
func (r NonCoverageReport) Silent() bool {
	return r.Trust == CoverageReported && len(r.Skipped) == 0 && len(r.Failed) == 0
}

// EstablishesClean reports whether this run is entitled to the conclusion
// that there is nothing here to fix.
//
// Both halves are required, and the second is the one that is easy to omit:
// no finding Giver would act on, AND a run that actually looked. Zero
// findings on its own means nothing.
//
// This is not hypothetical tidiness. The first CI run of the round-trip job
// measured it: on a bare runner with no Semgrep, no osv-scanner and no
// gitleaks, Vibe Killer scanned a deliberately vulnerable Flask fixture,
// reported "No findings from the checks that ran", listed all fourteen checks
// as skipped, and exited 0 -- its success code. Everything about that output
// reads as a clean bill except the coverage section. A consumer that gated on
// the finding count and the exit code would have declared a known-vulnerable
// application secure, on real infrastructure, with nothing misconfigured.
func (d *Document) EstablishesClean() bool {
	if !d.NonCoverage().Silent() {
		return false
	}
	for _, t := range TriageDocument(d) {
		if t.Disposition != DispositionNotOpen {
			return false
		}
	}
	return true
}

// Summary is one line for the top of a report.
func (r NonCoverageReport) Summary() string {
	if r.Trust == CoverageUnknown {
		return "this run envelope cannot report coverage, so nothing is known about what was not checked"
	}
	if r.Silent() {
		return "every check in this run produced results"
	}
	return fmt.Sprintf("%d check(s) did not run and %d failed, so nothing is known about what they cover",
		len(r.Skipped), len(r.Failed))
}
