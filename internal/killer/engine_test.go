package killer

import (
	"strings"
	"testing"

	"github.com/rohitanakiya/Vibe-Giver/internal/contract"
)

func sastFinding() contract.Finding {
	return contract.Finding{
		SchemaVersion: contract.FindingSchemaVersion,
		FindingID:     "vk-47f8f97a0b2c",
		RuleID:        "misconfig.debug-mode-enabled",
		Source:        contract.SourceSAST,
		Severity:      contract.SeverityCritical,
		Status:        contract.StatusOpen,
		Remediation:   contract.Remediation{Guidance: "g", FixableByGiver: true},
	}
}

// TestGuardStaticAbsence is the guard against the false clean that happened
// for real: a Semgrep other than the pinned one reported having run and found
// nothing on a deliberately vulnerable fixture, which read as a fix.
func TestGuardStaticAbsence(t *testing.T) {
	gone := contract.Gone("engine.semgrep in run r2", "engine.semgrep ran and no longer reports it")
	pinned := "1.185.0"

	t.Run("a mismatched engine cannot prove an absence", func(t *testing.T) {
		fid := EngineFidelity{
			Engine: contract.CheckSemgrep, Installed: "1.200.0", Expected: pinned,
			Known: true, Matches: false,
		}
		got := GuardStaticAbsence(sastFinding(), gone, fid)
		if got.ProvesFixed() {
			t.Fatalf("a mismatched engine proved a fix: %s", got)
		}
		if !strings.Contains(got.Reason(), "1.200.0") || !strings.Contains(got.Reason(), pinned) {
			t.Errorf("the reason must name both versions: %q", got.Reason())
		}
	})

	t.Run("the pinned engine can", func(t *testing.T) {
		// Without this, the test above would pass for a guard that rejected
		// everything, and Giver could never prove a static fix at all.
		fid := EngineFidelity{
			Engine: contract.CheckSemgrep, Installed: pinned, Expected: pinned,
			Known: true, Matches: true,
		}
		if got := GuardStaticAbsence(sastFinding(), gone, fid); !got.ProvesFixed() {
			t.Fatalf("the pinned engine was not allowed to prove a fix: %s", got)
		}
	})

	t.Run("presence is never downgraded", func(t *testing.T) {
		// A reported finding is a positive observation: the pack evidently
		// matched, and that does not depend on the engine being the pinned
		// one. Only silence can be faked by a quiet engine.
		still := contract.StillPresent("engine.semgrep", "the finding is still reported")
		fid := EngineFidelity{Engine: contract.CheckSemgrep, Installed: "1.200.0", Expected: pinned, Known: true}
		if got := GuardStaticAbsence(sastFinding(), still, fid); got.Outcome() != contract.OutcomeStillPresent {
			t.Errorf("a present finding was altered: %s", got)
		}
	})

	t.Run("an inconclusive verdict stays inconclusive", func(t *testing.T) {
		inc := contract.Inconclusive("the check was skipped")
		fid := EngineFidelity{Engine: contract.CheckSemgrep, Installed: pinned, Expected: pinned, Known: true, Matches: true}
		if got := GuardStaticAbsence(sastFinding(), inc, fid); got.ProvesFixed() {
			t.Error("an inconclusive verdict was promoted")
		}
	})

	t.Run("a dynamic finding is not affected", func(t *testing.T) {
		// The guard is about the static pack. A dast finding is proven by a
		// request against a running instance, which Semgrep has nothing to
		// do with, so downgrading it would block fixes for no reason.
		f := sastFinding()
		f.Source = contract.SourceDAST
		f.RuleID = "misconfig.cors-reflection"
		fid := EngineFidelity{Engine: contract.CheckSemgrep, Installed: "1.200.0", Expected: pinned, Known: true}
		if got := GuardStaticAbsence(f, gone, fid); !got.ProvesFixed() {
			t.Errorf("a dynamic finding was downgraded by a Semgrep mismatch: %s", got)
		}
	})

	t.Run("an undeterminable version does not overturn a run", func(t *testing.T) {
		// `semgrep --version` failing while Semgrep works is the one residual
		// gap, and it is a caveat rather than grounds to reject a scan that
		// evidently ran. Absent Semgrep is covered already: Killer records a
		// skip, and the coverage join reads that as inconclusive.
		fid := EngineFidelity{Engine: contract.CheckSemgrep, Expected: pinned, Known: false}
		if got := GuardStaticAbsence(sastFinding(), gone, fid); !got.ProvesFixed() {
			t.Errorf("an unreadable version overturned a run that worked: %s", got)
		}
		if !strings.Contains(fid.Reason(), "could not be determined") {
			t.Errorf("the state should be reported: %q", fid.Reason())
		}
	})
}

// TestFidelityAgainstTheRealToolchain reports what this machine has. It does
// not fail on a mismatch -- that is the operator's environment, not a bug in
// this package -- but it names it, so a surprising local result has an
// explanation on screen rather than in a comment.
func TestFidelityAgainstTheRealToolchain(t *testing.T) {
	fid := CheckSemgrepFidelity()
	t.Logf("semgrep: installed=%q expected=%q known=%v matches=%v",
		fid.Installed, fid.Expected, fid.Known, fid.Matches)

	if fid.Expected == "" {
		t.Error("the vendoring stamp records no pinned Semgrep version, so the guard cannot work")
	}
	if fid.Installed != "" && !fid.Known {
		t.Error("a version was found but not parsed")
	}
}

// TestSameChecksRan guards gate (b)'s precondition in both directions.
func TestSameChecksRan(t *testing.T) {
	withSkip := &contract.Document{
		SchemaVersion: contract.DocumentSchemaVersion, RunID: "a",
		Skipped: []contract.SkippedCheck{{CheckID: "engine.osv-scanner", Layer: "deps", Reason: "deselected"}},
	}
	sameSkip := &contract.Document{
		SchemaVersion: contract.DocumentSchemaVersion, RunID: "b",
		Skipped: []contract.SkippedCheck{{CheckID: "engine.osv-scanner", Layer: "deps", Reason: "deselected"}},
	}
	differentSkip := &contract.Document{
		SchemaVersion: contract.DocumentSchemaVersion, RunID: "c",
		Skipped: []contract.SkippedCheck{
			{CheckID: "engine.osv-scanner", Layer: "deps", Reason: "deselected"},
			{CheckID: "engine.semgrep", Layer: "static", Reason: "not installed"},
		},
	}

	if ok, why := SameChecksRan(withSkip, sameSkip); !ok {
		t.Errorf("identical coverage reported as different: %s", why)
	}
	if ok, _ := SameChecksRan(withSkip, differentSkip); ok {
		t.Error("a scan that skipped an extra check was treated as comparable")
	}
	if ok, _ := SameChecksRan(nil, sameSkip); ok {
		t.Error("a missing document was treated as comparable")
	}
}

// TestNewFindingsComparesByIdentity checks gate (b) itself.
func TestNewFindingsComparesByIdentity(t *testing.T) {
	a := sastFinding()
	b := sastFinding()
	b.FindingID = "vk-bbbbbbbbbbbb"

	before := &contract.Document{Findings: []contract.Finding{a}}
	after := &contract.Document{Findings: []contract.Finding{a, b}}

	got := NewFindings(before, after)
	if len(got) != 1 || got[0].FindingID != "vk-bbbbbbbbbbbb" {
		t.Fatalf("NewFindings = %+v", got)
	}

	// A finding that moved lines keeps its id, because finding_id excludes
	// line numbers on purpose, so it must not read as new.
	moved := a
	moved.Location.Line = a.Location.Line + 40
	if got := NewFindings(before, &contract.Document{Findings: []contract.Finding{moved}}); len(got) != 0 {
		t.Errorf("a finding that only moved was reported as new: %+v", got)
	}
}
