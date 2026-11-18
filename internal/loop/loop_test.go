package loop

import (
	"strings"
	"testing"

	"github.com/rohitanakiya/Vibe-Giver/internal/contract"
	"github.com/rohitanakiya/Vibe-Giver/internal/fix"
)

func doc(runID string, findings []contract.Finding, skipped []contract.SkippedCheck) *contract.Document {
	return &contract.Document{
		SchemaVersion: contract.DocumentSchemaVersion,
		RunID:         runID,
		Findings:      findings,
		Skipped:       skipped,
	}
}

func finding(id, rule string) contract.Finding {
	return contract.Finding{
		SchemaVersion: contract.FindingSchemaVersion,
		FindingID:     id,
		RuleID:        rule,
		Source:        contract.SourceSAST,
		Severity:      contract.SeverityHigh,
		Status:        contract.StatusOpen,
		Remediation:   contract.Remediation{Guidance: "g", FixableByGiver: true},
	}
}

var semgrepSkipped = []contract.SkippedCheck{
	{CheckID: "engine.osv-scanner", Layer: "deps", Reason: "deselected by --only"},
}

// TestNoNewFindingsGate covers gate (b) in both directions, and the two ways
// it must refuse to answer.
func TestNoNewFindingsGate(t *testing.T) {
	a := finding("vk-aaaaaaaaaaaa", "misconfig.debug-mode-enabled")
	b := finding("vk-bbbbbbbbbbbb", "injection.sql-string-built-from-input")
	c := finding("vk-cccccccccccc", "crypto.predictable-token")

	t.Run("the fix removed one finding and added nothing", func(t *testing.T) {
		before := doc("r1", []contract.Finding{a, b}, semgrepSkipped)
		after := doc("r2", []contract.Finding{b}, semgrepSkipped)
		v := noNewFindings(before, after)
		if !v.ProvesFixed() {
			t.Fatalf("got %s", v)
		}
	})

	t.Run("the fix introduced something", func(t *testing.T) {
		before := doc("r1", []contract.Finding{a}, semgrepSkipped)
		after := doc("r2", []contract.Finding{c}, semgrepSkipped)
		v := noNewFindings(before, after)
		if v.Outcome() != contract.OutcomeStillPresent {
			t.Fatalf("got %s", v)
		}
		if !strings.Contains(v.Reason(), "vk-cccccccccccc") {
			t.Errorf("the reason must name what appeared: %q", v.Reason())
		}
	})

	t.Run("the two scans did not cover the same checks", func(t *testing.T) {
		// A baseline that ran more checks than the after-scan would report
		// everything the after-scan never looked for as fixed. Refusing is
		// the only honest answer, and it has to be inconclusive rather than
		// a pass.
		before := doc("r1", []contract.Finding{a}, nil)
		after := doc("r2", nil, []contract.SkippedCheck{
			{CheckID: "engine.semgrep", Layer: "static", Reason: "semgrep is not installed"},
		})
		v := noNewFindings(before, after)
		if v.Outcome() != contract.OutcomeInconclusive {
			t.Fatalf("got %s", v)
		}
		if !strings.Contains(v.Reason(), "not meaningful") {
			t.Errorf("reason = %q", v.Reason())
		}
	})

	t.Run("the reproduce route answers nothing about this", func(t *testing.T) {
		// Reproduce re-runs one check and returns no document, so it cannot
		// speak to what else the change did. Saying so beats implying the
		// question was asked.
		v := noNewFindings(nil, nil)
		if v.ProvesFixed() {
			t.Fatal("a missing comparison proved a fix")
		}
		if !strings.Contains(v.Reason(), "focused re-scan is needed") {
			t.Errorf("reason = %q", v.Reason())
		}
	})
}

// TestOnlyFixedCountsAsFixed guards the status vocabulary. Four of the six
// statuses mean the weakness is still there.
func TestOnlyFixedCountsAsFixed(t *testing.T) {
	cases := map[Status]bool{
		StatusFixed:               true,
		StatusAlreadyResolved:     false,
		StatusBlockedUnverifiable: false,
		StatusFixFailed:           false,
		StatusHumanRequired:       false,
		StatusSkipped:             false,
	}
	for st, want := range cases {
		o := &Outcome{Status: st}
		if got := o.Fixed(); got != want {
			t.Errorf("%s: Fixed() = %v, want %v", st, got, want)
		}
	}
}

// TestHumanActionReportCoversEverythingStillOpen checks that nothing open
// falls out of the report. A finding that is silently absent reads as handled.
func TestHumanActionReportCoversEverythingStillOpen(t *testing.T) {
	rep := &Report{Outcomes: []Outcome{
		{FindingID: "vk-000000000001", Title: "fixed one", Status: StatusFixed},
		{FindingID: "vk-000000000002", Title: "already ok", Status: StatusAlreadyResolved},
		{FindingID: "vk-000000000003", Title: "a leaked key", Status: StatusHumanRequired,
			Category: string(contract.CategorySecretsExposure), Reason: "a credential must be rotated"},
		{FindingID: "vk-000000000004", Title: "cannot re-check", Status: StatusBlockedUnverifiable,
			Reason: "the endpoint layer needs a target"},
		{FindingID: "vk-000000000005", Title: "tried and failed", Status: StatusFixFailed,
			Reason: "tests went red"},
		{FindingID: "vk-000000000006", Title: "no strategy", Status: StatusSkipped,
			Reason: "no strategy for idor.missing-ownership-check"},
	}}

	got := HumanActionReport(rep)

	for _, id := range []string{"vk-000000000003", "vk-000000000004", "vk-000000000005", "vk-000000000006"} {
		if !strings.Contains(got, id) {
			t.Errorf("%s is still open and is missing from the human-action report", id)
		}
	}
	// The two that need nothing must not be in it, or the report becomes
	// noise and stops being read.
	for _, id := range []string{"vk-000000000001", "vk-000000000002"} {
		if strings.Contains(got, id) {
			t.Errorf("%s needs no human action and should not be listed", id)
		}
	}

	// A leaked credential gets rotation-first instructions, never a code
	// edit. Rotation has to come before the code change: until the
	// credential is rotated, the old value is compromised regardless.
	rotate := strings.Index(got, "Rotate the credential")
	replace := strings.Index(got, "Replace the literal")
	switch {
	case rotate < 0:
		t.Error("the secrets entry does not tell the operator to rotate the credential")
	case replace < 0:
		t.Error("the secrets entry does not mention replacing the literal")
	case rotate > replace:
		t.Error("the secrets entry puts the code change before the rotation")
	}
	if !strings.Contains(got, "filter-repo") {
		t.Error("the secrets entry does not say how to purge history")
	}
}

// TestHumanActionReportIsEmptyWhenNothingNeedsAPerson keeps the test above
// from passing for a function that always produces text.
func TestHumanActionReportIsEmptyWhenNothingNeedsAPerson(t *testing.T) {
	rep := &Report{Outcomes: []Outcome{
		{FindingID: "vk-000000000001", Status: StatusFixed},
		{FindingID: "vk-000000000002", Status: StatusAlreadyResolved},
	}}
	if got := HumanActionReport(rep); got != "" {
		t.Errorf("expected no report, got:\n%s", got)
	}
}

// TestPullRequestBodyCarriesBothProofs checks the review packet says what it
// measured.
//
// A security patch that arrives with only the after-proof asks the reviewer
// to take the tool word for the existence of the problem as well as for the
// fix, and a patch that hides what it could not check invites a false
// impression of how much was proven.
func TestPullRequestBodyCarriesBothProofs(t *testing.T) {
	f := finding("vk-47f8f97a0b2c", "misconfig.debug-mode-enabled")
	f.Title = "Debug mode is enabled"
	f.CWE = "CWE-489"
	f.Category = contract.CategoryMisconfiguration
	f.Location = contract.Location{Type: contract.LocationCode, File: "app.py", Line: 277}
	f.Evidence.Summary = "Debug mode is enabled."
	f.Remediation.RootCauseHint = "A development convenience is set unconditionally."

	out := &Outcome{
		FindingID: f.FindingID,
		Status:    StatusFixed,
		Rationale: "Replaced debug=True with a value read from the environment.",
		RootCause: "A development convenience was set unconditionally.",
		Caveats:   []string{"no test suite was found in this project"},
		VerificationResults: []GateResult{
			{Gate: "still-reproduces", Outcome: "still-present", Reason: "reported before the change"},
			{Gate: "vulnerability-gone", Outcome: "gone", Reason: "engine.semgrep ran and no longer reports it"},
			{Gate: "no-new-findings", Outcome: "gone", Reason: "nothing appeared that was not there"},
			{Gate: "build", Outcome: "gone", Reason: "the changed Python still compiles"},
		},
	}
	before := contract.StillPresent("engine.semgrep in run r1", "the finding was reported before any change")

	body := PullRequestBody(f, out, before, "--- a/app.py\n+++ b/app.py\n")

	for _, want := range []string{
		"## What was wrong",
		"## Proof it was real",
		"## Proof it is fixed",
		"### What was not verified",
		"CWE-489",
		"`app.py:277`",
		"no test suite was found",
		"does not merge",
		"`inconclusive` result is a failure",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the pull request body is missing %q", want)
		}
	}

	// The before-proof has to come before the after-proof, or the reviewer
	// reads the conclusion first.
	if strings.Index(body, "## Proof it was real") > strings.Index(body, "## Proof it is fixed") {
		t.Error("the after-proof is presented before the before-proof")
	}
}

// TestCommitMessageHasNoToolTrailers is a repository convention with teeth:
// on Vibe Killer, three commits carrying a co-author trailer were force-pushed
// away and GitHub kept counting the orphaned commits, so the repository still
// listed two contributors. Giver writes commit messages into other people
// repositories, so it must not put one there either.
func TestCommitMessageHasNoToolTrailers(t *testing.T) {
	f := finding("vk-47f8f97a0b2c", "misconfig.debug-mode-enabled")
	f.Title = "Debug mode is enabled"
	f.Evidence.Summary = "Debug mode is enabled."

	out := &Outcome{
		VerificationResults: []GateResult{{Gate: "vulnerability-gone", Outcome: "gone"}},
		Caveats:             []string{"no test suite was found"},
	}
	msg := CommitMessage(f, out, fixProposal())

	for _, forbidden := range []string{"Co-Authored-By", "Co-authored-by", "Generated with", "🤖"} {
		if strings.Contains(msg, forbidden) {
			t.Errorf("the commit message contains %q", forbidden)
		}
	}
	// It should still say where the change came from, in prose.
	if !strings.Contains(msg, "Vibe Giver") {
		t.Error("the commit message does not say Vibe Giver generated it")
	}
	if !strings.Contains(msg, "Verified, not assumed") || !strings.Contains(msg, "Not verified") {
		t.Error("the commit message must record both what was verified and what was not")
	}
	if !strings.HasPrefix(msg, "Fix Debug mode is enabled (vk-47f8f97a0b2c)") {
		t.Errorf("subject line = %q", strings.SplitN(msg, "\n", 2)[0])
	}
}

// fixProposal is a minimal proposal for the message tests.
func fixProposal() *fix.Proposal {
	return &fix.Proposal{
		Strategy:  "misconfig.debug-mode/env-driven-default-off",
		Rationale: "Replaced debug=True with a value read from the environment, defaulting to off.",
		RootCause: "A development convenience was set unconditionally in the source.",
		EnvVars: []fix.EnvVar{{
			Name:    "FLASK_DEBUG",
			Purpose: "set to 1 to enable the debugger locally",
			Default: "unset, which means off",
		}},
	}
}
