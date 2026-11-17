package contract

import (
	"strings"
	"testing"
)

// --- the zero value ---------------------------------------------------------

// TestZeroVerdictBlocks is the cheapest possible guard against the whole bug
// class. Every way of getting a verdict wrong in this program ends at the
// zero value, so the zero value must not pass.
func TestZeroVerdictBlocks(t *testing.T) {
	var v Verdict

	if v.ProvesFixed() {
		t.Fatal("the zero Verdict proves a fix; every missed assignment in this program would " +
			"close a real vulnerability as done")
	}
	if v.Outcome() != OutcomeInconclusive {
		t.Errorf("zero outcome = %q, want inconclusive", v.Outcome())
	}
	if got := v.Outcome().String(); got != "inconclusive" {
		t.Errorf("the zero outcome renders as %q; a report must never show a blank verdict", got)
	}
	if !strings.Contains(v.Reason(), "bug in Vibe Giver") {
		t.Errorf("an unset verdict should say it is a bug, got %q", v.Reason())
	}
}

func TestOnlyGoneProvesFixed(t *testing.T) {
	cases := []struct {
		name  string
		v     Verdict
		fixed bool
	}{
		{"gone", Gone("check", "did not find it"), true},
		{"still present", StillPresent("check", "found it again"), false},
		{"inconclusive", Inconclusive("the check never ran"), false},
		{"zero", Verdict{}, false},
	}
	for _, c := range cases {
		if got := c.v.ProvesFixed(); got != c.fixed {
			t.Errorf("%s: ProvesFixed = %v, want %v", c.name, got, c.fixed)
		}
	}
}

func TestGateRequiresEveryResultAndAtLeastOne(t *testing.T) {
	empty := NewGate("vk-1")
	if empty.Passed() {
		t.Error("a gate with nothing recorded passed; a fix nobody checked is not a fix")
	}
	if _, v, ok := empty.FirstFailure(); !ok || v.ProvesFixed() {
		t.Error("an empty gate should report a failure")
	}

	all := NewGate("vk-1")
	all.Record("reproduce", Gone("reproduce", "no longer reproducible"))
	all.Record("tests", Gone("go test ./...", "suite green"))
	if !all.Passed() {
		t.Error("a gate whose every result is gone should pass")
	}

	// The case that matters: one inconclusive among passes.
	mixed := NewGate("vk-1")
	mixed.Record("reproduce", Gone("reproduce", "no longer reproducible"))
	mixed.Record("tests", Inconclusive("the test runner could not be found"))
	mixed.Record("rescan", Gone("rescan", "no new findings"))
	if mixed.Passed() {
		t.Error("a gate containing an inconclusive result passed; inconclusive is a failure, never a pass")
	}
	name, v, ok := mixed.FirstFailure()
	if !ok || name != "tests" {
		t.Errorf("FirstFailure = %q, want tests", name)
	}
	if v.Outcome() != OutcomeInconclusive {
		t.Errorf("failure outcome = %q", v.Outcome())
	}
}

// --- the reproduce trap -----------------------------------------------------

// TestClassifyReproduceOutput covers every shape the pinned binary produces,
// including the one that makes exit 0 mean "nothing ran".
func TestClassifyReproduceOutput(t *testing.T) {
	cases := []struct {
		name string
		exit int
		out  string
		want Outcome
	}{
		{
			name: "dynamic check re-ran and the hole is shut",
			exit: KillerExitOK,
			out:  "Found vk-1 in run r\n  authz.unprotected-endpoint\n\nGET /api/orders/1 now returns 401\n\nNo longer reproducible.\n",
			want: OutcomeGone,
		},
		{
			name: "dynamic check re-ran and the hole is open",
			exit: KillerExitFindings,
			out:  "Found vk-1 in run r\n\nreturned 200 with the canary marker\n\nStill reproducible.\n",
			want: OutcomeStillPresent,
		},
		{
			// The trap. This is a real shape, printed by the three dynamic
			// misconfig checks, which are the whole of the v0 category.
			name: "exit 0 from the path that re-runs nothing",
			exit: KillerExitOK,
			out: "Found vk-1 in run r\n  misconfig.cors-reflection\n  Cross-origin policy reflects any origin\n\n" +
				"This is a static finding; it is verified by reading the code:\n" +
				"  1. Send a request with Origin: https://evil.example\n" +
				"  2. Observe the reflected Access-Control-Allow-Origin\n",
			want: OutcomeInconclusive,
		},
		{
			name: "exit 0 with no recognizable sentinel at all",
			exit: KillerExitOK,
			out:  "Found vk-1 in run r\n",
			want: OutcomeInconclusive,
		},
		{
			name: "no check registered for the rule, which is every Semgrep rule",
			exit: KillerExitError,
			out:  "Found vk-1 in run r\n  misconfig.debug-mode-enabled\n\nno check is registered for rule misconfig.debug-mode-enabled, so this finding cannot be re-run by this build\n",
			want: OutcomeInconclusive,
		},
		{
			name: "refused on scope grounds",
			exit: KillerExitRefused,
			out:  "refused: the target http://example.com is not in authorized_targets\n",
			want: OutcomeInconclusive,
		},
		{
			name: "an exit code Killer does not document",
			exit: 42,
			out:  "something happened\n",
			want: OutcomeInconclusive,
		},
		{
			name: "exit 1 without the sentinel",
			exit: KillerExitFindings,
			out:  "Found vk-1 in run r\n",
			want: OutcomeInconclusive,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ClassifyReproduceOutput("vk-1", c.exit, c.out)
			if got.Outcome() != c.want {
				t.Fatalf("outcome = %q, want %q\nverdict: %s", got.Outcome(), c.want, got)
			}
			if got.Outcome() == OutcomeGone && !got.ProvesFixed() {
				t.Error("a gone verdict must prove a fix")
			}
			if got.Reason() == "" {
				t.Error("every verdict needs a reason")
			}
		})
	}
}

// TestTheTrapIsNamedWhenItFires checks the inconclusive reason for the exit-0
// fallthrough actually tells an operator what happened, since "inconclusive"
// on its own looks like a flaky run rather than a command that verified
// nothing.
func TestTheTrapIsNamedWhenItFires(t *testing.T) {
	v := ClassifyReproduceOutput("vk-1", KillerExitOK,
		"This is a static finding; it is verified by reading the code:\n  1. do a thing\n")

	for _, want := range []string{"without re-running anything", "Nothing was sent", "focused re-scan"} {
		if !strings.Contains(v.Reason(), want) {
			t.Errorf("reason does not say %q:\n%s", want, v.Reason())
		}
	}
}

func TestReproducibleRuleSet(t *testing.T) {
	// The five checks that implement a single-finding re-run.
	for _, rule := range ReproducibleRules {
		if !RuleIsReproducible(rule) {
			t.Errorf("%s should be reproducible", rule)
		}
		if RouteFor(Finding{RuleID: rule}) != RouteReproduce {
			t.Errorf("%s should route to reproduce", rule)
		}
	}

	// The ones that look reproducible and are not. All three dynamic
	// misconfig checks emit reproduction.kind "http" with steps, so a
	// consumer reading the finding would conclude it can be re-run.
	for _, rule := range []string{
		"misconfig.cors-reflection",
		"misconfig.missing-security-headers",
		"misconfig.verbose-error",
		"ssrf.internal-canary-fetch",
		"misconfig.debug-mode-enabled",
		"deps.known-vulnerability",
	} {
		if RuleIsReproducible(rule) {
			t.Errorf("%s is not reproducible by the pinned binary", rule)
		}
		f := Finding{RuleID: rule, Reproduction: &Reproduction{Kind: ReproHTTP, Steps: []string{"a step"}}}
		if RouteFor(f) != RouteFocusedRescan {
			t.Errorf("%s should route to a focused re-scan even though it carries http reproduction steps", rule)
		}
	}
}

// --- the re-scan classifier -------------------------------------------------

func fixedFinding() Finding {
	return Finding{
		SchemaVersion: FindingSchemaVersion,
		FindingID:     "vk-aaaaaaaaaaaa",
		RuleID:        "misconfig.cors-reflection",
		Category:      CategoryMisconfiguration,
		Severity:      SeverityHigh,
		Source:        SourceDAST,
		Status:        StatusOpen,
		Remediation:   Remediation{Guidance: "g", FixableByGiver: true},
	}
}

func rescanDoc(findings []Finding, skipped []SkippedCheck, failed []FailedCheck) *Document {
	return &Document{
		SchemaVersion: DocumentSchemaVersion,
		RunID:         "rescan-1",
		Findings:      findings,
		Skipped:       skipped,
		Failed:        failed,
	}
}

func TestClassifyInRescan(t *testing.T) {
	f := fixedFinding()

	t.Run("still reported means still present", func(t *testing.T) {
		v := ClassifyInRescan(rescanDoc([]Finding{f}, nil, nil), f)
		if v.Outcome() != OutcomeStillPresent {
			t.Fatalf("got %s", v)
		}
	})

	t.Run("absent and its check ran means gone", func(t *testing.T) {
		v := ClassifyInRescan(rescanDoc(nil, nil, nil), f)
		if !v.ProvesFixed() {
			t.Fatalf("got %s", v)
		}
		if !strings.Contains(v.CheckedBy(), "misconfig.cors-reflection") {
			t.Errorf("a gone verdict must name what looked, got %q", v.CheckedBy())
		}
	})

	t.Run("absent because its own check was skipped is inconclusive", func(t *testing.T) {
		v := ClassifyInRescan(rescanDoc(nil, []SkippedCheck{{
			CheckID: "misconfig.cors-reflection",
			Layer:   "endpoint",
			Reason:  "no --target was given, so the endpoint layer did not run",
		}}, nil), f)
		if v.Outcome() != OutcomeInconclusive {
			t.Fatalf("got %s", v)
		}
		if !strings.Contains(v.Reason(), "evidence of nothing") {
			t.Errorf("reason = %q", v.Reason())
		}
	})

	t.Run("absent because its own check failed is inconclusive", func(t *testing.T) {
		v := ClassifyInRescan(rescanDoc(nil, nil, []FailedCheck{{
			CheckID: "misconfig.cors-reflection",
			Layer:   "endpoint",
			Error:   "dial tcp 127.0.0.1:5000: connection refused",
		}}), f)
		if v.Outcome() != OutcomeInconclusive {
			t.Fatalf("got %s", v)
		}
		if !strings.Contains(v.Reason(), "failed") {
			t.Errorf("a failure should be reported as a failure, not a skip: %q", v.Reason())
		}
	})

	t.Run("a 1.0 envelope cannot prove anything by absence", func(t *testing.T) {
		old := rescanDoc(nil, nil, nil)
		old.SchemaVersion = "1.0"
		v := ClassifyInRescan(old, f)
		if v.Outcome() != OutcomeInconclusive {
			t.Fatalf("a 1.0 document proved a fix by absence; Killer reads those absences as fixes "+
				"for its own diff, and for Giver that would close unchecked holes as done: %s", v)
		}
	})

	t.Run("a 1.0 envelope still reports a present finding", func(t *testing.T) {
		old := rescanDoc([]Finding{f}, nil, nil)
		old.SchemaVersion = "1.0"
		if ClassifyInRescan(old, f).Outcome() != OutcomeStillPresent {
			t.Error("presence is a positive observation and needs no trust in the envelope")
		}
	})

	t.Run("no re-scan at all is inconclusive", func(t *testing.T) {
		if ClassifyInRescan(nil, f).ProvesFixed() {
			t.Fatal("a nil re-scan proved a fix")
		}
	})

	t.Run("an unknown source fails closed", func(t *testing.T) {
		weird := f
		weird.Source = "telepathy"
		v := ClassifyInRescan(rescanDoc(nil, nil, nil), weird)
		if v.Outcome() != OutcomeInconclusive {
			t.Fatalf("got %s", v)
		}
	})
}

// TestFocusedRescanIsNotDefeatedByItsOwnDeselections is the second trap, and
// it is the reason ProducingCheckID exists instead of Killer layer join.
//
// Verifying one fix means `scan --only <rule>`, and Killer records every
// check it did not schedule in skipped[]. So the document that proves the fix
// also says that seven other endpoint checks were skipped, on the same layer,
// in a run that produced no dast findings at all. Killer own join -- rule id,
// then layer narrowed by "the source produced nothing" -- fires on that and
// calls the finding unchecked.
//
// Both directions are asserted: the precise join returns gone, and the layer
// join demonstrably would not have. The second half is what makes this a
// measurement rather than a claim.
func TestFocusedRescanIsNotDefeatedByItsOwnDeselections(t *testing.T) {
	f := fixedFinding()

	// What `vibekiller scan --only misconfig.cors-reflection` writes once the
	// fix lands: the target check ran and found nothing, every sibling was
	// deselected.
	siblings := []string{
		"authz.unprotected-endpoint",
		"idor.sequential-id-access",
		"injection.sql-differential",
		"misconfig.missing-security-headers",
		"misconfig.verbose-error",
		"ssrf.internal-canary-fetch",
		"traversal.path-escape",
	}
	var skipped []SkippedCheck
	for _, s := range siblings {
		skipped = append(skipped, SkippedCheck{
			CheckID: s,
			Layer:   "endpoint",
			Reason:  "deselected by --only",
		})
	}
	doc := rescanDoc(nil, skipped, nil)

	v := ClassifyInRescan(doc, f)
	if !v.ProvesFixed() {
		t.Fatalf("a focused re-scan that did verify the fix came back as %s\n"+
			"this is the trap: the run own deselections masked its own result", v)
	}

	// And now the counterfactual, so the trap is shown to be real rather than
	// described. This is Killer join, reimplemented here only to measure it.
	if !killerStyleLayerJoinSuppresses(doc, f) {
		t.Error("the layer join did not suppress this finding, so the precise join is solving " +
			"a problem that does not exist and ProducingCheckID should be simplified away")
	}
}

// killerStyleLayerJoinSuppresses reproduces Killer suppressedBy join: by rule
// id, then by layer when the later run produced nothing from that source. It
// exists only so the test above can show that join gives the wrong answer for
// a focused re-check.
func killerStyleLayerJoinSuppresses(doc *Document, f Finding) bool {
	present := map[Source]bool{}
	for _, x := range doc.Findings {
		present[x.Source] = true
	}
	byRule := map[string]string{}
	bySource := map[Source]string{}
	record := func(checkID, layer, reason string) {
		byRule[checkID] = reason
		src, ok := SourceForLayer(layer)
		if !ok || present[src] {
			return
		}
		bySource[src] = reason
	}
	for _, s := range doc.Skipped {
		record(s.CheckID, s.Layer, s.Reason)
	}
	for _, x := range doc.Failed {
		record(x.CheckID, x.Layer, "the check failed: "+x.Error)
	}
	if _, ok := byRule[f.RuleID]; ok {
		return true
	}
	_, ok := bySource[f.Source]
	return ok
}

// --- triage -----------------------------------------------------------------

// TestTriageRejectsWhatItMust feeds the filter cases it has to refuse,
// because on the real run it has nothing to refuse: all 53 findings are open
// and all 53 are marked auto-fixable, so a filter that matched everything
// would look identical to a correct one.
func TestTriageRejectsWhatItMust(t *testing.T) {
	base := fixedFinding()

	t.Run("the real run is all attemptable", func(t *testing.T) {
		doc := loadReal(t)
		tri := TriageDocument(doc)
		if got := len(Attemptable(tri)); got != 53 {
			t.Errorf("attemptable = %d, want 53", got)
		}
		if got := len(HumanRequired(tri)); got != 0 {
			t.Errorf("human-required = %d, want 0", got)
		}
	})

	t.Run("a finding that is not open", func(t *testing.T) {
		for _, s := range []Status{StatusFixed, StatusAccepted, StatusFalsePositive, StatusRegressed} {
			f := base
			f.Status = s
			if got := TriageFinding(f).Disposition; got != DispositionNotOpen {
				t.Errorf("status %q -> %q, want not_open", s, got)
			}
		}
	})

	t.Run("a finding Killer says needs a human", func(t *testing.T) {
		f := base
		f.Source = SourceSecrets
		f.Category = CategorySecretsExposure
		f.Remediation = Remediation{
			Guidance:            "rotate it",
			FixableByGiver:      false,
			HumanRequiredReason: "a leaked credential has to be rotated by a person",
		}
		tr := TriageFinding(f)
		if tr.Disposition != DispositionHumanRequired {
			t.Fatalf("disposition = %q", tr.Disposition)
		}
		if !strings.Contains(tr.Reason, "rotated by a person") {
			t.Errorf("the human-action report needs Killer own reason, got %q", tr.Reason)
		}
	})

	t.Run("open plus fixable is required, not either", func(t *testing.T) {
		f := base
		f.Status = StatusAccepted
		f.Remediation.FixableByGiver = true
		if TriageFinding(f).Disposition == DispositionAttempt {
			t.Error("an accepted finding was attempted because it was marked fixable")
		}
	})
}

// TestZeroFindingsIsNotCleanUnlessSomethingLooked encodes the case the first
// round-trip CI run produced on real infrastructure: a bare runner with no
// scanners installed, a deliberately vulnerable fixture, zero findings, every
// check skipped, and Killer's own exit 0.
func TestZeroFindingsIsNotCleanUnlessSomethingLooked(t *testing.T) {
	// What that runner actually wrote, in miniature: nothing found, because
	// nothing ran.
	nothingLooked := &Document{
		SchemaVersion: DocumentSchemaVersion,
		RunID:         "bare-runner",
		Skipped: []SkippedCheck{
			{CheckID: "engine.semgrep", Layer: "static", Reason: "semgrep is not installed or not on PATH"},
			{CheckID: "engine.osv-scanner", Layer: "deps", Reason: "osv-scanner is not installed or not on PATH"},
			{CheckID: "engine.gitleaks", Layer: "secrets", Reason: "gitleaks is not installed or not on PATH"},
		},
	}
	if nothingLooked.EstablishesClean() {
		t.Fatal("a run that found nothing because nothing ran was reported as clean; this is the " +
			"output a bare CI runner produces from a known-vulnerable application")
	}

	// A check that ran and broke is the same conclusion by another route.
	checkBroke := &Document{
		SchemaVersion: DocumentSchemaVersion,
		RunID:         "broken",
		Failed:        []FailedCheck{{CheckID: "engine.semgrep", Layer: "static", Error: "exit status 7"}},
	}
	if checkBroke.EstablishesClean() {
		t.Error("a run whose scanner crashed was reported as clean")
	}

	// And the one case that is genuinely clean: nothing skipped, nothing
	// failed, nothing found. Without this the test above would pass for a
	// function that always returned false.
	everythingRan := &Document{SchemaVersion: DocumentSchemaVersion, RunID: "complete"}
	if !everythingRan.EstablishesClean() {
		t.Error("a complete run with no findings should be clean; otherwise nothing ever is")
	}

	// A complete run that still has an open finding is not clean either.
	withFinding := &Document{
		SchemaVersion: DocumentSchemaVersion,
		RunID:         "complete-but-open",
		Findings:      []Finding{fixedFinding()},
	}
	if withFinding.EstablishesClean() {
		t.Error("a run with an open attemptable finding was reported as clean")
	}

	// The real corpus: 53 findings and 11 skipped checks. Not clean twice
	// over.
	if loadReal(t).EstablishesClean() {
		t.Error("the real run was reported as clean")
	}
}

// TestLoadRefusesASecretsFindingMarkedFixable guards the one rewrite that
// would be actively harmful: an edit that hides a credential while it stays
// valid reads as a fix.
func TestLoadRefusesASecretsFindingMarkedFixable(t *testing.T) {
	doc := Document{
		SchemaVersion: DocumentSchemaVersion,
		Findings: []Finding{{
			SchemaVersion: FindingSchemaVersion,
			FindingID:     "vk-bbbbbbbbbbbb",
			RuleID:        "secrets.committed-credential",
			Source:        SourceSecrets,
			Status:        StatusOpen,
			Remediation:   Remediation{Guidance: "g", FixableByGiver: true},
		}},
	}
	if err := doc.validateFindings("synthetic"); err == nil {
		t.Fatal("a secrets finding claiming fixable_by_giver=true was accepted")
	}
}
