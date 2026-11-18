// Package loop is the fix-and-verify cycle: the part of Vibe Giver that
// decides whether a candidate change is allowed to be called a fix.
//
// The model proposes, the loop disposes. Nothing a strategy produces is
// trusted; it is applied in an isolated worktree, put through every gate, and
// discarded along with its branch unless every gate it could run returned
// gone.
//
// The gates are an AND in which inconclusive loses, which is the whole of the
// brief fourth section expressed once:
//
//  0. the finding still reproduces here       (else already_resolved / blocked)
//     a. after the change, it is gone            (not inconclusive -- that is a fail)
//     b. the same re-scan introduces no new finding
//     c. the project own tests still pass        (or a recorded caveat, never a pass)
//     d. the changed files still parse and build, and the project linter passes
//
// A fix that cannot clear those is a fix_failed with the captured reason, not
// a quiet skip and never a success.
package loop

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rohitanakiya/Vibe-Giver/internal/contract"
	"github.com/rohitanakiya/Vibe-Giver/internal/fix"
	"github.com/rohitanakiya/Vibe-Giver/internal/killer"
	"github.com/rohitanakiya/Vibe-Giver/internal/project"
	"github.com/rohitanakiya/Vibe-Giver/internal/repo"
)

// Status is the terminal state for one finding, as the brief sixth section
// defines it.
type Status string

const (
	// StatusFixed means every gate that could run returned gone. Only this
	// one is a success.
	StatusFixed Status = "fixed"

	// StatusAlreadyResolved means the finding did not reproduce before
	// anything was changed. Not a fix: nothing was done.
	StatusAlreadyResolved Status = "already_resolved"

	// StatusBlockedUnverifiable means the finding could not be re-checked
	// here, so a fix for it could not be proven either. Attempting a blind
	// fix is the trap the whole tool is built around, so nothing is
	// attempted.
	StatusBlockedUnverifiable Status = "blocked_unverifiable"

	// StatusFixFailed means a change was generated and did not clear the
	// gates. The branch is gone; the reason is kept.
	StatusFixFailed Status = "fix_failed"

	// StatusHumanRequired means Killer said a person has to act.
	StatusHumanRequired Status = "human_required"

	// StatusSkipped means this build has no strategy for the finding. It is
	// reported rather than omitted: a finding nobody looked at must not be
	// invisible in the report.
	StatusSkipped Status = "skipped_no_strategy"
)

// GateResult is one gate and what it decided.
type GateResult struct {
	Gate    string `json:"gate"`
	Outcome string `json:"outcome"`
	Reason  string `json:"reason"`
	Checked string `json:"checked_by,omitempty"`
}

// Outcome is everything that happened for one finding. It is what
// fix_report.json is written from, and what the pull request body quotes.
type Outcome struct {
	FindingID string `json:"finding_id"`
	RuleID    string `json:"rule_id"`
	Title     string `json:"title"`
	Severity  string `json:"severity"`
	Category  string `json:"category"`

	Status Status `json:"status"`
	Reason string `json:"reason,omitempty"`

	Branch string `json:"branch,omitempty"`
	Commit string `json:"commit,omitempty"`

	// PRURL is always empty in v0. The field exists because the contract in
	// the brief names it, and because an empty pr_url is the honest way to
	// say "a branch exists and nobody has opened anything".
	PRURL string `json:"pr_url,omitempty"`

	PatchPath string `json:"patch_path,omitempty"`
	RunDir    string `json:"run_dir,omitempty"`

	Strategy string `json:"strategy,omitempty"`

	VerificationResults []GateResult `json:"verification_results"`

	// Caveats are gates that could not be run, most often a project with no
	// test suite. They are never a pass and never dropped.
	Caveats []string `json:"caveats,omitempty"`

	// EnvVars is configuration the fix introduces and the operator must set.
	EnvVars []fix.EnvVar `json:"env_vars,omitempty"`

	// BaseNote records which revision the fix was based on and why.
	BaseNote string `json:"base_note,omitempty"`

	SiblingNote string `json:"sibling_note,omitempty"`
	Rationale   string `json:"rationale,omitempty"`
	RootCause   string `json:"root_cause,omitempty"`
	Attempts    int    `json:"attempts"`
}

// Fixed reports whether this outcome is a proven fix.
func (o *Outcome) Fixed() bool { return o.Status == StatusFixed }

// Report is the whole run, written as fix_report.json so Killer or a person
// can reconcile against the next scan.
type Report struct {
	Tool          string    `json:"tool"`
	Version       string    `json:"version"`
	GeneratedAt   string    `json:"generated_at"`
	KillerVersion string    `json:"killer_version"`
	KillerPinned  string    `json:"killer_pinned_tag"`
	SourceRun     string    `json:"source_run"`
	Repo          string    `json:"repo"`
	Outcomes      []Outcome `json:"outcomes"`

	// SourceCoverage carries what the scan Giver read could not establish.
	// A report that said "fixed 2 of 2" without it would read as a clean
	// bill of health for an application whose other eleven checks never ran.
	SourceCoverage SourceCoverage `json:"source_coverage"`
}

// SourceCoverage is the non-coverage of the scan this run consumed.
type SourceCoverage struct {
	Summary string   `json:"summary"`
	Skipped []string `json:"skipped,omitempty"`
	Failed  []string `json:"failed,omitempty"`
}

// Options configures a run.
type Options struct {
	Repo     *repo.Repo
	Killer   *killer.Runner
	Registry *fix.Registry

	// RunsDir is where Giver writes its own record, one directory per
	// finding, as the brief requires.
	RunsDir string

	// WorktreeRoot is where isolated checkouts are made. Outside the
	// repository, so a scan of the worktree does not find the parent.
	WorktreeRoot string

	// MaxAttempts is how many times a candidate may be regenerated with the
	// failure fed back. v0 generates deterministically, so a retry would
	// produce the same change; it is 1 here and the plumbing is in place for
	// the retry-with-feedback work in v2.
	MaxAttempts int

	// Categories limits what is attempted. v0 passes
	// security-misconfiguration only.
	Categories []contract.Category

	// TestTimeout caps each project command.
	TestTimeout time.Duration

	// Progress receives human-readable progress lines.
	Progress func(string)

	// KillerVersion is recorded in the report.
	KillerVersion string
}

func (o *Options) progress(format string, args ...any) {
	if o.Progress != nil {
		o.Progress(fmt.Sprintf(format, args...))
	}
}

// Run processes every actionable finding in a document.
func Run(ctx context.Context, doc *contract.Document, sourceRun string, opts Options) (*Report, error) {
	if opts.MaxAttempts <= 0 {
		opts.MaxAttempts = 1
	}
	if err := os.MkdirAll(opts.RunsDir, 0o755); err != nil {
		return nil, err
	}

	rep := &Report{
		Tool:          "vibegiver",
		Version:       opts.KillerVersion,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		KillerVersion: opts.KillerVersion,
		KillerPinned:  contract.PinnedKiller().PinnedTag,
		SourceRun:     sourceRun,
		Repo:          opts.Repo.Root,
	}

	nc := doc.NonCoverage()
	rep.SourceCoverage.Summary = nc.Summary()
	for _, s := range nc.Skipped {
		rep.SourceCoverage.Skipped = append(rep.SourceCoverage.Skipped, s.CheckID+": "+s.Reason)
	}
	for _, f := range nc.Failed {
		rep.SourceCoverage.Failed = append(rep.SourceCoverage.Failed, f.CheckID+": "+f.Error)
	}

	wanted := map[contract.Category]bool{}
	for _, c := range opts.Categories {
		wanted[c] = true
	}

	for _, tri := range contract.TriageDocument(doc) {
		f := tri.Finding

		switch tri.Disposition {
		case contract.DispositionNotOpen:
			continue
		case contract.DispositionHumanRequired:
			rep.Outcomes = append(rep.Outcomes, newOutcome(f, StatusHumanRequired, tri.Reason))
			continue
		}

		if len(wanted) > 0 && !wanted[f.Category] {
			continue
		}
		if _, ok := opts.Registry.For(f); !ok {
			rep.Outcomes = append(rep.Outcomes, newOutcome(f, StatusSkipped, fmt.Sprintf(
				"this build has no fix strategy for %s; it is reported rather than omitted so the "+
					"finding is not invisible", f.RuleID)))
			continue
		}

		out := one(ctx, f, opts)
		rep.Outcomes = append(rep.Outcomes, out)
	}

	return rep, nil
}

func newOutcome(f contract.Finding, status Status, reason string) Outcome {
	return Outcome{
		FindingID:           f.FindingID,
		RuleID:              f.RuleID,
		Title:               f.Title,
		Severity:            string(f.Severity),
		Category:            string(f.Category),
		Status:              status,
		Reason:              reason,
		VerificationResults: []GateResult{},
	}
}

func record(out *Outcome, gate string, v contract.Verdict) {
	out.VerificationResults = append(out.VerificationResults, GateResult{
		Gate:    gate,
		Outcome: v.Outcome().String(),
		Reason:  v.Reason(),
		Checked: v.CheckedBy(),
	})
}

// one runs the whole cycle for a single finding.
func one(ctx context.Context, f contract.Finding, opts Options) Outcome {
	out := newOutcome(f, StatusFixFailed, "")
	out.Branch = repo.BranchFor(f.FindingID)

	runDir := filepath.Join(opts.RunsDir, f.FindingID)
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		out.Reason = fmt.Sprintf("could not create the run directory: %v", err)
		return out
	}
	out.RunDir = runDir

	logPath := filepath.Join(runDir, "log.txt")
	logFile, err := os.Create(logPath)
	if err != nil {
		out.Reason = fmt.Sprintf("could not open the run log: %v", err)
		return out
	}
	defer logFile.Close()
	logln := func(format string, args ...any) {
		fmt.Fprintf(logFile, format+"\n", args...)
	}
	logln("finding   %s  %s", f.FindingID, f.RuleID)
	logln("title     %s", f.Title)
	logln("location  %s:%d", f.Location.File, f.Location.Line)
	logln("route     %s", contract.RouteFor(f))
	logln("started   %s", time.Now().UTC().Format(time.RFC3339))
	logln("")

	// An existing branch means an earlier attempt is still around. Reusing
	// the name would overwrite someone review in progress.
	if opts.Repo.BranchExists(out.Branch) {
		out.Status = StatusFixFailed
		out.Reason = fmt.Sprintf(
			"branch %s already exists, so an earlier attempt at this finding is still in the "+
				"repository; refusing to overwrite it. Review and delete it, then run again.", out.Branch)
		logln("REFUSED: %s", out.Reason)
		return out
	}

	base, baseNote, err := opts.Repo.BaseFor(f.Location.RepoRev)
	if err != nil {
		out.Reason = fmt.Sprintf("could not work out a base revision: %v", err)
		return out
	}
	out.BaseNote = baseNote
	logln("base      %s", baseNote)

	wtDir := filepath.Join(opts.WorktreeRoot, f.FindingID)
	_ = os.RemoveAll(wtDir)
	wt, err := opts.Repo.AddWorktree(wtDir, out.Branch, base)
	if err != nil {
		out.Reason = fmt.Sprintf("could not create an isolated worktree: %v", err)
		logln("FAILED: %s", out.Reason)
		return out
	}

	// Every path out of here either keeps the branch deliberately or removes
	// it completely. Nothing half-applied is ever left behind.
	kept := false
	defer func() {
		if kept {
			if err := wt.Keep(); err != nil {
				logln("note: could not remove the worktree directory (the branch is kept): %v", err)
			}
			return
		}
		if err := wt.Discard(); err != nil {
			logln("note: discarding the attempt was not clean: %v", err)
		} else {
			logln("discarded branch %s; the repository is as it was", out.Branch)
		}
	}()

	// The Killer runner works on the worktree, not the operator checkout.
	kr := *opts.Killer
	kr.Repo = wt.Dir
	kr.RunsDir = filepath.Join(runDir, "killer")
	kr.Log = func(s string) { logln("%s", s) }

	suite := project.Detect(wt.Dir)
	logln("project   %s %s", suite.Language, suite.Framework)
	for _, c := range suite.Caveats {
		logln("caveat    %s", c)
	}
	out.Caveats = append(out.Caveats, suite.Caveats...)

	// --- gate 0: does it still reproduce here? ----------------------------
	opts.progress("  %s  %s", f.FindingID, "confirming the finding is still here")
	before, beforeDoc, err := kr.Verify(ctx, f, "before")
	if err != nil {
		out.Status = StatusBlockedUnverifiable
		out.Reason = fmt.Sprintf("the pre-check could not run: %v", err)
		record(&out, "still-reproduces", contract.Inconclusive(out.Reason))
		logln("GATE 0  %s", out.Reason)
		return out
	}
	record(&out, "still-reproduces", before)
	logln("GATE 0  %s", before)

	switch before.Outcome() {
	case contract.OutcomeGone:
		out.Status = StatusAlreadyResolved
		out.Reason = "the finding does not reproduce here, so there is nothing to fix. " + before.Reason()
		return out
	case contract.OutcomeInconclusive:
		// This is the §0 trap, declined. A fix cannot be proven for a
		// finding that cannot be re-checked, so none is attempted.
		out.Status = StatusBlockedUnverifiable
		out.Reason = "the finding could not be re-checked here, so a fix for it could not be proven " +
			"either; no change was attempted. " + before.Reason()
		return out
	}

	// --- generate and verify ----------------------------------------------
	for attempt := 1; attempt <= opts.MaxAttempts; attempt++ {
		out.Attempts = attempt
		logln("")
		logln("--- attempt %d ---", attempt)

		strategy, ok := opts.Registry.For(f)
		if !ok {
			out.Status = StatusSkipped
			out.Reason = "no strategy for " + f.RuleID
			return out
		}
		out.Strategy = strategy.Name()

		proposal, err := strategy.Propose(fix.Input{
			Finding: f,
			Root:    wt.Dir,
			Suite:   suite,
			ReadFile: func(rel string) ([]byte, error) {
				return os.ReadFile(wt.Path(rel))
			},
		})
		if err != nil {
			out.Status = StatusFixFailed
			out.Reason = err.Error()
			logln("GENERATE  refused: %v", err)
			return out
		}
		out.Rationale = proposal.Rationale
		out.RootCause = proposal.RootCause
		out.SiblingNote = proposal.SiblingNote
		out.EnvVars = proposal.EnvVars
		logln("GENERATE  %s touching %s", strategy.Name(), strings.Join(proposal.Files(), ", "))

		if err := applyEdits(wt, proposal); err != nil {
			out.Status = StatusFixFailed
			out.Reason = fmt.Sprintf("could not write the candidate fix: %v", err)
			logln("APPLY     failed: %v", err)
			return out
		}

		clean, err := wt.IsClean()
		if err == nil && clean {
			// A strategy that returned a proposal and changed nothing would
			// otherwise sail through every gate: the finding would still be
			// there, so gate (a) catches it, but saying so here is clearer.
			out.Status = StatusFixFailed
			out.Reason = "the strategy produced a proposal that changed nothing"
			logln("APPLY     no change was written")
			return out
		}

		gate := contract.NewGate(f.FindingID)
		out.VerificationResults = out.VerificationResults[:1] // keep gate 0

		// (a) the weakness is gone.
		opts.progress("  %s  re-checking after the change", f.FindingID)
		after, afterDoc, err := kr.Verify(ctx, f, fmt.Sprintf("after-%d", attempt))
		if err != nil {
			after = contract.Inconclusive(fmt.Sprintf("the re-check could not run: %v", err))
		}
		gate.Record("vulnerability-gone", after)
		record(&out, "vulnerability-gone", after)
		logln("GATE a  %s", after)

		// (b) nothing new was introduced.
		newV := noNewFindings(beforeDoc, afterDoc)
		gate.Record("no-new-findings", newV)
		record(&out, "no-new-findings", newV)
		logln("GATE b  %s", newV)

		// (c) the project own tests.
		for _, check := range suite.Tests {
			opts.progress("  %s  running %s", f.FindingID, check)
			res := project.Run(ctx, wt.Dir, check, opts.TestTimeout)
			gate.Record("tests", res.Verdict)
			record(&out, "tests", res.Verdict)
			logln("GATE c  %s", res.Verdict)
			writeOutput(runDir, fmt.Sprintf("attempt-%d-tests.txt", attempt), res.Output)
		}

		// (d) the change parses and builds, and the project linter passes.
		buildChecks := append(suite.Syntax(proposal.Files()), suite.Lint...)
		for _, check := range buildChecks {
			opts.progress("  %s  running %s", f.FindingID, check)
			res := project.Run(ctx, wt.Dir, check, opts.TestTimeout)
			gate.Record(check.Name, res.Verdict)
			record(&out, check.Name, res.Verdict)
			logln("GATE d  %s", res.Verdict)
			writeOutput(runDir, fmt.Sprintf("attempt-%d-%s.txt", attempt, check.Name), res.Output)
		}

		if !gate.Passed() {
			gateName, failed, _ := gate.FirstFailure()
			logln("")
			logln("FAILED at gate %q: %s", gateName, failed)
			if attempt < opts.MaxAttempts {
				// Reset the worktree and try again. v0 generates
				// deterministically, so this does not run; the reset is here
				// so that when v2 feeds the failure back, the next attempt
				// starts from the base tree rather than from a partial fix.
				logln("resetting the worktree for another attempt")
				continue
			}
			out.Status = StatusFixFailed
			out.Reason = fmt.Sprintf("gate %q did not pass: %s", gateName, failed.Reason())
			if patch, perr := wt.Diff(); perr == nil {
				// Keep the rejected diff in the run record. It is the most
				// useful thing to look at when a fix did not work, and it is
				// not left in the repository.
				writeOutput(runDir, fmt.Sprintf("attempt-%d-rejected.diff", attempt), patch)
			}
			return out
		}

		// Every gate passed.
		patch, err := wt.Diff()
		if err != nil {
			out.Status = StatusFixFailed
			out.Reason = fmt.Sprintf("the gates passed but the diff could not be read: %v", err)
			return out
		}
		patchPath := filepath.Join(runDir, "fix.diff")
		if err := os.WriteFile(patchPath, []byte(patch), 0o644); err != nil {
			out.Status = StatusFixFailed
			out.Reason = fmt.Sprintf("could not write the patch: %v", err)
			return out
		}
		out.PatchPath = patchPath

		commit, err := wt.CommitAll(CommitMessage(f, &out, proposal))
		if err != nil {
			out.Status = StatusFixFailed
			out.Reason = fmt.Sprintf("the gates passed but the commit failed: %v", err)
			return out
		}
		out.Commit = commit
		out.Status = StatusFixed
		kept = true

		body := PullRequestBody(f, &out, before, patch)
		writeOutput(runDir, "pull-request.md", body)
		logln("")
		logln("FIXED   commit %s on %s", commit, out.Branch)
		return out
	}

	out.Status = StatusFixFailed
	if out.Reason == "" {
		out.Reason = "the gates did not pass within the attempt budget"
	}
	return out
}

// noNewFindings is gate (b).
//
// It refuses to answer when the two scans did not cover the same checks,
// because a comparison between different questions is worse than no
// comparison: it is confident.
func noNewFindings(before, after *contract.Document) contract.Verdict {
	if before == nil || after == nil {
		// The reproduce route returns no document. A fix verified that way
		// has not been asked this question at all, and saying so is the
		// honest answer.
		return contract.Inconclusive(
			"this finding was verified by re-running its single check, which reports nothing about " +
				"whether the change introduced something else; a focused re-scan is needed to answer that")
	}
	if same, why := killer.SameChecksRan(before, after); !same {
		return contract.Inconclusive(why)
	}
	introduced := killer.NewFindings(before, after)
	if len(introduced) == 0 {
		return contract.Gone(
			fmt.Sprintf("re-scan %s", after.RunID),
			"the same checks ran before and after and reported no finding that was not already there")
	}
	var ids []string
	for _, f := range introduced {
		ids = append(ids, fmt.Sprintf("%s (%s, %s)", f.FindingID, f.RuleID, f.Severity))
	}
	return contract.StillPresent(
		fmt.Sprintf("re-scan %s", after.RunID),
		fmt.Sprintf("the change introduced %d finding(s) that were not there before: %s",
			len(introduced), strings.Join(ids, ", ")))
}

func applyEdits(wt *repo.Worktree, p *fix.Proposal) error {
	for _, e := range p.Edits {
		path := wt.Path(e.Path)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, e.Content, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func writeOutput(dir, name, content string) {
	if strings.TrimSpace(content) == "" {
		return
	}
	_ = os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644)
}

// WriteReport writes fix_report.json.
func WriteReport(path string, rep *Report) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}
