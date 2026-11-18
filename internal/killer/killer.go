// Package killer drives the Vibe Killer binary.
//
// Giver never reimplements a check. Everything it claims about whether a
// weakness is present comes from running Killer and reading what Killer
// wrote, so that the two tools cannot disagree about what "gone" means.
//
// The two routes out of this package are deliberately asymmetric in cost and
// identical in honesty: Reproduce re-runs one check and is available for five
// rule ids, FocusedRescan re-runs a producing check and is available for
// everything. Neither returns gone without evidence.
package killer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rohitanakiya/Vibe-Giver/internal/contract"
)

// Runner invokes a Vibe Killer binary against one repository.
type Runner struct {
	// Binary is the vibekiller executable. Resolved from PATH when empty.
	Binary string

	// Repo is the repository to scan.
	Repo string

	// ConfigPath is passed as --config. Killer looks in the repo root when
	// this is empty.
	ConfigPath string

	// RunsDir is where Killer writes run directories. Giver keeps these
	// under its own run log rather than in the operator repository, so a
	// verification does not dirty the tree it is verifying.
	RunsDir string

	// Target is a running instance, for the dynamic checks. Empty means
	// static only, which is what v0 uses.
	Target string

	// OwnTarget passes --i-own-this-target. Killer refuses any request
	// without it, and Giver never supplies it unless the operator did.
	OwnTarget bool

	// Log receives each command line and its outcome, for the run record.
	Log func(string)

	// Fidelity is whether the static engine on this machine is the one the
	// pinned Killer release tests its rule pack against. It is consulted
	// before any absence is read as a fix; see GuardStaticAbsence.
	Fidelity EngineFidelity
}

// Resolve finds the Killer binary and checks it runs, so a missing or broken
// install is reported once up front rather than as a verification failure
// that looks like a finding.
func (r *Runner) Resolve() (version string, err error) {
	bin := r.Binary
	if bin == "" {
		bin = "vibekiller"
	}
	found, err := exec.LookPath(bin)
	if err != nil {
		return "", fmt.Errorf(
			"could not find the vibekiller executable (%q): %w\n"+
				"install it with: go install github.com/rohitanakiya/Vibe-Killer/cmd/vibekiller@%s",
			bin, err, contract.PinnedKiller().PinnedTag)
	}
	r.Binary = found

	out, err := exec.Command(found, "--version").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s --version failed: %w\n%s", found, err, out)
	}
	return strings.TrimSpace(string(out)), nil
}

// Result is one Killer invocation.
type Result struct {
	Args     []string
	ExitCode int
	Output   string
}

func (r *Runner) run(ctx context.Context, args ...string) (Result, error) {
	bin := r.Binary
	if bin == "" {
		bin = "vibekiller"
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	err := cmd.Run()
	res := Result{Args: args, Output: buf.String()}

	var ee *exec.ExitError
	switch {
	case err == nil:
		res.ExitCode = 0
	case errors.As(err, &ee):
		res.ExitCode = ee.ExitCode()
	default:
		// The process did not start, or the context was cancelled. That is
		// not an exit code and must not be classified as one: a failure to
		// run is inconclusive, and mapping it onto 0 would make it a pass.
		return res, fmt.Errorf("running %s %s: %w", bin, strings.Join(args, " "), err)
	}

	if r.Log != nil {
		r.Log(fmt.Sprintf("$ %s %s\n  exit %d", bin, strings.Join(args, " "), res.ExitCode))
	}
	return res, nil
}

// ScanOptions selects what a scan runs.
type ScanOptions struct {
	// Only limits the scan to these check ids. A focused re-scan passes one.
	Only []string

	// StaticOnly makes the scan local, with no outbound connection at all.
	StaticOnly bool

	// RunsSubdir keeps each invocation output separate inside RunsDir, so a
	// before and an after scan do not have to be told apart by timestamp.
	RunsSubdir string
}

// Scan runs Killer and returns the document it wrote.
//
// Killer exits 1 when a finding trips the severity gate, which is the normal
// outcome of scanning something that has a finding in it and is not an error
// here. Exit 2 and 3 are: a scan that could not complete, or was refused,
// establishes nothing, and the caller turns that into an inconclusive verdict
// rather than an empty finding list.
func (r *Runner) Scan(ctx context.Context, opts ScanOptions) (*contract.Document, Result, error) {
	runsDir := r.RunsDir
	if opts.RunsSubdir != "" {
		runsDir = filepath.Join(runsDir, opts.RunsSubdir)
	}

	args := []string{"scan", "--repo", r.Repo, "--runs-dir", runsDir, "--quiet"}
	if r.ConfigPath != "" {
		args = append(args, "--config", r.ConfigPath)
	}
	if opts.StaticOnly || r.Target == "" {
		args = append(args, "--static-only")
	} else {
		args = append(args, "--target", r.Target)
		if r.OwnTarget {
			args = append(args, "--i-own-this-target")
		}
	}
	for _, only := range opts.Only {
		args = append(args, "--only", only)
	}

	res, err := r.run(ctx, args...)
	if err != nil {
		return nil, res, err
	}

	switch res.ExitCode {
	case contract.KillerExitOK, contract.KillerExitFindings:
		// Completed. Exit 1 only means something is open.
	case contract.KillerExitRefused:
		return nil, res, fmt.Errorf(
			"the scan was refused on scope or safety grounds (exit 3), so it established nothing:\n%s",
			strings.TrimSpace(res.Output))
	default:
		return nil, res, fmt.Errorf(
			"the scan could not complete (exit %d), so it established nothing:\n%s",
			res.ExitCode, strings.TrimSpace(res.Output))
	}

	dir, err := newestRun(runsDir)
	if err != nil {
		return nil, res, err
	}
	doc, err := contract.LoadRun(dir)
	if err != nil {
		return nil, res, err
	}
	return doc, res, nil
}

// newestRun returns the most recent run directory under dir. Killer names
// them by timestamp, so lexical order is chronological.
func newestRun(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("reading run directory %s: %w", dir, err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return "", fmt.Errorf("the scan wrote no run directory under %s", dir)
	}
	sort.Strings(names)
	return filepath.Join(dir, names[len(names)-1]), nil
}

// Reproduce re-runs one finding check and classifies the outcome.
//
// The classification is the whole value of this method and lives in the
// contract package, because the mapping is not obvious: one of Killer paths
// prints manual steps and exits 0 without sending anything.
func (r *Runner) Reproduce(ctx context.Context, f contract.Finding) (contract.Verdict, Result, error) {
	args := []string{
		"reproduce", f.FindingID,
		"--repo", r.Repo,
		"--runs-dir", filepath.Join(r.RunsDir, "reproduce"),
	}
	if r.ConfigPath != "" {
		args = append(args, "--config", r.ConfigPath)
	}
	if r.Target != "" {
		args = append(args, "--target", r.Target)
	}
	if r.OwnTarget {
		args = append(args, "--i-own-this-target")
	}

	res, err := r.run(ctx, args...)
	if err != nil {
		// Could not run it at all. Inconclusive, never gone.
		return contract.Inconclusive(fmt.Sprintf("could not run vibekiller reproduce: %v", err)), res, nil
	}
	return contract.ClassifyReproduceOutput(f.FindingID, res.ExitCode, res.Output), res, nil
}

// FocusedRescan re-runs the check that produces a finding and says whether
// the finding is still there.
//
// It returns the document as well, because the caller needs it for the second
// gate: a fix that removes one finding and introduces another has not
// succeeded.
func (r *Runner) FocusedRescan(ctx context.Context, f contract.Finding, subdir string) (contract.Verdict, *contract.Document, Result, error) {
	checkID, ok := contract.ProducingCheckID(f)
	if !ok {
		return contract.Inconclusive(fmt.Sprintf(
			"this build cannot tell which check produces a finding with source %q, so it cannot re-run it",
			f.Source)), nil, Result{}, nil
	}

	doc, res, err := r.Scan(ctx, ScanOptions{
		Only:       []string{checkID},
		StaticOnly: r.Target == "" || !needsTarget(checkID),
		RunsSubdir: subdir,
	})
	if err != nil {
		return contract.Inconclusive(fmt.Sprintf("the focused re-scan established nothing: %v", err)), nil, res, nil
	}
	// The coverage join says whether the producing check ran. That is
	// necessary and not sufficient for a static finding: a rule pack can run
	// under the wrong engine and report nothing while looking healthy, and
	// that silence is what an absence-based verdict is made of.
	return GuardStaticAbsence(f, contract.ClassifyInRescan(doc, f), r.Fidelity), doc, res, nil
}

// needsTarget reports whether a check requires a running instance. The three
// scanner engines are local; everything else Killer registers needs a target.
func needsTarget(checkID string) bool {
	switch checkID {
	case contract.CheckSemgrep, contract.CheckOSVScanner, contract.CheckGitleaks:
		return false
	default:
		return true
	}
}

// Verify picks the cheapest honest route for re-checking one finding.
func (r *Runner) Verify(ctx context.Context, f contract.Finding, subdir string) (contract.Verdict, *contract.Document, error) {
	switch contract.RouteFor(f) {
	case contract.RouteReproduce:
		v, _, err := r.Reproduce(ctx, f)
		return v, nil, err
	default:
		v, doc, _, err := r.FocusedRescan(ctx, f, subdir)
		return v, doc, err
	}
}

// NewFindings returns findings present in after and absent from before.
//
// This is the "introduced no new finding" gate. It compares by finding id,
// which is stable for the same underlying issue and deliberately excludes
// line numbers, so moving code around does not read as a new weakness.
//
// Both documents must come from the same focused re-scan, or the comparison
// is between different questions: a baseline that ran more checks than the
// after-scan would report everything the after-scan did not look for as
// fixed, and one that ran fewer would report real findings as new.
func NewFindings(before, after *contract.Document) []contract.Finding {
	if before == nil || after == nil {
		return nil
	}
	had := make(map[string]bool, len(before.Findings))
	for _, f := range before.Findings {
		had[f.FindingID] = true
	}
	var out []contract.Finding
	for _, f := range after.Findings {
		if !had[f.FindingID] {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FindingID < out[j].FindingID })
	return out
}

// SameChecksRan reports whether two documents ran the same set of checks.
//
// NewFindings is only meaningful when they did. Without this, a baseline and
// an after-scan that happened to deselect different checks would produce a
// confident and meaningless comparison.
func SameChecksRan(before, after *contract.Document) (bool, string) {
	if before == nil || after == nil {
		return false, "one of the two scans produced no document"
	}
	a, b := nonCoverageIDs(before), nonCoverageIDs(after)
	if strings.Join(a, ",") == strings.Join(b, ",") {
		return true, ""
	}
	return false, fmt.Sprintf(
		"the two scans did not cover the same checks, so comparing their findings is not meaningful "+
			"(before did not run: %s; after did not run: %s)",
		strings.Join(a, ", "), strings.Join(b, ", "))
}

func nonCoverageIDs(d *contract.Document) []string {
	var out []string
	for id := range d.NonCoverageByCheck() {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
