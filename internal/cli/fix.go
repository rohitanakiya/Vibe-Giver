package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/rohitanakiya/Vibe-Giver/internal/contract"
	"github.com/rohitanakiya/Vibe-Giver/internal/fix"
	"github.com/rohitanakiya/Vibe-Giver/internal/killer"
	"github.com/rohitanakiya/Vibe-Giver/internal/loop"
	"github.com/rohitanakiya/Vibe-Giver/internal/repo"
)

// KillerConfigName is the config file Killer reads.
const KillerConfigName = "vibekiller.config.yaml"

func newFixCmd() *cobra.Command {
	var (
		repoPath    string
		runsDir     string
		configPath  string
		target      string
		ownTarget   bool
		categories  []string
		only        []string
		maxAttempts int
		timeout     time.Duration
		killerBin   string
	)

	cmd := &cobra.Command{
		Use:   "fix <run-dir-or-findings.json>",
		Short: "Propose verified fixes for the findings in a Killer run",
		Long: `Fix reads a Vibe Killer run and, for each finding it has a strategy for, proposes
a change and proves it.

Each finding is handled in its own git worktree on its own branch,
vibegiver/<finding_id>. The change is applied there, and then every gate has to
return "gone":

  the finding still reproduced here before anything was changed
  the finding is gone after the change
  the same re-scan introduced no new finding
  the project's own tests still pass
  the changed files still parse and build, and the project's linter passes

An inconclusive result at any gate is a failure, never a pass. A finding that
could not be re-checked here is not touched at all: a fix that cannot be
verified is indistinguishable from no fix, and proposing one would be the exact
mistake this tool exists to avoid.

If every gate passes, the branch is kept with one commit on it and the patch,
the pull request body and the full gate output are written to the run
directory. If any gate fails, the branch is deleted and nothing is left behind.

Vibe Giver never merges, and never pushes. v0 writes the branch and the patch
locally; opening the pull request is yours.

The working tree has to be clean, because the diff Giver reports as proof of
what it changed is not true otherwise, and discarding a failed attempt could
take your work with it.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()

			doc, err := contract.LoadRun(args[0])
			if err != nil {
				var ee *contract.EnvelopeError
				if errors.As(err, &ee) {
					return exitWith(ExitRefused, "%v", err)
				}
				return exitWith(ExitError, "%v", err)
			}

			r, err := repo.Open(repoPath)
			if err != nil {
				return exitWith(ExitError, "%v", err)
			}
			if err := r.PruneWorktrees(); err != nil {
				return exitWith(ExitError, "%v", err)
			}
			if err := r.RequireClean(); err != nil {
				var de *repo.DirtyError
				if errors.As(err, &de) {
					return exitWith(ExitRefused, "%v", err)
				}
				return exitWith(ExitError, "%v", err)
			}

			if runsDir == "" {
				runsDir = filepath.Join("runs", "giver")
			}
			absRuns, err := filepath.Abs(runsDir)
			if err != nil {
				return exitWith(ExitError, "%v", err)
			}
			if err := os.MkdirAll(absRuns, 0o755); err != nil {
				return exitWith(ExitError, "%v", err)
			}

			kr := &killer.Runner{
				Binary:    killerBin,
				Repo:      r.Root,
				Target:    target,
				OwnTarget: ownTarget,
			}
			version, err := kr.Resolve()
			if err != nil {
				return exitWith(ExitError, "%v", err)
			}
			fmt.Fprintf(out, "Using %s\n", version)

			cfg, note, err := ensureKillerConfig(kr.Binary, r.Root, configPath, absRuns)
			if err != nil {
				return exitWith(ExitError, "%v", err)
			}
			kr.ConfigPath = cfg
			if note != "" {
				fmt.Fprintf(out, "  %s\n", note)
			}

			if target != "" && !ownTarget {
				return exitWith(ExitRefused,
					"refusing to contact %s: --i-own-this-target is required for any request to a "+
						"running instance, and Vibe Giver will not supply it on your behalf", target)
			}

			cats, err := parseCategories(categories)
			if err != nil {
				return exitWith(ExitError, "%v", err)
			}
			if len(cats) == 0 {
				cats = fix.DefaultRegistry().Categories()
			}

			if len(only) > 0 {
				doc = filterFindings(doc, only)
			}

			catNames := make([]string, 0, len(cats))
			for _, c := range cats {
				catNames = append(catNames, string(c))
			}
			fmt.Fprintf(out, "Attempting: %s\n", strings.Join(catNames, ", "))
			fmt.Fprintf(out, "Run record: %s\n\n", absRuns)

			rep, err := loop.Run(cmd.Context(), doc, doc.RunID, loop.Options{
				Repo:          r,
				Killer:        kr,
				Registry:      fix.DefaultRegistry(),
				RunsDir:       absRuns,
				WorktreeRoot:  filepath.Join(absRuns, "worktrees"),
				MaxAttempts:   maxAttempts,
				Categories:    cats,
				TestTimeout:   timeout,
				KillerVersion: version,
				Progress:      func(s string) { fmt.Fprintln(out, s) },
			})
			if err != nil {
				return exitWith(ExitError, "%v", err)
			}

			reportPath := filepath.Join(absRuns, "fix_report.json")
			if err := loop.WriteReport(reportPath, rep); err != nil {
				return exitWith(ExitError, "writing the fix report: %v", err)
			}
			if human := loop.HumanActionReport(rep); human != "" {
				humanPath := filepath.Join(absRuns, "human-action-report.md")
				if err := os.WriteFile(humanPath, []byte(human), 0o644); err != nil {
					return exitWith(ExitError, "writing the human-action report: %v", err)
				}
			}

			printFixSummary(cmd, rep, absRuns)

			if stillOpen(rep) > 0 || rep.SourceCoverage.Summary == "" ||
				len(rep.SourceCoverage.Skipped)+len(rep.SourceCoverage.Failed) > 0 {
				return exitWith(ExitUnfixed, "")
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&repoPath, "repo", ".", "the repository to fix")
	f.StringVar(&runsDir, "runs-dir", "", "where to write Giver's run record (default: runs/giver)")
	f.StringVar(&configPath, "config", "", "path to vibekiller.config.yaml")
	f.StringVar(&target, "target", "", "base URL of a running instance, for the dynamic checks")
	f.BoolVar(&ownTarget, "i-own-this-target", false,
		"confirm you own or are authorized to test the instance at --target")
	f.StringSliceVar(&categories, "category", nil,
		"finding categories to attempt (default: every category this build has strategies for)")
	f.StringSliceVar(&only, "only", nil, "attempt only these finding ids (repeatable)")
	f.IntVar(&maxAttempts, "max-attempts", 1,
		"how many times to regenerate a candidate after a failed gate")
	f.DurationVar(&timeout, "timeout", 10*time.Minute, "cap on each test, build or lint command")
	f.StringVar(&killerBin, "vibekiller", "", "path to the vibekiller executable (default: look on PATH)")

	return cmd
}

// ensureKillerConfig makes a config available at a stable path.
//
// It is always materialized outside the repository and passed with --config,
// rather than relying on Killer finding one in the repo root. The reason is
// specific: each fix is verified in a fresh git worktree, which contains only
// tracked files, so an operator config created by `vibekiller init` and never
// committed would simply not be there -- and the scan would fail inside the
// gate rather than up front, where the cause is obvious.
func ensureKillerConfig(killerBin, repoRoot, explicit, runsDir string) (path string, note string, err error) {
	dest := filepath.Join(runsDir, KillerConfigName)

	source := explicit
	if source == "" {
		candidate := filepath.Join(repoRoot, KillerConfigName)
		if _, statErr := os.Stat(candidate); statErr == nil {
			source = candidate
		}
	}

	if source != "" {
		raw, readErr := os.ReadFile(source)
		if readErr != nil {
			return "", "", fmt.Errorf("reading %s: %w", source, readErr)
		}
		if writeErr := os.WriteFile(dest, raw, 0o644); writeErr != nil {
			return "", "", writeErr
		}
		return dest, fmt.Sprintf("Killer config: %s", source), nil
	}

	// No config anywhere. Generate one with Killer's own `init`, rather than
	// writing a hand-made file: the schema belongs to Killer, and a config
	// this build invented could be valid today and wrong after an upgrade.
	tmp, err := os.MkdirTemp("", "vibegiver-config-")
	if err != nil {
		return "", "", err
	}
	defer os.RemoveAll(tmp)

	cmd := exec.Command(killerBin, "init")
	cmd.Dir = tmp
	if combined, runErr := cmd.CombinedOutput(); runErr != nil {
		return "", "", fmt.Errorf("could not generate a Killer config with `vibekiller init`: %w\n%s",
			runErr, combined)
	}
	raw, err := os.ReadFile(filepath.Join(tmp, KillerConfigName))
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(dest, raw, 0o644); err != nil {
		return "", "", err
	}
	return dest, fmt.Sprintf(
		"no %s in the repository, so a default one was generated at %s; it declares no targets, "+
			"so verification is static only", KillerConfigName, dest), nil
}

func parseCategories(names []string) ([]contract.Category, error) {
	var out []contract.Category
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		var found bool
		for _, c := range contract.AllCategories {
			if string(c) == n {
				out = append(out, c)
				found = true
				break
			}
		}
		if !found {
			var all []string
			for _, c := range contract.AllCategories {
				all = append(all, string(c))
			}
			return nil, fmt.Errorf("%q is not a category in Killer's contract; the twelve are: %s",
				n, strings.Join(all, ", "))
		}
	}
	return out, nil
}

func filterFindings(doc *contract.Document, ids []string) *contract.Document {
	want := map[string]bool{}
	for _, id := range ids {
		want[strings.TrimSpace(id)] = true
	}
	clone := *doc
	clone.Findings = nil
	for _, f := range doc.Findings {
		if want[f.FindingID] {
			clone.Findings = append(clone.Findings, f)
		}
	}
	return &clone
}

func stillOpen(rep *loop.Report) int {
	var n int
	for _, o := range rep.Outcomes {
		switch o.Status {
		case loop.StatusFixed, loop.StatusAlreadyResolved:
		default:
			n++
		}
	}
	return n
}

func printFixSummary(cmd *cobra.Command, rep *loop.Report, runsDir string) {
	out := cmd.OutOrStdout()

	byStatus := map[loop.Status][]loop.Outcome{}
	for _, o := range rep.Outcomes {
		byStatus[o.Status] = append(byStatus[o.Status], o)
	}

	fmt.Fprintf(out, "\n%s\n", strings.Repeat("-", 72))
	fmt.Fprintf(out, "%d finding(s) considered\n\n", len(rep.Outcomes))

	order := []loop.Status{
		loop.StatusFixed,
		loop.StatusAlreadyResolved,
		loop.StatusFixFailed,
		loop.StatusBlockedUnverifiable,
		loop.StatusHumanRequired,
		loop.StatusSkipped,
	}
	for _, st := range order {
		group := byStatus[st]
		if len(group) == 0 {
			continue
		}
		fmt.Fprintf(out, "%s (%d)\n", st, len(group))
		sort.Slice(group, func(i, j int) bool { return group[i].FindingID < group[j].FindingID })
		for _, o := range group {
			fmt.Fprintf(out, "  %-16s %-36s %s\n", o.FindingID, o.RuleID, truncate(o.Title, 44))
			if o.Branch != "" && o.Status == loop.StatusFixed {
				fmt.Fprintf(out, "  %-16s branch %s  commit %s\n", "", o.Branch, shortSHA(o.Commit))
			}
			if o.Reason != "" && o.Status != loop.StatusFixed {
				fmt.Fprintf(out, "  %-16s %s\n", "", truncate(oneLine(o.Reason), 110))
			}
			for _, c := range o.Caveats {
				fmt.Fprintf(out, "  %-16s not verified: %s\n", "", truncate(oneLine(c), 96))
			}
		}
		fmt.Fprintln(out)
	}

	fmt.Fprintf(out, "Coverage of the scan this read: %s\n", rep.SourceCoverage.Summary)
	if n := len(rep.SourceCoverage.Skipped) + len(rep.SourceCoverage.Failed); n > 0 {
		fmt.Fprintf(out, "  %d check(s) in that scan established nothing, so this is not a clean bill\n", n)
		fmt.Fprintf(out, "  of health for anything they cover.\n")
	}
	fmt.Fprintln(out)

	if fixed := byStatus[loop.StatusFixed]; len(fixed) > 0 {
		fmt.Fprintf(out, "Vibe Giver does not merge. Review each branch and open the pull request yourself:\n")
		for _, o := range fixed {
			fmt.Fprintf(out, "  git diff main..%s\n", o.Branch)
		}
		fmt.Fprintln(out)
	}

	fmt.Fprintf(out, "Report: %s\n", filepath.Join(runsDir, "fix_report.json"))
	if _, err := os.Stat(filepath.Join(runsDir, "human-action-report.md")); err == nil {
		fmt.Fprintf(out, "        %s\n", filepath.Join(runsDir, "human-action-report.md"))
	}
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.Join(strings.Fields(s), " ")
}
