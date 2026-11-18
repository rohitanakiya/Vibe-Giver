package cli

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rohitanakiya/Vibe-Giver/internal/contract"
	"github.com/rohitanakiya/Vibe-Giver/internal/killer"
)

// --- contract --------------------------------------------------------------

func newContractCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "contract",
		Short: "Print the Vibe Killer contract this build is bound to",
		Long: `Contract prints which Vibe Killer artifact this build reads, and what it will
and will not accept.

It is here because the binding is the part most likely to go wrong quietly. A
consumer reading a findings.json it half-understands produces confident output
either way.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			s := contract.PinnedKiller()

			fmt.Fprintf(out, "Vibe Giver %s\n\n", Version)
			fmt.Fprintf(out, "Bound to Vibe Killer %s (%s)\n", s.PinnedTag, shortSHA(s.PinnedCommit))
			fmt.Fprintf(out, "  schema         %s/%s\n", s.SourceRepo, s.SourcePath)
			fmt.Fprintf(out, "  vendored       %s, from %s\n", s.VendoredAt, s.VendoredFrom)
			fmt.Fprintf(out, "  sha256         %s\n\n", s.SHA256)

			fmt.Fprintf(out, "Per-finding schema_version   %s (pinned by \"const\" in the published schema)\n",
				contract.FindingSchemaVersion)
			fmt.Fprintf(out, "Envelope schema_version      %s\n", contract.DocumentSchemaVersion)
			fmt.Fprintf(out, "Envelopes this build reads   %s\n\n",
				strings.Join(contract.KnownDocumentSchemaVersions, ", "))

			fmt.Fprintln(out, "An envelope newer than the newest above is refused rather than read.")
			fmt.Fprintln(out, "A newer Killer may record another kind of non-coverage, and a finding that is")
			fmt.Fprintln(out, "absent for a reason this build cannot read would be reported as fixed.")
			fmt.Fprintln(out)
			fmt.Fprintln(out, "A 1.0 envelope is read, but it predates the skipped and failed arrays, so it")
			fmt.Fprintln(out, "cannot tell a check that found nothing from one that never ran. No fix can be")
			fmt.Fprintln(out, "proven against one.")
			fmt.Fprintln(out)

			// The engine matters as much as the schema. Giver proves a static
			// fix by reading Killer's rule pack silence, and that silence is
			// sensitive to the Semgrep version as well as to the rules.
			fmt.Fprintf(out, "Semgrep Killer %s pins   %s\n", s.PinnedTag, s.SemgrepPinnedByKiller)
			fid := killer.CheckSemgrepFidelity()
			if fid.Matches {
				fmt.Fprintf(out, "Semgrep installed here       %s\n\n", fid.Installed)
			} else {
				fmt.Fprintf(out, "Semgrep installed here       %s   <-- MISMATCH\n", displayVersion(fid.Installed))
				fmt.Fprintf(out, "  %s\n\n", fid.Reason())
			}

			fmt.Fprintf(out, "Rules `vibekiller reproduce` can re-run (%d of 45 pack rules and 14 checks):\n",
				len(contract.ReproducibleRules))
			for _, r := range contract.ReproducibleRules {
				fmt.Fprintf(out, "  %s\n", r)
			}
			fmt.Fprintln(out, "\nEverything else is verified by a focused re-scan. In the pinned release the")
			fmt.Fprintln(out, "three dynamic misconfiguration checks emit http reproduction steps and")
			fmt.Fprintln(out, "implement no single-finding re-run: `reproduce` prints those steps and exits 0")
			fmt.Fprintln(out, "without sending anything, so exit 0 alone is never read as proof.")
			return nil
		},
	}
}

func shortSHA(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// --- inspect ---------------------------------------------------------------

func newInspectCmd() *cobra.Command {
	var showAll bool

	cmd := &cobra.Command{
		Use:   "inspect <run-dir-or-findings.json>",
		Short: "Read a Killer run and say what Vibe Giver would act on",
		Long: `Inspect loads a Vibe Killer run, validates it against the contract this build
is bound to, and reports what Giver would attempt, what it would hand to a
person, and what the run could not establish at all.

It changes nothing. It exists so the contract binding can be exercised against
a real run before any fix logic runs, and so an operator can see what Giver
would do before letting it do anything.

The coverage section is not a footnote. A run that skipped eleven checks says
nothing about what those checks cover, and "Giver fixed 4 of 4" alongside
"eleven checks never ran" is a different claim from "your application is
clean".`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()

			doc, err := contract.LoadRun(args[0])
			if err != nil {
				// A contract refusal is not a crash, and the distinction is
				// worth an exit code: a pipeline should be able to tell
				// "upgrade Giver" from "Giver broke".
				var ee *contract.EnvelopeError
				if errors.As(err, &ee) {
					return exitWith(ExitRefused, "%v", err)
				}
				return exitWith(ExitError, "%v", err)
			}

			fmt.Fprintf(out, "Run %s", doc.RunID)
			if doc.GeneratedAt != "" {
				fmt.Fprintf(out, "  %s", doc.GeneratedAt)
			}
			fmt.Fprintf(out, "\n  repo     %s", doc.RepoPath)
			if doc.RepoRev != "" {
				fmt.Fprintf(out, " @ %s", shortSHA(doc.RepoRev))
			}
			if doc.Target != "" {
				fmt.Fprintf(out, "\n  target   %s", doc.Target)
			}
			fmt.Fprintf(out, "\n  envelope schema_version %s\n\n", doc.SchemaVersion)

			triage := contract.TriageDocument(doc)
			attempt := contract.Attemptable(triage)
			human := contract.HumanRequired(triage)
			var notOpen int
			for _, t := range triage {
				if t.Disposition == contract.DispositionNotOpen {
					notOpen++
				}
			}

			fmt.Fprintf(out, "%d finding(s)\n", len(doc.Findings))
			fmt.Fprintf(out, "  %3d would be attempted   (status open and fixable_by_giver)\n", len(attempt))
			fmt.Fprintf(out, "  %3d need a person        (fixable_by_giver is false)\n", len(human))
			fmt.Fprintf(out, "  %3d not open             (already fixed, accepted or a false positive)\n\n", notOpen)

			byRoute := map[contract.VerificationRoute]int{}
			for _, t := range attempt {
				byRoute[t.Route]++
			}
			if len(attempt) > 0 {
				fmt.Fprintln(out, "How each would be verified:")
				fmt.Fprintf(out, "  %3d by `vibekiller reproduce` (re-runs the single check)\n",
					byRoute[contract.RouteReproduce])
				fmt.Fprintf(out, "  %3d by a focused re-scan      (reproduce cannot re-run these)\n\n",
					byRoute[contract.RouteFocusedRescan])
			}

			if len(attempt) > 0 {
				fmt.Fprintln(out, "Attemptable, worst first:")
				limit := len(attempt)
				if !showAll && limit > 10 {
					limit = 10
				}
				for _, t := range attempt[:limit] {
					f := t.Finding
					fmt.Fprintf(out, "  %-8s %-22s %-34s %s\n",
						f.Severity, f.FindingID, f.RuleID, truncate(f.Title, 60))
				}
				if limit < len(attempt) {
					fmt.Fprintf(out, "  ... and %d more (--all)\n", len(attempt)-limit)
				}
				fmt.Fprintln(out)
			}

			if len(human) > 0 {
				fmt.Fprintln(out, "Needs a person, never an automated edit:")
				for _, t := range human {
					fmt.Fprintf(out, "  %-22s %-34s %s\n",
						t.Finding.FindingID, t.Finding.RuleID, t.Reason)
				}
				fmt.Fprintln(out)
			}

			printCoverage(cmd, doc)

			// Exit 0 means "there is nothing here to fix, and this run
			// looked". Both halves, because a run that found nothing while
			// checking nothing is the single most dangerous thing this tool
			// could call success -- and it is not a corner case: a bare CI
			// runner with no scanners installed produces exactly that, from
			// a deliberately vulnerable application, and Killer exits 0 on
			// it too.
			if !doc.EstablishesClean() {
				if len(attempt)+len(human) == 0 {
					return exitWith(ExitUnfixed,
						"\nNothing was found, but this run did not establish that there is nothing to find.\n"+
							"That is not a clean result. Install the missing checks, or scan a running\n"+
							"instance, and look again.")
				}
				return exitWith(ExitUnfixed, "")
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&showAll, "all", false, "list every attemptable finding rather than the worst ten")
	return cmd
}

func printCoverage(cmd *cobra.Command, doc *contract.Document) {
	out := cmd.OutOrStdout()
	nc := doc.NonCoverage()

	if nc.Trust == contract.CoverageUnknown {
		fmt.Fprintf(out, "Coverage: %s\n", nc.Summary())
		fmt.Fprintln(out, "  No fix can be proven against this run. Re-scan with a newer Vibe Killer.")
		return
	}
	if nc.Silent() {
		fmt.Fprintf(out, "Coverage: %s\n", nc.Summary())
		return
	}

	fmt.Fprintf(out, "Coverage: %s\n", nc.Summary())

	// Group by reason the way Killer's own report does, because eleven lines
	// of the same sentence hides the one that differs.
	byReason := map[string][]string{}
	for _, s := range doc.Skipped {
		byReason[s.Reason] = append(byReason[s.Reason], s.CheckID)
	}
	reasons := make([]string, 0, len(byReason))
	for r := range byReason {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	for _, r := range reasons {
		checks := byReason[r]
		sort.Strings(checks)
		if len(checks) == 1 {
			fmt.Fprintf(out, "  - %s: %s\n", checks[0], r)
			continue
		}
		fmt.Fprintf(out, "  - %s\n      [%d checks: %s]\n", r, len(checks), strings.Join(checks, ", "))
	}
	for _, f := range doc.Failed {
		fmt.Fprintf(out, "  ! %s ran and failed: %s\n", f.CheckID, f.Error)
	}
	fmt.Fprintln(out, "\n  Nothing is known about what those checks cover. Their silence is not a clean bill.")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

// displayVersion names an absent engine rather than printing a blank.
func displayVersion(v string) string {
	if v == "" {
		return "not installed"
	}
	return v
}
