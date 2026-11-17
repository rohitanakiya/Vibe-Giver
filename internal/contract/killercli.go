package contract

import (
	"fmt"
	"slices"
	"strings"
)

// Killer exit codes. These are Killer's stated contract with a CI pipeline,
// read from internal/cli/root.go at the pinned tag, and they are deliberately
// few and stable.
const (
	// KillerExitOK means the command completed and nothing tripped the
	// severity gate. On `reproduce` it means the check did not reproduce the
	// finding -- but see ClassifyReproduceOutput before reading that as a fix.
	KillerExitOK = 0

	// KillerExitFindings means a finding at or above the configured
	// threshold is open. On `reproduce` it means the finding reproduced.
	KillerExitFindings = 1

	// KillerExitError means the command could not complete.
	KillerExitError = 2

	// KillerExitRefused means the operation was refused on scope or safety
	// grounds: an undeclared target, or a missing ownership acknowledgement.
	KillerExitRefused = 3
)

// Sentinels printed by `vibekiller reproduce`. The command does not emit a
// machine-readable verdict, so these lines plus the exit code are the whole
// signal.
const (
	// ReproStillReproducible accompanies exit 1 from the dynamic path.
	ReproStillReproducible = "Still reproducible."

	// ReproNoLongerReproducible accompanies exit 0 from the dynamic path,
	// and is the ONLY thing that makes exit 0 mean the weakness is gone.
	ReproNoLongerReproducible = "No longer reproducible."

	// ReproStaticFallthrough is printed by the path that re-runs nothing.
	// See ClassifyReproduceOutput.
	ReproStaticFallthrough = "This is a static finding; it is verified by reading the code:"
)

// ReproducibleRules are the rule ids that `vibekiller reproduce` can actually
// re-run in the pinned release: the checks implementing Killer's Reproducer
// interface.
//
// Five, out of fourteen registered checks and forty-five Semgrep rules. The
// list is measured, not inferred: `grep -rn "func (.*) Reproduce(ctx"` over
// the published tree returns exactly these, and a test cross-checks the names
// against the check list the pinned binary prints.
//
// Knowing this in advance is an optimization, not a safety mechanism. Giver
// does not decide whether a reproduction counted by consulting this list; it
// decides from what the command actually printed. The list only lets Giver
// skip an invocation that cannot answer and go straight to a focused re-scan.
var ReproducibleRules = []string{
	"authz.unprotected-endpoint",
	"idor.sequential-id-access",
	"injection.sql-differential",
	"traversal.path-escape",
	"exposure.shared-trust-domain",
}

// RuleIsReproducible reports whether `vibekiller reproduce` can re-run a
// finding of this rule.
func RuleIsReproducible(ruleID string) bool {
	return slices.Contains(ReproducibleRules, ruleID)
}

// ClassifyReproduceOutput turns an invocation of `vibekiller reproduce` into
// a verdict, and it is the single most important function in this package.
//
// The build brief has Giver's whole loop hinge on this command, and describes
// it as returning gone, still-present or inconclusive. It returns none of
// those words. It signals through an exit code, and one of its paths makes
// that exit code mean the opposite of what it means everywhere else.
//
// Measured against the published v1.0.0 binary:
//
//	exit 1, "Still reproducible."  -> the check re-ran and the hole is open
//	exit 0, "No longer reproducible." -> the check re-ran and the hole is shut
//	exit 2 -> "no check is registered for rule X, so this finding cannot be
//	          re-run by this build"
//	exit 3 -> refused: undeclared target, or --i-own-this-target missing
//
// and then the path that matters. When a finding's rule maps to a registered
// check that does not implement a single-finding re-run, and the finding
// carries reproduction.steps, the command prints "This is a static finding;
// it is verified by reading the code:", lists the steps, and returns nil --
// exit 0. Nothing was re-run. No request was sent. The weakness may be
// entirely untouched.
//
// Three endpoint checks are in exactly that state in the pinned release:
// misconfig.cors-reflection, misconfig.missing-security-headers and
// misconfig.verbose-error emit reproduction.kind "http" with steps and
// implement no Reproduce method, and ssrf.internal-canary-fetch is a fourth.
// The first three are the whole of security-misconfiguration on the dynamic
// side, which the brief names as the v0 category because its diffs are the
// smallest and safest.
//
// So a Giver that read exit 0 as "gone" -- the obvious reading, and the one
// the brief implies -- would have certified every v0 fix as proven by running
// a command that sent no traffic and printed some prose. A tool that looks
// alive because the only thing asserting it cannot tell the difference, in
// the exact category it was told to start with.
//
// Hence: exit 0 is gone only when the dynamic sentinel is present. Every
// other exit 0 is inconclusive, and names the fallthrough as the reason.
func ClassifyReproduceOutput(findingID string, exitCode int, combinedOutput string) Verdict {
	out := combinedOutput
	checkedBy := fmt.Sprintf("vibekiller reproduce %s", findingID)

	switch exitCode {
	case KillerExitFindings:
		if strings.Contains(out, ReproStillReproducible) {
			return StillPresent(checkedBy, "the check re-ran and the finding still reproduces")
		}
		// Exit 1 without the sentinel is not a shape the pinned binary
		// produces. Reporting still-present on a signal nobody recognizes
		// would be a guess, and the guess that blocks is the safe one.
		return Inconclusive(fmt.Sprintf(
			"reproduce exited %d but did not print %q, so this build cannot tell what it decided",
			exitCode, ReproStillReproducible))

	case KillerExitOK:
		if strings.Contains(out, ReproNoLongerReproducible) {
			return Gone(checkedBy, "the check re-ran against the instance and the finding no longer reproduces")
		}
		if strings.Contains(out, ReproStaticFallthrough) {
			return Inconclusive(
				"reproduce exited 0 without re-running anything: the check behind this finding does not " +
					"implement a single-finding re-run, so the command printed manual steps and returned " +
					"success. Nothing was sent and nothing was verified. Verify this finding with a " +
					"focused re-scan instead.")
		}
		return Inconclusive(fmt.Sprintf(
			"reproduce exited 0 but printed neither %q nor the manual-steps notice, so there is no "+
				"evidence that a check actually ran",
			ReproNoLongerReproducible))

	case KillerExitError:
		return Inconclusive(fmt.Sprintf(
			"reproduce could not complete (exit %d). Usually this means no check is registered for the "+
				"finding rule, which is true of every Semgrep-pack rule: %s",
			exitCode, firstLineOfInterest(out)))

	case KillerExitRefused:
		return Inconclusive(fmt.Sprintf(
			"reproduce was refused on scope or safety grounds (exit %d): %s. The target has to be in "+
				"authorized_targets and --i-own-this-target has to be passed; a refusal is not a fix",
			exitCode, firstLineOfInterest(out)))

	default:
		return Inconclusive(fmt.Sprintf(
			"reproduce exited %d, which is not one of Killer documented exit codes (0, 1, 2, 3); "+
				"treating an unrecognized signal as unverified",
			exitCode))
	}
}

// firstLineOfInterest pulls the most informative line out of Killer output
// for an error message, skipping the two-line "Found <id> in run <x>" banner.
func firstLineOfInterest(out string) string {
	lines := strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		l := strings.TrimSpace(lines[i])
		if l == "" || strings.HasPrefix(l, "Found ") {
			continue
		}
		return l
	}
	return "no output"
}

// VerificationRoute is how Giver intends to re-check one finding.
type VerificationRoute string

const (
	// RouteReproduce re-runs the single check behind the finding. Available
	// for the five reproducible rules, and the cheapest honest answer.
	RouteReproduce VerificationRoute = "reproduce"

	// RouteFocusedRescan re-runs the producing check over the repository or
	// instance and asks whether the finding is still in the output, with the
	// coverage join deciding whether the absence counts. This is the route
	// for everything else, which is most things.
	RouteFocusedRescan VerificationRoute = "focused-rescan"
)

// RouteFor picks the verification route for a finding.
//
// Both routes end in a Verdict and neither is allowed to return gone without
// evidence, so this choice is about cost rather than honesty: reproduce sends
// one request sequence, a focused re-scan re-runs a whole check.
func RouteFor(f Finding) VerificationRoute {
	if RuleIsReproducible(f.RuleID) {
		return RouteReproduce
	}
	return RouteFocusedRescan
}
