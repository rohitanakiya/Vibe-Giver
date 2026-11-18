package killer

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/rohitanakiya/Vibe-Giver/internal/contract"
)

// EngineFidelity is whether the scanner engines on this machine are the ones
// the pinned Killer release was tested against.
//
// This exists because of a false clean that actually happened, in this
// repository's own CI, on a commit that changed nothing relevant.
//
// Killer's rule pack asserts both directions: each rule fires on its
// vulnerable fixture and the whole pack stays silent on the patched one. The
// silent half is sensitive to the engine and not only to the rules, which is
// why Killer pins `semgrep==1.185.0` in its CI rather than floating it.
//
// Giver proves a static fix by re-running that pack and reading the silence.
// So an engine that makes the pack go quiet does not produce a visibly broken
// run -- it produces a run where `engine.semgrep` is reported as having run,
// no finding is reported, and every absence therefore looks like a fix.
// Measured: a pipx-installed latest Semgrep reported engine.semgrep as having
// run and produced 0 findings on flask-vulnerable, where 1.185.0 produces 11.
//
// Followed through the loop, that is worse than a crash. The pre-check would
// find the weakness absent before anything was changed and report
// already_resolved: nothing to fix here. A false clean, reached honestly from
// a silent engine, in the one direction nobody re-reads.
type EngineFidelity struct {
	// Engine is the check id, for example engine.semgrep.
	Engine string

	// Installed is the version found on this machine, empty when the engine
	// is absent.
	Installed string

	// Expected is the version the pinned Killer release tests against.
	Expected string

	// Matches is true only when both are known and equal.
	Matches bool

	// Known is false when the installed version could not be determined, in
	// which case nothing can be concluded either way.
	Known bool
}

// Reason explains the state in one sentence for a report.
func (e EngineFidelity) Reason() string {
	switch {
	case e.Matches:
		return fmt.Sprintf("%s is Semgrep %s, the version Killer %s pins",
			e.Engine, e.Installed, contract.PinnedKiller().PinnedTag)
	case !e.Known:
		return fmt.Sprintf(
			"the installed Semgrep version could not be determined, so it is not known whether "+
				"Killer's rule pack behaves here as it does in the release this build is pinned to (%s)",
			e.Expected)
	case e.Installed == "":
		return fmt.Sprintf(
			"Semgrep is not installed, so %s cannot run at all and no static finding can be "+
				"verified either way", e.Engine)
	default:
		return fmt.Sprintf(
			"Semgrep %s is installed and Killer %s pins %s. The silent half of Killer's rule pack is "+
				"sensitive to the engine, so under a different one the pack can report nothing while "+
				"appearing to have run -- which is indistinguishable from a fix. Install %s "+
				"(pip install semgrep==%s) before trusting a static verification here.",
			e.Installed, contract.PinnedKiller().PinnedTag, e.Expected, e.Expected, e.Expected)
	}
}

var semgrepVersion = regexp.MustCompile(`^\s*v?(\d+\.\d+\.\d+)`)

// CheckSemgrepFidelity reports whether the installed Semgrep is the pinned one.
func CheckSemgrepFidelity() EngineFidelity {
	out := EngineFidelity{
		Engine:   contract.CheckSemgrep,
		Expected: contract.PinnedKiller().SemgrepPinnedByKiller,
	}

	path, err := exec.LookPath("semgrep")
	if err != nil {
		// Absent is a known state: the check will be recorded as skipped by
		// Killer, and the coverage join already turns that into
		// inconclusive. Nothing here has to guess.
		out.Known = true
		return out
	}

	raw, err := exec.Command(path, "--version").CombinedOutput()
	if err != nil {
		return out
	}
	m := semgrepVersion.FindStringSubmatch(strings.TrimSpace(string(raw)))
	if m == nil {
		return out
	}
	out.Known = true
	out.Installed = m[1]
	out.Matches = out.Expected != "" && out.Installed == out.Expected
	return out
}

// GuardStaticAbsence downgrades a verdict that rests on a static engine's
// silence when that engine is not the one the pack was tested against.
//
// Only an absence is downgraded. Presence is a positive observation: if the
// pack reported the finding, it evidently matched, and that conclusion does
// not depend on the engine being the pinned one. Silence is the only direction
// a quiet engine can fake, so it is the only direction guarded.
//
// The result is that a static finding on a mismatched engine comes back
// inconclusive instead of gone, which the loop turns into
// blocked_unverifiable rather than already_resolved or fixed. That is the same
// principle as refusing to read a 1.0 envelope's absences: when the thing that
// would have told us is not working, absence is not evidence.
func GuardStaticAbsence(f contract.Finding, v contract.Verdict, fid EngineFidelity) contract.Verdict {
	if v.Outcome() != contract.OutcomeGone {
		return v
	}
	checkID, ok := contract.ProducingCheckID(f)
	if !ok || checkID != contract.CheckSemgrep {
		return v
	}
	if fid.Matches || !fid.Known || fid.Installed == "" {
		// A matching engine is fine. An unknown or absent one is handled
		// elsewhere: absent means Killer records a skip, which the coverage
		// join already reads as inconclusive, and unknown is reported as a
		// caveat rather than used to overturn a positive run.
		return v
	}
	return contract.Inconclusive(fmt.Sprintf(
		"%s is absent from the re-scan and %s reported having run, but %s. Refusing to read that "+
			"silence as a fix.",
		f.FindingID, checkID, fid.Reason()))
}
