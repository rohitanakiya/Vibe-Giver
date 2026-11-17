package contract

import "fmt"

// SourceForLayer maps a check layer to the finding source that layer
// produces. It mirrors Killer's own mapping, including the two entries that
// do not match their own names: every endpoint check emits dast, and the
// exposure check emits blast-radius.
//
// The second return value is false for a layer this build does not know, so a
// layer added later fails to match rather than matching the wrong source.
func SourceForLayer(layer string) (Source, bool) {
	switch layer {
	case "static":
		return SourceSAST, true
	case "endpoint":
		return SourceDAST, true
	case "runtime":
		return SourceRuntime, true
	case "deps":
		return SourceDeps, true
	case "secrets":
		return SourceSecrets, true
	case "exposure":
		return SourceBlastRadius, true
	default:
		return "", false
	}
}

// Engine check ids in the published v1.0.0 binary. A scanner engine emits
// findings under rule ids of its own, so its skip cannot be joined on
// rule_id.
const (
	CheckSemgrep    = "engine.semgrep"
	CheckOSVScanner = "engine.osv-scanner"
	CheckGitleaks   = "engine.gitleaks"
)

// ProducingCheckID returns the id of the check whose run would have produced
// this finding.
//
// This is the join Giver verifies with, and it is deliberately narrower than
// the one Killer uses for its own diff. Killer joins a skip to a finding by
// rule id and, failing that, by layer -- "something in this finding layer was
// skipped and the layer produced nothing, so do not call it fixed". That is
// the right conservative choice for comparing two whole runs.
//
// It is the wrong one for a focused re-check, and measurably so. Verifying
// one fix means re-running one check, and `vibekiller scan --only <rule>`
// records every check it did not schedule as skipped. So a focused re-scan of
// misconfig.cors-reflection reports the other seven endpoint checks as
// skipped on layer "endpoint", which maps to source dast; if the fix worked
// the run produces no dast findings at all, so the layer join fires and the
// finding Giver just verified comes back as "not re-checked". The fix would
// be discarded as unverifiable every time it actually worked -- the §0 trap
// inverted, failing closed instead of open, but still a tool that cannot work.
//
// The precise join asks the question Giver actually has: did the one check
// that produces this finding run? For a first-party check the finding rule id
// is the check id. For a scanner engine it is not -- engine.osv-scanner emits
// deps.known-vulnerability -- so the engine is identified by source. That
// mapping is 1:1 in the published binary, and the test that asserts it reads
// the check list out of the pinned binary rather than trusting this comment.
//
// An unrecognized source returns false, and the caller turns that into
// inconclusive. Failing closed on an unknown producer is the only safe
// default: the alternative is concluding that a check ran because nothing
// said it did not.
func ProducingCheckID(f Finding) (string, bool) {
	switch f.Source {
	case SourceSAST:
		return CheckSemgrep, true
	case SourceDeps:
		return CheckOSVScanner, true
	case SourceSecrets:
		return CheckGitleaks, true
	case SourceDAST, SourceRuntime, SourceBlastRadius:
		// The endpoint, runtime and exposure checks all emit findings under
		// their own rule id.
		if f.RuleID == "" {
			return "", false
		}
		return f.RuleID, true
	default:
		return "", false
	}
}

// NonCoverage is a check that did not produce results, and why.
type NonCoverage struct {
	CheckID string
	Layer   string
	Reason  string

	// Failed distinguishes a check that ran and broke from one that never
	// ran. A failure is worth retrying; a skip is not.
	Failed bool
}

// NonCoverageByCheck indexes everything a document says did not produce
// results, by check id.
func (d *Document) NonCoverageByCheck() map[string]NonCoverage {
	out := make(map[string]NonCoverage, len(d.Skipped)+len(d.Failed))
	for _, s := range d.Skipped {
		out[s.CheckID] = NonCoverage{CheckID: s.CheckID, Layer: s.Layer, Reason: s.Reason}
	}
	// A failure is recorded after the skips deliberately: if a check appears
	// in both, the failure is the more specific fact about this run.
	for _, f := range d.Failed {
		out[f.CheckID] = NonCoverage{
			CheckID: f.CheckID,
			Layer:   f.Layer,
			Reason:  "the check ran and failed: " + f.Error,
			Failed:  true,
		}
	}
	return out
}

// CheckProduced reports whether a named check produced results in this run.
//
// It answers from what the document says did not run, not from whether
// findings appeared: a check that ran and found nothing is exactly the case
// Giver is trying to confirm, so "produced no findings" must not be read as
// "did not run".
func (d *Document) CheckProduced(checkID string) (bool, NonCoverage) {
	if nc, ok := d.NonCoverageByCheck()[checkID]; ok {
		return false, nc
	}
	return true, NonCoverage{}
}

// ClassifyInRescan is the verification primitive: given a re-scan document
// and the finding that was being fixed, say whether the weakness is gone,
// still present, or whether the re-scan simply could not tell.
//
// Every branch that is not a positive observation ends at inconclusive, and
// each one is reachable in practice:
//
//   - a pre-1.1 envelope cannot report coverage at all, so absence in it
//     means nothing;
//   - the producing check cannot be identified, so nothing can be said about
//     whether it ran;
//   - the producing check was skipped or failed, so the finding is absent for
//     a reason that is not a fix.
//
// Only the last branch, where the check demonstrably ran and the finding is
// not in its output, returns gone.
func ClassifyInRescan(rescan *Document, f Finding) Verdict {
	if rescan == nil {
		return Inconclusive("no re-scan document was produced, so nothing was re-checked")
	}

	// A finding that is still reported is still there, and that holds
	// regardless of coverage: presence is a positive observation and needs no
	// trust in the envelope.
	if _, present := rescan.FindingByID(f.FindingID); present {
		return StillPresent(
			fmt.Sprintf("run %s", rescan.RunID),
			fmt.Sprintf("%s is still reported by %s", f.FindingID, f.RuleID))
	}

	if rescan.Trust() == CoverageUnknown {
		return Inconclusive(fmt.Sprintf(
			"the re-scan envelope is schema_version %q, which predates the skipped and failed arrays, "+
				"so this document cannot distinguish a check that found nothing from one that never ran; "+
				"re-scan with Killer %s or newer",
			rescan.SchemaVersion, killerPinnedTag))
	}

	checkID, ok := ProducingCheckID(f)
	if !ok {
		return Inconclusive(fmt.Sprintf(
			"this build cannot tell which check produces a finding with source %q, so it cannot tell "+
				"whether that check ran; refusing to read the absence of %s as a fix",
			f.Source, f.FindingID))
	}

	if produced, nc := rescan.CheckProduced(checkID); !produced {
		verb := "was skipped"
		if nc.Failed {
			verb = "failed"
		}
		return Inconclusive(fmt.Sprintf(
			"%s is absent from run %s, but %s -- the check that produces it -- %s, so the absence is "+
				"evidence of nothing: %s",
			f.FindingID, rescan.RunID, checkID, verb, nc.Reason))
	}

	return Gone(
		fmt.Sprintf("%s in run %s", checkID, rescan.RunID),
		fmt.Sprintf("%s ran and no longer reports %s (%s)", checkID, f.FindingID, f.RuleID))
}
