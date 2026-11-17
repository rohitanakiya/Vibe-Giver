package contract

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// DocumentSchemaVersion is the findings.json envelope version this build was
// written against, measured from the published artifact rather than copied
// from a document.
//
// Both the build brief and the project roadmap said the envelope was at 1.1.
// It is not: Vibe Killer v1.0.0 ships DocumentSchemaVersion = "1.2" in
// internal/finding/finding.go, and a real scan of a fixture with that binary
// wrote "schema_version": "1.2". That is a two-document agreement against one
// artifact, which is exactly the drift this package exists to catch, so the
// value here comes from the artifact and the test that asserts it reads a
// real run rather than a hand-written sample.
const DocumentSchemaVersion = "1.2"

// KnownDocumentSchemaVersions are the envelope versions this build can read,
// oldest first.
//
// Killer reads the same three. The agreement is a coincidence of timing, not
// a shared constant, and the two lists mean different things: Killer's says
// "documents I can still parse", this one says "documents whose coverage
// semantics I know in full". That difference is the subject of
// CoverageTrust below.
var KnownDocumentSchemaVersions = []string{"1.0", "1.1", DocumentSchemaVersion}

// SkippedCheck records a check that did not run. A consumer that ignores it
// cannot tell "this layer found nothing" from "this layer never ran".
type SkippedCheck struct {
	CheckID string `json:"check_id"`
	Layer   string `json:"layer,omitempty"`
	Reason  string `json:"reason"`
}

// FailedCheck records a check that ran and broke. It suppresses findings just
// as a skip does, and Killer keeps the two in separate arrays because the
// right response differs: retry a failure, do not retry a skip.
type FailedCheck struct {
	CheckID string `json:"check_id"`
	Layer   string `json:"layer,omitempty"`
	Error   string `json:"error"`
}

// Counts is Killer's per-run summary.
type Counts struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
	BySource   map[string]int `json:"by_source"`
	Confirmed  int            `json:"confirmed"`
}

// Document is the top-level shape of runs/<id>/findings.json.
//
// This half of the contract is not published. Killer ships
// schema/finding.schema.json, which describes a single finding and says
// nothing about the envelope that carries it, so the skipped and failed
// arrays -- the two fields Giver depends on most, because they are the
// difference between "gone" and "nobody looked" -- cannot be bound by schema
// validation at all. They are bound instead by three things that do not
// require Killer to publish anything: the version gate below, the
// unknown-field check in LoadDocument, and a test that reads a findings.json
// produced by the pinned binary.
type Document struct {
	SchemaVersion string    `json:"schema_version"`
	RunID         string    `json:"run_id"`
	GeneratedAt   string    `json:"generated_at"`
	RepoPath      string    `json:"repo_path"`
	RepoRev       string    `json:"repo_rev,omitempty"`
	Target        string    `json:"target,omitempty"`
	Counts        Counts    `json:"counts"`
	Findings      []Finding `json:"findings"`

	// Skipped and Failed are omitted when empty, so their absence from a
	// document is not evidence that every check ran. A 1.2 run in which
	// nothing was skipped looks exactly like a 1.0 run that cannot say.
	// Only SchemaVersion distinguishes them, which is why the version gate
	// is load-bearing rather than hygienic.
	Skipped []SkippedCheck `json:"skipped,omitempty"`
	Failed  []FailedCheck  `json:"failed,omitempty"`
}

// CoverageTrust says how much of a document's silence Giver is entitled to
// read as coverage.
type CoverageTrust int

const (
	// CoverageUnknown means the envelope predates the coverage arrays, so
	// the document cannot distinguish a check that found nothing from one
	// that never ran. Absence establishes nothing at all.
	CoverageUnknown CoverageTrust = iota

	// CoverageReported means the envelope carries skipped and failed, so an
	// absence can be checked against them.
	CoverageReported
)

// Trust reports whether this document can speak to what did not run.
//
// This is the one place where Giver deliberately parts company with Killer.
// Killer reads a 1.0 document and treats every absence in it as a fix,
// documented in internal/diff as keeping the old behaviour on purpose:
// "inventing uncertainty about runs we have no information on would be its
// own kind of dishonesty." For a diff report shown to a human that is a
// defensible call.
//
// For Giver it is the fatal one. Giver's verdict closes a vulnerability as
// done, and on a 1.0 document "the finding is absent from the re-scan" and
// "the check that would have found it never ran" are the same observation. So
// a 1.0 envelope yields CoverageUnknown, every absence in it is inconclusive,
// and no fix can be proven from it. The honest consequence is that Giver
// cannot verify against pre-1.1 run directories, and it says so loudly
// instead of succeeding cheaply.
func (d *Document) Trust() CoverageTrust {
	if d.SchemaVersion == "1.0" {
		return CoverageUnknown
	}
	return CoverageReported
}

// documentTopLevelKeys is every key this build knows how to read. A real
// document is checked against it on load.
//
// The point is not tidiness. A future Killer that adds a third coverage array
// -- "deselected", say, or "timed_out" -- beside skipped and failed, without
// moving the envelope version, would hand Giver a document in which some
// findings are absent for a reason Giver does not read. Those absences would
// pass the coverage join and be reported as fixed. An unknown key is
// therefore a refusal, not a warning.
var documentTopLevelKeys = []string{
	"schema_version",
	"run_id",
	"generated_at",
	"repo_path",
	"repo_rev",
	"target",
	"counts",
	"findings",
	"skipped",
	"failed",
}

// EnvelopeError is a refusal to read a findings document.
type EnvelopeError struct {
	Path    string
	Version string
	Reason  string
	Advice  string
}

func (e *EnvelopeError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "refusing to read %s: %s", e.Path, e.Reason)
	if e.Advice != "" {
		fmt.Fprintf(&b, "\n  %s", e.Advice)
	}
	return b.String()
}

// checkEnvelopeVersion is the version gate, and it is deliberately
// asymmetric.
//
// An older envelope than this build expects is merely less informative: the
// fields it has mean what they have always meant, and Trust downgrades what
// Giver may conclude from it. An envelope newer than this build knows is a
// different matter. It may carry a new way of recording that a check did not
// run, and a consumer that shrugs and parses the fields it recognizes will
// read those suppressed findings as fixed. There is no safe default for
// "something changed in the half of the contract that tells me what was not
// covered", so this refuses and names the mismatch.
func checkEnvelopeVersion(path, version string) error {
	if version == "" {
		return &EnvelopeError{
			Path:   path,
			Reason: "the document declares no schema_version, so there is no way to tell which envelope it is",
			Advice: "this is not a findings.json written by any released Vibe Killer; check the path",
		}
	}
	if slices.Contains(KnownDocumentSchemaVersions, version) {
		return nil
	}

	known := strings.Join(KnownDocumentSchemaVersions, ", ")
	newer, comparable := envelopeIsNewerThanKnown(version)
	switch {
	case comparable && newer:
		return &EnvelopeError{
			Path:    path,
			Version: version,
			Reason: fmt.Sprintf(
				"envelope schema_version is %q and this build of Vibe Giver knows %s",
				version, known),
			Advice: "a newer envelope may record a kind of non-coverage this build does not read, " +
				"and an unread non-coverage entry is how a finding nobody checked gets reported as fixed. " +
				"Upgrade Vibe Giver, or re-run the scan with the Killer version this build is pinned to (" +
				killerPinnedTag + ").",
		}
	default:
		return &EnvelopeError{
			Path:    path,
			Version: version,
			Reason: fmt.Sprintf(
				"envelope schema_version is %q, which is not one of the versions this build reads (%s)",
				version, known),
			Advice: "check that this is a Vibe Killer run directory and not another tool output",
		}
	}
}

// envelopeIsNewerThanKnown compares a dotted version against the newest
// version this build knows. The second return value is false when the string
// is not dotted numbers, in which case "newer" is not a meaningful question.
func envelopeIsNewerThanKnown(version string) (newer bool, comparable bool) {
	got, ok := parseDotted(version)
	if !ok {
		return false, false
	}
	want, ok := parseDotted(KnownDocumentSchemaVersions[len(KnownDocumentSchemaVersions)-1])
	if !ok {
		return false, false
	}
	for i := 0; i < len(got) && i < len(want); i++ {
		if got[i] != want[i] {
			return got[i] > want[i], true
		}
	}
	return len(got) > len(want), true
}

func parseDotted(v string) ([]int, bool) {
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, false
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}
