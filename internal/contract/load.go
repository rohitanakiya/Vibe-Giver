package contract

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/rohitanakiya/Vibe-Giver/internal/contract/killerschema"
)

// FindingsFileName is the file Killer writes inside a run directory.
const FindingsFileName = "findings.json"

// killerPinnedTag is the Killer release this build is bound to, read from the
// vendoring stamp so there is one source for it.
var killerPinnedTag = killerschema.Pinned().PinnedTag

// PinnedKiller returns the Killer artifact this build is bound to.
func PinnedKiller() killerschema.Stamp { return killerschema.Pinned() }

// LoadDocument reads a findings.json and refuses anything it cannot fully
// account for.
//
// The order of the checks matters. The envelope version is settled before any
// field is trusted, because the version is what says whether the coverage
// arrays mean anything. Unknown top-level keys are rejected next, because a
// new coverage array added without a version bump would otherwise sail
// through. Only then are the findings themselves read.
func LoadDocument(path string) (*Document, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading findings: %w", err)
	}
	return ParseDocument(path, raw)
}

// LoadRun reads the findings.json inside a Killer run directory. Passing the
// file itself works too, since that is what an operator reaches for.
func LoadRun(dir string) (*Document, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("reading run directory: %w", err)
	}
	if !info.IsDir() {
		return LoadDocument(dir)
	}
	return LoadDocument(filepath.Join(dir, FindingsFileName))
}

// ParseDocument parses and validates a findings document. path is used only
// in messages.
func ParseDocument(path string, raw []byte) (*Document, error) {
	// Read the envelope as a bag of keys first. Decoding straight into
	// Document would discard anything unmodelled, which is the one thing
	// that must not be discarded quietly.
	var bag map[string]json.RawMessage
	if err := json.Unmarshal(raw, &bag); err != nil {
		return nil, &EnvelopeError{
			Path:   path,
			Reason: fmt.Sprintf("the file is not a JSON object: %v", err),
		}
	}

	var declared string
	if rawVer, ok := bag["schema_version"]; ok {
		if err := json.Unmarshal(rawVer, &declared); err != nil {
			return nil, &EnvelopeError{
				Path:   path,
				Reason: fmt.Sprintf("schema_version is not a string: %v", err),
			}
		}
	}
	if err := checkEnvelopeVersion(path, declared); err != nil {
		return nil, err
	}

	if unknown := unknownKeys(bag); len(unknown) > 0 {
		return nil, &EnvelopeError{
			Path:    path,
			Version: declared,
			Reason: fmt.Sprintf("the envelope carries %d key(s) this build does not read: %s",
				len(unknown), strings.Join(unknown, ", ")),
			Advice: "Vibe Giver refuses rather than ignores an unmodelled envelope field, because the " +
				"fields it reads are what distinguish a finding that is gone from one whose check " +
				"never ran. If a new field records another kind of non-coverage, ignoring it would " +
				"turn unchecked findings into fixed ones. Upgrade Vibe Giver.",
		}
	}

	var doc Document
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		// Reached when a nested object, a finding or a skip entry, carries a
		// field this build does not model. Same reasoning as above: a
		// finding-level field could change what the finding means.
		return nil, &EnvelopeError{
			Path:    path,
			Version: declared,
			Reason:  fmt.Sprintf("a nested object carries a field this build does not read: %v", err),
			Advice:  "upgrade Vibe Giver, or re-scan with Killer " + killerPinnedTag,
		}
	}

	if err := doc.validateFindings(path); err != nil {
		return nil, err
	}
	return &doc, nil
}

func unknownKeys(bag map[string]json.RawMessage) []string {
	var unknown []string
	for k := range bag {
		if !slices.Contains(documentTopLevelKeys, k) {
			unknown = append(unknown, k)
		}
	}
	sort.Strings(unknown)
	return unknown
}

// validateFindings enforces the per-finding invariants Giver relies on.
//
// It intentionally does not re-implement all of Killer's validation. Killer
// validates on the way out and will not write a malformed finding; duplicating
// that here would be a second copy to drift. What is checked is what Giver
// would otherwise act on wrongly: the schema version, and the two contract
// rules whose violation would let Giver edit something it must not touch.
func (d *Document) validateFindings(path string) error {
	var errs []error
	for i := range d.Findings {
		f := &d.Findings[i]
		where := fmt.Sprintf("finding %d (%s/%s)", i, f.RuleID, f.FindingID)

		if f.SchemaVersion != FindingSchemaVersion {
			errs = append(errs, fmt.Errorf(
				"%s: schema_version is %q and this build speaks %q; the per-finding schema is pinned by "+
					"\"const\": \"1.0\" in Killer's published schema, so a different value means the "+
					"contract moved under us",
				where, f.SchemaVersion, FindingSchemaVersion))
		}

		// A leaked credential is never fixed by editing code, and Killer
		// enforces that on the way out. If a document ever says otherwise,
		// Giver must not be the thing that acts on it.
		if f.Source == SourceSecrets && f.Remediation.FixableByGiver {
			errs = append(errs, fmt.Errorf(
				"%s: a secrets finding claims remediation.fixable_by_giver=true; refusing, because the "+
					"only real remediation is rotating the credential and scrubbing history, and an "+
					"edit that hides it would read as a fix",
				where))
		}

		// Killer guarantees a reason whenever a human has to act. Giver
		// prints it in the human-action report, so an empty one is a gap in
		// the report rather than a silently dropped finding.
		if !f.Remediation.FixableByGiver && strings.TrimSpace(f.Remediation.HumanRequiredReason) == "" {
			errs = append(errs, fmt.Errorf(
				"%s: fixable_by_giver is false with no human_required_reason, so there is nothing to tell "+
					"the operator to do", where))
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("%s does not satisfy the findings contract:\n%w", path, errors.Join(errs...))
}

// FindingByID returns the finding with that id.
func (d *Document) FindingByID(id string) (*Finding, bool) {
	for i := range d.Findings {
		if d.Findings[i].FindingID == id {
			return &d.Findings[i], true
		}
	}
	return nil, false
}
