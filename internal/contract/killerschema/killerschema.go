// Package killerschema holds Vibe Killer's published findings contract,
// vendored, plus the stamp recording exactly which artifact it came from.
//
// Why vendored and not a git submodule, which was the going-in preference:
// a submodule's content is not part of its parent repository's tree. In the
// parent it is a gitlink (mode 160000) pointing at a commit, so an archive of
// the parent -- which is what the Go module proxy serves for a tag -- contains
// the submodule's directory and nothing inside it. That was measured before
// choosing: `git archive HEAD | tar -t` on a repository with a submodule
// listed `vendor-schema/` as an empty directory, and `git ls-tree` showed
// `160000 commit` rather than a tree.
//
// So a //go:embed over a submodule path builds from a developer's checkout,
// where `git submodule update` has run, and fails or embeds nothing for
// anyone who installs with `go install ...@vX.Y.Z`. Vibe Killer has already
// paid for this exact class of mistake once, from the other direction: a
// gitignore entry came one slash from excluding its own embedded rule pack,
// which would have published a scanner with no rules that reported a clean
// scan of everything.
//
// Vendoring makes the file part of this module's tree, so the published
// binary provably carries it. The anti-drift property a submodule would have
// given is recovered by Stamp plus the drift check in CI, which re-fetches
// the pinned tag's schema and compares the hash.
package killerschema

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

// FindingSchema is Killer's published per-finding JSON schema, byte for byte
// as the module proxy serves it at the pinned tag.
//
//go:embed finding.schema.json
var FindingSchema []byte

//go:embed stamp.json
var stampJSON []byte

// Stamp records which Killer artifact this schema was taken from, so a
// mismatch is attributable to a version rather than to a mystery.
type Stamp struct {
	SourceRepo   string `json:"source_repo"`
	SourcePath   string `json:"source_path"`
	PinnedTag    string `json:"pinned_tag"`
	PinnedCommit string `json:"pinned_commit"`
	SHA256       string `json:"sha256"`
	VendoredAt   string `json:"vendored_at"`
	VendoredFrom string `json:"vendored_from"`

	FindingSchemaVersion  string `json:"finding_schema_version"`
	DocumentSchemaVersion string `json:"document_schema_version"`

	// DocumentSchemaVersionsKillerReads is what Killer itself accepts. Giver
	// deliberately does not accept the same set; see contract.EnvelopeGate.
	DocumentSchemaVersionsKillerReads []string `json:"document_schema_versions_killer_reads"`

	// SemgrepPinnedByKiller is the Semgrep version the pinned Killer release
	// tests its rule pack against.
	//
	// It is part of the contract in every sense that matters here, even
	// though it is not in the schema. Giver proves a static fix by re-running
	// Killer's pack and reading the silence, and the silent half of that pack
	// is sensitive to the engine as well as to the rules -- which is why
	// Killer pins it in its own CI. Under a different engine the pack can go
	// quiet, and quiet is exactly what Giver reads as success.
	SemgrepPinnedByKiller string `json:"semgrep_pinned_by_killer"`
	SemgrepPinNote        string `json:"semgrep_pin_note"`

	Note string `json:"note"`
}

// Pinned returns the vendoring stamp.
func Pinned() Stamp {
	var s Stamp
	if err := json.Unmarshal(stampJSON, &s); err != nil {
		// stamp.json is embedded from this package's own directory and is
		// covered by a test, so a failure here means the build is corrupt.
		panic(fmt.Sprintf("killerschema: embedded stamp.json is not valid JSON: %v", err))
	}
	return s
}
