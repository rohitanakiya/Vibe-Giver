package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/rohitanakiya/Vibe-Giver/internal/contract/killerschema"
)

const realRun = "testdata/flask-vulnerable-static-only.json"

func loadReal(t *testing.T) *Document {
	t.Helper()
	doc, err := LoadDocument(realRun)
	if err != nil {
		t.Fatalf("loading the real Killer run: %v", err)
	}
	return doc
}

// --- the drift the brief and the roadmap both got wrong ---------------------

// TestEnvelopeVersionMatchesTheArtifactNotTheDocuments is the test Step 0
// exists for.
//
// The build brief says the Document envelope is at 1.1, and the project
// roadmap says the same. The artifact says 1.2. Two documents agreeing with
// each other against the thing they describe is exactly the drift this
// package is supposed to make impossible, so the constant is asserted against
// a real run rather than against either document.
func TestEnvelopeVersionMatchesTheArtifactNotTheDocuments(t *testing.T) {
	doc := loadReal(t)

	if doc.SchemaVersion != DocumentSchemaVersion {
		t.Fatalf("the pinned Killer binary wrote schema_version %q but this build is written against %q",
			doc.SchemaVersion, DocumentSchemaVersion)
	}
	if doc.SchemaVersion == "1.1" {
		t.Fatalf("envelope is 1.1 after all; the brief was right and this package comment is wrong")
	}
	if got := killerschema.Pinned().DocumentSchemaVersion; got != doc.SchemaVersion {
		t.Errorf("stamp records envelope %q, real run wrote %q", got, doc.SchemaVersion)
	}
}

func TestEnvelopeGate(t *testing.T) {
	cases := []struct {
		version string
		accept  bool
		why     string
	}{
		{"1.2", true, "the version the pinned binary writes"},
		{"1.1", true, "older, and its fields still mean what they meant"},
		{"1.0", true, "older still; readable, but Trust downgrades it"},
		{"1.3", false, "newer: may carry a non-coverage field this build cannot read"},
		{"2.0", false, "newer major"},
		{"1.2.1", false, "not a version Killer ships"},
		{"", false, "no version at all"},
		{"banana", false, "not a version"},
	}

	for _, c := range cases {
		err := checkEnvelopeVersion("x/findings.json", c.version)
		if c.accept && err != nil {
			t.Errorf("version %q (%s): refused, want accepted: %v", c.version, c.why, err)
		}
		if !c.accept && err == nil {
			t.Errorf("version %q (%s): accepted, want refused", c.version, c.why)
		}
	}
}

// TestNewerEnvelopeSaysWhyItRefuses checks that the refusal explains the
// consequence, because the operator reading it has to decide whether to
// upgrade or to re-scan, and "unsupported version" does not tell them.
func TestNewerEnvelopeSaysWhyItRefuses(t *testing.T) {
	err := checkEnvelopeVersion("x", "1.9")
	if err == nil {
		t.Fatal("1.9 was accepted")
	}
	var ee *EnvelopeError
	if !asEnvelopeError(err, &ee) {
		t.Fatalf("got %T, want *EnvelopeError", err)
	}
	for _, want := range []string{"reported as fixed", "Upgrade Vibe Giver"} {
		if !strings.Contains(ee.Error(), want) {
			t.Errorf("refusal does not mention %q:\n%s", want, ee.Error())
		}
	}
}

func asEnvelopeError(err error, out **EnvelopeError) bool {
	if e, ok := err.(*EnvelopeError); ok {
		*out = e
		return true
	}
	return false
}

// TestUnknownEnvelopeKeyIsRefused feeds the real document back with one extra
// top-level array, which is what a future Killer adding a third kind of
// non-coverage without bumping the envelope would look like.
func TestUnknownEnvelopeKeyIsRefused(t *testing.T) {
	raw, err := os.ReadFile(realRun)
	if err != nil {
		t.Fatal(err)
	}

	// Control: unmodified, it parses.
	if _, err := ParseDocument(realRun, raw); err != nil {
		t.Fatalf("the real run should parse: %v", err)
	}

	var bag map[string]json.RawMessage
	if err := json.Unmarshal(raw, &bag); err != nil {
		t.Fatal(err)
	}
	bag["deselected"] = json.RawMessage(`[{"check_id":"idor.sequential-id-access","reason":"not scheduled"}]`)
	mutated, err := json.Marshal(bag)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ParseDocument("mutated", mutated)
	if err == nil {
		t.Fatal("a document with an unmodelled top-level coverage array was accepted; " +
			"those findings would be absent for a reason this build cannot read, and would be reported as fixed")
	}
	if !strings.Contains(err.Error(), "deselected") {
		t.Errorf("refusal does not name the offending key: %v", err)
	}

	// Which mechanism refused it matters, and asserting only that it was
	// refused could not tell. Two things in ParseDocument reject this
	// document: the explicit top-level key check, and DisallowUnknownFields
	// on the Document decode that follows it. Disabling the first one was
	// measured to leave this test passing, which made it a test of neither.
	//
	// So the assertion is on the explanation only the explicit check
	// produces. The stdlib refusal says `json: unknown field "deselected"`
	// and stops there; an operator reading that has no way to know it means
	// their verification results may be wrong.
	if !strings.Contains(err.Error(), "turn unchecked findings into fixed ones") {
		t.Errorf("the refusal came from somewhere other than the envelope key check, so that check "+
			"is untested and could be deleted without failing anything:\n%v", err)
	}
}

// TestUnknownKeysIsolated tests the key check on its own, since the loader
// has a second mechanism that masks it.
func TestUnknownKeysIsolated(t *testing.T) {
	bag := map[string]json.RawMessage{}
	for _, k := range documentTopLevelKeys {
		bag[k] = json.RawMessage(`null`)
	}
	if got := unknownKeys(bag); len(got) != 0 {
		t.Errorf("every modelled key was reported unknown: %v", got)
	}

	bag["timed_out"] = json.RawMessage(`[]`)
	bag["deselected"] = json.RawMessage(`[]`)
	got := unknownKeys(bag)
	if len(got) != 2 || got[0] != "deselected" || got[1] != "timed_out" {
		t.Errorf("unknownKeys = %v, want [deselected timed_out] sorted", got)
	}
}

// TestUnknownNestedFieldIsRefused does the same one level down: a new field on
// a finding could change what the finding means.
func TestUnknownNestedFieldIsRefused(t *testing.T) {
	raw, err := os.ReadFile(realRun)
	if err != nil {
		t.Fatal(err)
	}
	var bag map[string]any
	if err := json.Unmarshal(raw, &bag); err != nil {
		t.Fatal(err)
	}
	findings := bag["findings"].([]any)
	findings[0].(map[string]any)["exploitability"] = "trivial"
	mutated, _ := json.Marshal(bag)

	if _, err := ParseDocument("mutated", mutated); err == nil {
		t.Fatal("a finding carrying an unmodelled field was accepted")
	}
}

// --- the vendored schema ---------------------------------------------------

func TestVendoredSchemaMatchesItsStamp(t *testing.T) {
	sum := sha256.Sum256(killerschema.FindingSchema)
	got := hex.EncodeToString(sum[:])
	stamp := killerschema.Pinned()

	if got != stamp.SHA256 {
		t.Errorf("vendored schema hashes to %s but the stamp says %s; one of them was edited",
			got, stamp.SHA256)
	}
	if stamp.PinnedTag == "" || stamp.PinnedCommit == "" {
		t.Error("the stamp does not say which Killer artifact the schema came from")
	}
	if stamp.FindingSchemaVersion != FindingSchemaVersion {
		t.Errorf("stamp says per-finding schema %q, this build speaks %q",
			stamp.FindingSchemaVersion, FindingSchemaVersion)
	}
}

// TestGoModelMatchesPublishedSchema is the field-by-field binding, in both
// directions.
//
// One direction catches a field Killer added that Giver does not read. The
// other catches a field Giver invented that the contract does not have, which
// is how a consumer ends up depending on something the producer never
// promised. Checking only one direction would let the model drift the other
// way in silence.
func TestGoModelMatchesPublishedSchema(t *testing.T) {
	var schema struct {
		Required   []string `json:"required"`
		Properties map[string]struct {
			Properties map[string]json.RawMessage `json:"properties"`
			Enum       []string                   `json:"enum"`
			Const      *string                    `json:"const"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(killerschema.FindingSchema, &schema); err != nil {
		t.Fatalf("vendored schema is not readable: %v", err)
	}

	goFields := jsonTagsOf(reflect.TypeOf(Finding{}))
	schemaFields := make([]string, 0, len(schema.Properties))
	for k := range schema.Properties {
		schemaFields = append(schemaFields, k)
	}

	if missing := difference(schemaFields, goFields); len(missing) > 0 {
		t.Errorf("the published schema has field(s) the Go model does not read: %v\n"+
			"a contract field Giver ignores is a fact about the finding it is deciding without", missing)
	}
	if extra := difference(goFields, schemaFields); len(extra) > 0 {
		t.Errorf("the Go model has field(s) the published schema does not define: %v\n"+
			"Giver would be depending on something Killer never promised", extra)
	}

	// Nested objects matter as much as the top level: evidence.request is
	// where a credential could leak into a pull request body.
	nested := map[string]reflect.Type{
		"location":     reflect.TypeOf(Location{}),
		"evidence":     reflect.TypeOf(Evidence{}),
		"reproduction": reflect.TypeOf(Reproduction{}),
		"blast_radius": reflect.TypeOf(BlastRadius{}),
		"remediation":  reflect.TypeOf(Remediation{}),
	}
	for name, typ := range nested {
		prop, ok := schema.Properties[name]
		if !ok {
			t.Errorf("schema has no %q object", name)
			continue
		}
		var want []string
		for k := range prop.Properties {
			want = append(want, k)
		}
		got := jsonTagsOf(typ)
		if missing := difference(want, got); len(missing) > 0 {
			t.Errorf("%s: schema field(s) not modelled: %v", name, missing)
		}
		if extra := difference(got, want); len(extra) > 0 {
			t.Errorf("%s: modelled field(s) not in schema: %v", name, extra)
		}
	}
}

// TestEnumsMatchPublishedSchema pins every closed value set. A category Giver
// does not know is a finding it would route to no strategy at all.
func TestEnumsMatchPublishedSchema(t *testing.T) {
	var schema struct {
		Properties map[string]struct {
			Enum []string `json:"enum"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(killerschema.FindingSchema, &schema); err != nil {
		t.Fatal(err)
	}

	check := func(field string, got []string) {
		want := schema.Properties[field].Enum
		if len(want) == 0 {
			t.Fatalf("schema defines no enum for %q", field)
		}
		if missing := difference(want, got); len(missing) > 0 {
			t.Errorf("%s: schema value(s) this build does not know: %v", field, missing)
		}
		if extra := difference(got, want); len(extra) > 0 {
			t.Errorf("%s: value(s) this build invented: %v", field, extra)
		}
	}

	var cats []string
	for _, c := range AllCategories {
		cats = append(cats, string(c))
	}
	check("category", cats)

	var srcs []string
	for _, s := range AllSources {
		srcs = append(srcs, string(s))
	}
	check("source", srcs)

	check("severity", []string{
		string(SeverityInfo), string(SeverityLow), string(SeverityMedium),
		string(SeverityHigh), string(SeverityCritical),
	})
	check("confidence", []string{
		string(ConfidenceHeuristic), string(ConfidenceLikely), string(ConfidenceConfirmed),
	})
	check("status", []string{
		string(StatusOpen), string(StatusFixed), string(StatusRegressed),
		string(StatusAccepted), string(StatusFalsePositive),
	})
}

func jsonTagsOf(t reflect.Type) []string {
	var out []string
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		out = append(out, strings.Split(tag, ",")[0])
	}
	sort.Strings(out)
	return out
}

func difference(a, b []string) []string {
	have := make(map[string]bool, len(b))
	for _, x := range b {
		have[x] = true
	}
	var out []string
	for _, x := range a {
		if !have[x] {
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

// --- what the real run actually contains -----------------------------------

func TestRealRunShape(t *testing.T) {
	doc := loadReal(t)

	if got := len(doc.Findings); got != 53 {
		t.Errorf("findings = %d, want 53", got)
	}
	if got := len(doc.Skipped); got != 11 {
		t.Errorf("skipped = %d, want 11", got)
	}
	if got := len(doc.Failed); got != 0 {
		t.Errorf("failed = %d, want 0 (the key is omitted when empty)", got)
	}
	if doc.Trust() != CoverageReported {
		t.Error("a 1.2 envelope should report coverage")
	}
	if doc.NonCoverage().Silent() {
		t.Error("a run with 11 skipped checks is not silent about coverage")
	}

	// Every finding carries the pinned per-finding version.
	for _, f := range doc.Findings {
		if f.SchemaVersion != FindingSchemaVersion {
			t.Fatalf("%s: schema_version %q", f.FindingID, f.SchemaVersion)
		}
	}
}

// TestEveryFindingHasAKnownProducer is the join Giver verifies with, measured
// against every finding in a real run rather than asserted for the two cases
// that were convenient to think about.
func TestEveryFindingHasAKnownProducer(t *testing.T) {
	doc := loadReal(t)

	// The fourteen checks the pinned binary registers, as `vibekiller checks`
	// prints them.
	registered := map[string]bool{
		"engine.semgrep": true, "engine.osv-scanner": true, "engine.gitleaks": true,
		"authz.unprotected-endpoint": true, "idor.sequential-id-access": true,
		"injection.sql-differential": true, "misconfig.cors-reflection": true,
		"misconfig.missing-security-headers": true, "misconfig.verbose-error": true,
		"ssrf.internal-canary-fetch": true, "traversal.path-escape": true,
		"runtime.auth-check-not-fired": true, "runtime.query-missing-owner-filter": true,
		"exposure.shared-trust-domain": true,
	}

	for _, f := range doc.Findings {
		id, ok := ProducingCheckID(f)
		if !ok {
			t.Errorf("%s (%s, source %s): no producing check", f.FindingID, f.RuleID, f.Source)
			continue
		}
		if !registered[id] {
			t.Errorf("%s: producing check %q is not one the pinned binary registers", f.FindingID, id)
		}
		// The scanner engines are the whole reason this is not a rule-id
		// join: their findings carry rule ids that are not check ids.
		if f.Source == SourceDeps && id == f.RuleID {
			t.Errorf("%s: deps finding joined on its own rule id %q; engine.osv-scanner emits "+
				"deps.known-vulnerability, so that join cannot work", f.FindingID, f.RuleID)
		}
	}

	if _, ok := ProducingCheckID(Finding{Source: "quantum-analysis", RuleID: "x.y"}); ok {
		t.Error("an unknown source produced a check id; it must fail closed instead")
	}
}

// TestSkipsJoinToTheChecksThatWereDeselected confirms the eleven skips in the
// real run are the layers --static-only never schedules, and that they map to
// sources through Killer's own layer mapping.
func TestSkipsJoinToTheChecksThatWereDeselected(t *testing.T) {
	doc := loadReal(t)
	byLayer := map[string]int{}
	for _, s := range doc.Skipped {
		if s.Reason == "" {
			t.Errorf("skip of %s carries no reason, so there is nothing to report", s.CheckID)
		}
		if _, ok := SourceForLayer(s.Layer); !ok {
			t.Errorf("skip of %s is on layer %q, which this build cannot map to a source",
				s.CheckID, s.Layer)
		}
		byLayer[s.Layer]++
	}
	want := map[string]int{"endpoint": 8, "runtime": 2, "exposure": 1}
	if !reflect.DeepEqual(byLayer, want) {
		t.Errorf("skipped layers = %v, want %v", byLayer, want)
	}
}

func TestLayerMappingKnowsTheTwoThatDoNotMatchTheirNames(t *testing.T) {
	if got, _ := SourceForLayer("endpoint"); got != SourceDAST {
		t.Errorf("endpoint -> %q, want dast", got)
	}
	if got, _ := SourceForLayer("exposure"); got != SourceBlastRadius {
		t.Errorf("exposure -> %q, want blast-radius", got)
	}
	if _, ok := SourceForLayer("quantum"); ok {
		t.Error("an unknown layer mapped to a source")
	}
}

func TestStampPathsResolve(t *testing.T) {
	if _, err := os.Stat(filepath.Join("killerschema", "finding.schema.json")); err != nil {
		t.Errorf("vendored schema is not on disk: %v", err)
	}
	if len(killerschema.FindingSchema) < 1000 {
		t.Errorf("embedded schema is %d bytes, which is too small to be the real one; "+
			"an embed that silently matched nothing is how a published binary ends up without its assets",
			len(killerschema.FindingSchema))
	}
}
