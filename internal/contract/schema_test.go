package contract

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/rohitanakiya/Vibe-Giver/internal/contract/killerschema"
)

// compiledKillerSchema compiles Killer's published per-finding schema.
func compiledKillerSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()

	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(killerschema.FindingSchema))
	if err != nil {
		t.Fatalf("vendored schema is not valid JSON: %v", err)
	}
	const id = "https://raw.githubusercontent.com/rohitanakiya/Vibe-Killer/main/schema/finding.schema.json"

	c := jsonschema.NewCompiler()
	if err := c.AddResource(id, doc); err != nil {
		t.Fatalf("adding the vendored schema: %v", err)
	}
	s, err := c.Compile(id)
	if err != nil {
		t.Fatalf("the vendored schema does not compile as draft 2020-12: %v", err)
	}
	return s
}

// TestRealFindingsValidateAgainstPublishedSchema is the binding the brief
// asks for, done against the schema itself rather than against a reading of
// it.
//
// The reflection test next door compares field names. This one runs Killer's
// published schema as a schema: the finding_id pattern, the CWE pattern, the
// closed enums, additionalProperties:false, and the three conditional
// contract rules in its allOf -- confirmed requires a reproduction, a secrets
// finding is never auto-fixable, a blast-radius finding carries its scope.
// Those conditionals are the part Giver leans on hardest and the part a
// hand-written struct check cannot see at all.
func TestRealFindingsValidateAgainstPublishedSchema(t *testing.T) {
	schema := compiledKillerSchema(t)

	raw, err := os.ReadFile(realRun)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Findings []json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Findings) != 53 {
		t.Fatalf("expected the 53-finding corpus, got %d", len(envelope.Findings))
	}

	for i, rawFinding := range envelope.Findings {
		inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(rawFinding))
		if err != nil {
			t.Fatalf("finding %d is not valid JSON: %v", i, err)
		}
		if err := schema.Validate(inst); err != nil {
			t.Errorf("finding %d does not validate against the published schema:\n%v", i, err)
		}
	}
}

// TestRoundTripThroughTheGoModelStaysValid is the direction that catches a
// lossy model.
//
// A struct missing a field parses happily and drops it. The reflection test
// catches a field the schema declares and the model omits, but not a field
// whose Go type or json tag quietly mangles the value -- an int where the
// schema says string, or an omitempty that erases a meaningful false. So
// every real finding is decoded into the Go model, re-encoded, and validated
// again. Anything the model cannot carry faithfully shows up here.
func TestRoundTripThroughTheGoModelStaysValid(t *testing.T) {
	schema := compiledKillerSchema(t)
	doc := loadReal(t)

	for _, f := range doc.Findings {
		reencoded, err := json.Marshal(f)
		if err != nil {
			t.Fatalf("%s: re-encoding: %v", f.FindingID, err)
		}
		inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(reencoded))
		if err != nil {
			t.Fatalf("%s: re-encoded finding is not valid JSON: %v", f.FindingID, err)
		}
		if err := schema.Validate(inst); err != nil {
			t.Errorf("%s survived parsing but does not validate after a round trip through the Go "+
				"model, so the model loses or mangles something the contract requires:\n%v",
				f.FindingID, err)
		}
	}
}

// TestTheSchemaRejectsWhatItShould proves the validator is actually asserting
// something.
//
// A schema that compiled but matched everything would make the two tests
// above pass vacuously, which is the same failure shape as a Semgrep rule
// that matches nothing: the output is identical to the healthy case. So each
// mutation below takes a real finding and breaks one rule the contract cares
// about, and the schema has to reject it.
func TestTheSchemaRejectsWhatItShould(t *testing.T) {
	schema := compiledKillerSchema(t)
	doc := loadReal(t)

	base, err := json.Marshal(doc.Findings[0])
	if err != nil {
		t.Fatal(err)
	}

	// Control: unmutated, it validates. Without this, a broken harness would
	// report every mutation as correctly rejected.
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(base))
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(inst); err != nil {
		t.Fatalf("the control finding does not validate, so this test proves nothing: %v", err)
	}

	mutations := []struct {
		name  string
		apply func(map[string]any)
	}{
		{"finding_id that is not vk- plus 12 hex", func(m map[string]any) {
			m["finding_id"] = "vk-not-a-hash"
		}},
		{"a category outside the enum", func(m map[string]any) {
			m["category"] = "vibes-based-failure"
		}},
		{"a severity outside the enum", func(m map[string]any) {
			m["severity"] = "catastrophic"
		}},
		{"a per-finding schema_version other than 1.0", func(m map[string]any) {
			m["schema_version"] = "1.1"
		}},
		{"a malformed CWE", func(m map[string]any) {
			m["cwe"] = "CWE-eighty-nine"
		}},
		{"an undeclared extra property", func(m map[string]any) {
			m["exploitability"] = "trivial"
		}},
		{"remediation without fixable_by_giver", func(m map[string]any) {
			rem := m["remediation"].(map[string]any)
			delete(rem, "fixable_by_giver")
		}},
		{"confirmed confidence with no reproduction", func(m map[string]any) {
			m["confidence"] = "confirmed"
			delete(m, "reproduction")
		}},
		{"a secrets finding claiming it is auto-fixable", func(m map[string]any) {
			m["source"] = "secrets"
			rem := m["remediation"].(map[string]any)
			rem["fixable_by_giver"] = true
		}},
		{"a blast-radius finding with no blast_radius block", func(m map[string]any) {
			m["source"] = "blast-radius"
			delete(m, "blast_radius")
		}},
		{"missing evidence.summary", func(m map[string]any) {
			ev := m["evidence"].(map[string]any)
			delete(ev, "summary")
		}},
	}

	for _, mut := range mutations {
		t.Run(mut.name, func(t *testing.T) {
			var m map[string]any
			if err := json.Unmarshal(base, &m); err != nil {
				t.Fatal(err)
			}
			mut.apply(m)
			mutated, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(mutated))
			if err != nil {
				t.Fatal(err)
			}
			if err := schema.Validate(inst); err == nil {
				t.Fatalf("the published schema accepted a finding that breaks the contract (%s), "+
					"so validating against it asserts less than it appears to", mut.name)
			}
		})
	}
}

// TestSchemaIdMatchesWhereItIsPublished keeps the vendored copy traceable to
// a URL a human can open, which is what the drift check in CI fetches.
func TestSchemaIdMatchesWhereItIsPublished(t *testing.T) {
	var head struct {
		ID     string `json:"$id"`
		Schema string `json:"$schema"`
	}
	if err := json.Unmarshal(killerschema.FindingSchema, &head); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(head.ID, "rohitanakiya/Vibe-Killer") {
		t.Errorf("$id does not point at Vibe Killer: %q", head.ID)
	}
	if !strings.Contains(head.Schema, "2020-12") {
		t.Errorf("$schema is %q; the compiler above assumes draft 2020-12", head.Schema)
	}
}
