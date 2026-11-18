package fix

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/rohitanakiya/Vibe-Giver/internal/contract"
)

// The real fixture sources. See testdata/PROVENANCE.md.
const (
	flaskVulnerable  = "flask-vulnerable-app.py"
	djangoVulnerable = "django-vulnerable-settings.py"
)

func inputFor(t *testing.T, f contract.Finding, file string) Input {
	t.Helper()
	return Input{
		Finding: f,
		Root:    "testdata",
		ReadFile: func(rel string) ([]byte, error) {
			return os.ReadFile(filepath.Join("testdata", rel))
		},
	}
}

// The two misconfiguration findings a real Killer scan produced against
// flask-vulnerable, copied from the run in internal/contract/testdata. Line
// numbers are the ones Killer reported.
func debugFinding() contract.Finding {
	return contract.Finding{
		SchemaVersion: contract.FindingSchemaVersion,
		FindingID:     "vk-47f8f97a0b2c",
		RuleID:        "misconfig.debug-mode-enabled",
		Category:      contract.CategoryMisconfiguration,
		Severity:      contract.SeverityCritical,
		Confidence:    contract.ConfidenceLikely,
		Source:        contract.SourceSAST,
		Status:        contract.StatusOpen,
		Location:      contract.Location{Type: contract.LocationCode, File: flaskVulnerable, Line: 277, EndLine: 277},
		Evidence:      contract.Evidence{Summary: "Debug mode is enabled.", EvidenceKey: "semgrep:debug-mode-enabled"},
		Remediation: contract.Remediation{
			Guidance:       `Drive this from configuration and default it off, for example debug=os.environ.get("FLASK_DEBUG") == "1".`,
			RootCauseHint:  "A development convenience is set unconditionally rather than from the environment.",
			FixableByGiver: true,
		},
	}
}

func corsFinding() contract.Finding {
	return contract.Finding{
		SchemaVersion: contract.FindingSchemaVersion,
		FindingID:     "vk-d19263a87798",
		RuleID:        "misconfig.cors-credentialed-wildcard",
		Category:      contract.CategoryMisconfiguration,
		Severity:      contract.SeverityHigh,
		Confidence:    contract.ConfidenceLikely,
		Source:        contract.SourceSAST,
		Status:        contract.StatusOpen,
		Location:      contract.Location{Type: contract.LocationCode, File: flaskVulnerable, Line: 104, EndLine: 104},
		Evidence: contract.Evidence{
			Summary:     "The response reflects the request Origin header while allowing credentials.",
			EvidenceKey: "semgrep:cors-origin-reflected-python",
		},
		Remediation: contract.Remediation{
			Guidance:       "Configure an explicit list of allowed origins and do not echo the Origin header.",
			RootCauseHint:  "The allowed origin is taken from the request instead of from configuration.",
			FixableByGiver: true,
		},
	}
}

// --- routing ---------------------------------------------------------------

func TestRegistryRoutesOnlyWhatItHandles(t *testing.T) {
	r := DefaultRegistry()

	for _, f := range []contract.Finding{debugFinding(), corsFinding()} {
		if _, ok := r.For(f); !ok {
			t.Errorf("no strategy for %s, which v0 is supposed to cover", f.RuleID)
		}
	}

	// Things v0 must NOT claim. A registry that matched these would produce
	// a confident edit for a category whose rule fidelity is still being
	// hardened upstream.
	for _, rule := range []string{
		"idor.missing-ownership-check",
		"injection.sql-string-built-from-input",
		"auth.jwt-not-verified",
		"deps.known-vulnerability",
		"misconfig.cors-reflection", // the dynamic twin, not a code finding
	} {
		f := debugFinding()
		f.RuleID = rule
		f.Evidence.EvidenceKey = "semgrep:" + rule
		if s, ok := r.For(f); ok {
			t.Errorf("%s was routed to %s; v0 covers security-misconfiguration only", rule, s.Name())
		}
	}

	// The JavaScript variant of the CORS rule shares the rule id and needs
	// different code, so the Python strategy must not take it.
	js := corsFinding()
	js.Evidence.EvidenceKey = "semgrep:cors-wildcard-with-credentials"
	js.Location.File = "server.js"
	if s, ok := r.For(js); ok {
		t.Errorf("the JavaScript CORS variant was routed to %s, which emits Python", s.Name())
	}
}

// --- debug mode ------------------------------------------------------------

// TestDebugModeMatchesThePatchedTwin checks the generated code against the
// answer key rather than against what this strategy happens to emit.
//
// flask-patched and django-patched are the same applications with every
// weakness correctly fixed, and Killer CI asserts they yield zero confirmed
// findings. So the patched twin is what "correct" means here, and both use
// exactly this shape.
func TestDebugModeMatchesThePatchedTwin(t *testing.T) {
	f := debugFinding()
	p, err := (&debugModeStrategy{}).Propose(inputFor(t, f, flaskVulnerable))
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	got := string(p.Edits[0].Content)

	// The vulnerable literal is gone.
	if strings.Contains(got, "debug=True") {
		t.Error("debug=True survived the fix")
	}
	// And the replacement is the one the patched fixture and Killer own
	// guidance both name.
	want := `debug=os.environ.get("FLASK_DEBUG") == "1"`
	if !strings.Contains(got, want) {
		t.Errorf("expected %s in the output", want)
	}
	// Nothing else moved: exactly one line differs from the original, since
	// os is already imported in this fixture.
	assertOnlyLinesChanged(t, readTestdata(t, flaskVulnerable), got, 1)

	if p.RootCause == "" || p.Rationale == "" {
		t.Error("a proposal must carry its rationale and root cause; they go in the pull request")
	}
	if len(p.EnvVars) != 1 || p.EnvVars[0].Name != "FLASK_DEBUG" {
		t.Errorf("the fix introduces configuration and must say so: %+v", p.EnvVars)
	}
}

func TestDebugModeHandlesTheDjangoForm(t *testing.T) {
	f := debugFinding()
	f.Location.File = djangoVulnerable
	f.Location.Line = 17 // DEBUG = True, as Killer reports it

	p, err := (&debugModeStrategy{}).Propose(inputFor(t, f, djangoVulnerable))
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	got := string(p.Edits[0].Content)

	// django-patched/config/settings.py line 19 is exactly this.
	want := `DEBUG = os.environ.get("DJANGO_DEBUG") == "1"`
	if !strings.Contains(got, want) {
		t.Errorf("expected %q (what django-patched does), got these DEBUG lines:\n%s",
			want, grepLines(got, "DEBUG"))
	}
	if strings.Contains(got, "DEBUG = True") {
		t.Error("DEBUG = True survived the fix")
	}
	if p.EnvVars[0].Name != "DJANGO_DEBUG" {
		t.Errorf("env var = %q, want DJANGO_DEBUG", p.EnvVars[0].Name)
	}
}

// TestDebugModeFailsClosed is the half that matters more. A strategy that
// edits something it does not understand is worse than one that refuses.
func TestDebugModeFailsClosed(t *testing.T) {
	s := &debugModeStrategy{}

	cases := []struct {
		name string
		line int
		why  string
	}{
		{"a line past the end of the file", 99999, "the finding and the file have diverged"},
		{"a line with no debug flag on it", 1, "the anchor points at something else"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := debugFinding()
			f.Location.Line = c.line
			if _, err := s.Propose(inputFor(t, f, flaskVulnerable)); err == nil {
				t.Fatalf("a fix was generated for %s", c.why)
			}
		})
	}

	t.Run("a file with no import block to add os to", func(t *testing.T) {
		dir := t.TempDir()
		// debug=True with no imports anywhere. The replacement needs os, and
		// guessing where an import belongs is how a tool corrupts a file.
		if err := os.WriteFile(filepath.Join(dir, "x.py"), []byte("app.run(debug=True)\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		f := debugFinding()
		f.Location.File = "x.py"
		f.Location.Line = 1
		in := Input{Finding: f, Root: dir, ReadFile: func(rel string) ([]byte, error) {
			return os.ReadFile(filepath.Join(dir, rel))
		}}
		_, err := s.Propose(in)
		if err == nil {
			t.Fatal("a fix was generated for a file with nowhere to put the import")
		}
		if !strings.Contains(err.Error(), "import os") {
			t.Errorf("the refusal should name the problem: %v", err)
		}
	})
}

// --- CORS ------------------------------------------------------------------

func TestCORSReplacesReflectionWithAnAllowlist(t *testing.T) {
	f := corsFinding()
	p, err := (&corsReflectionStrategy{}).Propose(inputFor(t, f, flaskVulnerable))
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	got := string(p.Edits[0].Content)

	// The reflection is gone, in the only sense that counts: no assignment
	// of a request-derived value into the header, directly or otherwise.
	if corsOriginAssign.MatchString(firstMatchingLine(got, "Access-Control-Allow-Origin")) {
		t.Error("the header is still assigned from request.headers")
	}
	for _, want := range []string{
		`_allowed_origins = {o.strip() for o in os.environ.get("CORS_ALLOWED_ORIGINS", "").split(",") if o.strip()}`,
		`_origin = request.headers.get("Origin", "")`,
		`if _origin in _allowed_origins:`,
		`["Access-Control-Allow-Origin"] = _origin`,
		`["Vary"] = "Origin"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing from the fix:\n  %s", want)
		}
	}

	// The credentials header has to move inside the guard, or the
	// credentialed half of the mistake survives. In the fixture it is the
	// line immediately after the anchor.
	if !insideGuard(got, `["Access-Control-Allow-Credentials"] = "true"`) {
		t.Error("Access-Control-Allow-Credentials is still set unconditionally")
	}

	// Defaults to deny. An unset variable must not reinstate the hole.
	if strings.Contains(got, `os.environ.get("CORS_ALLOWED_ORIGINS", "*")`) {
		t.Error("the allowlist defaults to a wildcard")
	}
	if len(p.EnvVars) != 1 || !p.EnvVars[0].Required {
		t.Errorf("the operator has to set the allowlist; that must be reported as required: %+v", p.EnvVars)
	}

	// Indentation preserved: the fixture block is inside a function.
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, "_allowed_origins = {") && !strings.HasPrefix(line, "    ") {
			t.Errorf("indentation lost: %q", line)
		}
	}
}

func TestCORSFailsClosed(t *testing.T) {
	s := &corsReflectionStrategy{}
	for _, line := range []int{1, 99999, 103} {
		f := corsFinding()
		f.Location.Line = line
		if _, err := s.Propose(inputFor(t, f, flaskVulnerable)); err == nil {
			t.Errorf("line %d: a fix was generated for a line that is not a reflected-origin assignment", line)
		}
	}
}

// TestAPatternDodgeSilencesTheRuleWithoutFixingAnything is the measurement
// behind this package design, and it is the reason strategies are constrained
// transformations instead of anything that makes a re-scan come back clean.
//
// The rule alternative that fires on the Flask fixture is a regex over
// "access-control-allow-origin ... = request.headers". Assigning the
// reflected origin to a local first satisfies it completely. The application
// is unchanged: every origin is still echoed back with credentials allowed.
//
// So this constructs that dodge, asserts the rule no longer matches it, and
// asserts the vulnerability is still there. If the dodge ever stops
// satisfying the rule, the comment above is wrong and this test says so.
func TestAPatternDodgeSilencesTheRuleWithoutFixingAnything(t *testing.T) {
	// Killer's actual rule text, from the published pack:
	//   (?i)access-control-allow-origin['"]?\s*\]?\s*=\s*request\.headers
	rule := killerCORSRegex()

	vulnerable := `    response.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "*")`
	if !rule.MatchString(vulnerable) {
		t.Fatal("the rule does not match the vulnerable line, so this test is not testing the rule")
	}

	dodge := strings.Join([]string{
		`    _o = request.headers.get("Origin", "*")`,
		`    response.headers["Access-Control-Allow-Origin"] = _o`,
	}, "\n")

	if rule.MatchString(dodge) {
		t.Fatal("the dodge still matches the rule; the premise of this package comment is wrong " +
			"and the design note should be corrected")
	}

	// It satisfies the rule. It fixes nothing: every origin is still
	// reflected, and whatever sets credentials is untouched.
	if !strings.Contains(dodge, `request.headers.get("Origin", "*")`) {
		t.Fatal("the dodge was supposed to keep reflecting the origin")
	}

	// And the real strategy output does not merely dodge: the header is
	// assigned a value that came from the allowlist check, not from the
	// request.
	f := corsFinding()
	p, err := (&corsReflectionStrategy{}).Propose(inputFor(t, f, flaskVulnerable))
	if err != nil {
		t.Fatal(err)
	}
	fixed := string(p.Edits[0].Content)
	if rule.MatchString(fixed) {
		t.Error("the real fix still matches the rule")
	}
	if !insideGuard(fixed, `["Access-Control-Allow-Origin"] = _origin`) {
		t.Error("the real fix sets the origin header outside the allowlist guard, which would make it " +
			"a dodge too")
	}
}

// killerCORSRegex is Killer published pattern-regex for the Python CORS
// alternative, written out so this test is about the real rule rather than
// about this package idea of it.
func killerCORSRegex() *regexp.Regexp {
	return regexp.MustCompile(`(?i)access-control-allow-origin['"]?\s*\]?\s*=\s*request\.headers`)
}

// --- the generated code has to be valid Python -----------------------------

// TestGeneratedPythonCompiles runs the real interpreter over the output.
//
// A strategy emits text, and text that looks right and does not parse is the
// most likely way an automated edit fails. The loop runs this as a gate; this
// test runs it on the strategy output directly so a broken template is caught
// here rather than three stages later.
//
// Skips cleanly without python, the way Killer Semgrep tests skip without
// Semgrep.
func TestGeneratedPythonCompiles(t *testing.T) {
	python := ""
	for _, c := range []string{"python3", "python", "py"} {
		if p, err := exec.LookPath(c); err == nil {
			python = p
			break
		}
	}
	if python == "" {
		t.Skip("no python interpreter on PATH")
	}

	cases := []struct {
		name string
		f    contract.Finding
		s    Strategy
	}{
		{"debug mode", debugFinding(), &debugModeStrategy{}},
		{"cors allowlist", corsFinding(), &corsReflectionStrategy{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := c.s.Propose(inputFor(t, c.f, c.f.Location.File))
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			out := filepath.Join(dir, "candidate.py")
			if err := os.WriteFile(out, p.Edits[0].Content, 0o644); err != nil {
				t.Fatal(err)
			}
			// py_compile rather than import: the fixture binds a port and
			// opens a database at import time.
			cmd := exec.Command(python, "-m", "py_compile", out)
			if combined, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("the generated file does not compile: %v\n%s", err, combined)
			}
		})
	}
}

// --- helpers ---------------------------------------------------------------

func readTestdata(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// assertOnlyLinesChanged keeps a fix reviewable. The brief asks for minimal
// diffs with no drive-by reformatting, and the cheapest way to hold a
// generator to that is to count.
func assertOnlyLinesChanged(t *testing.T, before, after string, want int) {
	t.Helper()
	b := strings.Split(strings.ReplaceAll(before, "\r\n", "\n"), "\n")
	a := strings.Split(strings.ReplaceAll(after, "\r\n", "\n"), "\n")
	if len(a) != len(b) {
		t.Errorf("the fix changed the line count from %d to %d; it should be a single-line replacement",
			len(b), len(a))
		return
	}
	var changed int
	for i := range b {
		if b[i] != a[i] {
			changed++
		}
	}
	if changed != want {
		t.Errorf("%d line(s) differ, want %d; a fix with drive-by edits is not reviewable", changed, want)
	}
}

func grepLines(s, needle string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, needle) {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

func firstMatchingLine(s, needle string) string {
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, needle) {
			return l
		}
	}
	return ""
}

// insideGuard reports whether the line containing needle is indented deeper
// than the nearest preceding `if _origin in _allowed_origins:`.
func insideGuard(content, needle string) bool {
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	guard := -1
	for i, l := range lines {
		if strings.Contains(l, "if _origin in _allowed_origins:") {
			guard = i
		}
		if guard >= 0 && strings.Contains(l, needle) {
			guardIndent := len(indentOf(lines[guard]))
			return len(indentOf(l)) > guardIndent
		}
	}
	return false
}
