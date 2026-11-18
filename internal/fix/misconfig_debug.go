package fix

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/rohitanakiya/Vibe-Giver/internal/contract"
)

// debugModeStrategy fixes misconfig.debug-mode-enabled.
//
// The root cause Killer states is "a development convenience is set
// unconditionally rather than from the environment", and its guidance names
// the exact replacement: debug=os.environ.get("FLASK_DEBUG") == "1". That is
// also, independently, what the patched twin of every affected fixture does --
// flask-patched uses FLASK_DEBUG and django-patched uses DJANGO_DEBUG, both in
// that shape. So the transformation is not invented here; it is the one the
// project already treats as correct, and the fixture pair is the answer key
// the strategy test checks against.
//
// Defaulting to off is the point. The expression is false unless the variable
// is exactly "1", so a deployed instance that sets nothing gets the debugger
// disabled, and enabling it is a deliberate act in the environment rather
// than an edit to the source.
type debugModeStrategy struct{}

func (s *debugModeStrategy) Name() string { return "misconfig.debug-mode/env-driven-default-off" }

func (s *debugModeStrategy) Handles(f contract.Finding) bool {
	return f.RuleID == "misconfig.debug-mode-enabled"
}

// The forms the rule matches, each paired with the environment variable the
// framework conventionally uses. The rule pattern-either list is the source
// of this set, so a form the rule can report always has an entry or is
// explicitly refused.
var debugForms = []struct {
	// pattern matches the vulnerable fragment on the anchored line.
	pattern *regexp.Regexp
	// replacement is the fragment that replaces it, with %s for the env var.
	replacement string
	envVar      string
	purpose     string
	describe    string
}{
	{
		// app.run(..., debug=True, ...) and FastAPI(..., debug=True, ...)
		pattern:     regexp.MustCompile(`\bdebug\s*=\s*True\b`),
		replacement: `debug=os.environ.get(%q) == "1"`,
		envVar:      "FLASK_DEBUG",
		purpose:     "set to 1 to enable the interactive debugger locally; anything else leaves it off",
		describe:    "a debug=True keyword argument",
	},
	{
		// uvicorn.run(..., reload=True, ...)
		pattern:     regexp.MustCompile(`\breload\s*=\s*True\b`),
		replacement: `reload=os.environ.get(%q) == "1"`,
		envVar:      "UVICORN_RELOAD",
		purpose:     "set to 1 to enable the autoreloader locally; anything else leaves it off",
		describe:    "a reload=True keyword argument",
	},
	{
		// Django settings: DEBUG = True
		pattern:     regexp.MustCompile(`^(\s*)DEBUG\s*=\s*True\s*$`),
		replacement: `DEBUG = os.environ.get(%q) == "1"`,
		envVar:      "DJANGO_DEBUG",
		purpose:     "set to 1 to enable Django debug pages locally; anything else leaves them off",
		describe:    "a module-level DEBUG = True",
	},
	{
		// app.debug = True
		pattern:     regexp.MustCompile(`\.debug\s*=\s*True\b`),
		replacement: `.debug = os.environ.get(%q) == "1"`,
		envVar:      "FLASK_DEBUG",
		purpose:     "set to 1 to enable the interactive debugger locally; anything else leaves it off",
		describe:    "an app.debug = True assignment",
	},
	{
		// app.config["DEBUG"] = True
		pattern:     regexp.MustCompile(`(\[\s*["']DEBUG["']\s*\])\s*=\s*True\b`),
		replacement: `["DEBUG"] = os.environ.get(%q) == "1"`,
		envVar:      "FLASK_DEBUG",
		purpose:     "set to 1 to enable the interactive debugger locally; anything else leaves it off",
		describe:    "a config[\"DEBUG\"] = True assignment",
	},
	{
		// app.config.update(..., DEBUG=True, ...)
		pattern:     regexp.MustCompile(`\bDEBUG\s*=\s*True\b`),
		replacement: `DEBUG=os.environ.get(%q) == "1"`,
		envVar:      "FLASK_DEBUG",
		purpose:     "set to 1 to enable the interactive debugger locally; anything else leaves it off",
		describe:    "a DEBUG=True keyword argument",
	},
}

func (s *debugModeStrategy) Propose(in Input) (*Proposal, error) {
	f := in.Finding
	if f.Location.File == "" {
		return nil, fmt.Errorf("%s carries no file to edit", f.FindingID)
	}

	content, err := in.ReadFile(f.Location.File)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", f.Location.File, err)
	}
	lf := splitLines(content)

	line, ok := lf.at(f.Location.Line)
	if !ok {
		return nil, fmt.Errorf(
			"%s points at %s:%d but the file has %d lines; the finding and the file have diverged, "+
				"so no edit is attempted",
			f.FindingID, f.Location.File, f.Location.Line, len(lf.lines))
	}

	// The anchored line is the only line considered. Searching the file for
	// something to change would turn a stale line number into an edit
	// somewhere the finding never pointed at.
	var (
		fixed   string
		matched bool
		form    int
	)
	for i, candidate := range debugForms {
		if !candidate.pattern.MatchString(line) {
			continue
		}
		replacement := fmt.Sprintf(candidate.replacement, candidate.envVar)
		if i == 2 {
			// The Django form matches the whole line, so the indentation it
			// captured has to be put back.
			fixed = indentOf(line) + replacement
		} else {
			fixed = candidate.pattern.ReplaceAllString(line, replacement)
		}
		matched, form = true, i
		break
	}
	if !matched {
		return nil, errUnrecognized(f, fmt.Sprintf("not a debug flag this build recognizes: %q", strings.TrimSpace(line)))
	}

	chosen := debugForms[form]
	lf.lines[f.Location.Line-1] = fixed

	// The replacement calls os.environ, so os has to be imported. A file
	// with no import block at all is refused rather than guessed at.
	addedImport, importOK := ensureImport(lf, "os")
	if !importOK {
		return nil, fmt.Errorf(
			"%s needs `import os` for the replacement expression, and no top-level import statement was "+
				"found in %s to add it beside; refusing to guess where it belongs",
			f.FindingID, f.Location.File)
	}

	rationale := fmt.Sprintf(
		"Replaced %s with a value read from the environment, defaulting to off.\n\n"+
			"The expression is false unless %s is exactly \"1\", so an instance that sets nothing has the "+
			"debugger disabled. Enabling it is now a deliberate change to the environment rather than an "+
			"edit to the source, which is what stops it reaching a deployed instance by accident.",
		chosen.describe, chosen.envVar)
	if addedImport {
		rationale += "\n\nAdded `import os`, which the new expression needs."
	}

	siblings := s.siblings(in, f)

	return &Proposal{
		Strategy:  s.Name(),
		Edits:     []FileEdit{{Path: f.Location.File, Content: lf.bytes()}},
		Rationale: rationale,
		RootCause: "A development convenience was set unconditionally in the source rather than read from " +
			"configuration, so it shipped with the code.",
		SiblingNote: siblings,
		EnvVars: []EnvVar{{
			Name:     chosen.envVar,
			Purpose:  chosen.purpose,
			Default:  "unset, which means off",
			Required: false,
		}},
	}, nil
}

// siblings reports the same pattern elsewhere in the same file.
//
// The brief asks for the broader pattern to be named even when the landed fix
// is scoped, so the reviewer knows whether the class is closed. Scope is the
// one file on purpose: a repository-wide search belongs to the cross-file
// work in v2, and claiming to have looked everywhere when only one file was
// read would be the same overclaim this tool exists to avoid.
func (s *debugModeStrategy) siblings(in Input, f contract.Finding) string {
	content, err := in.ReadFile(f.Location.File)
	if err != nil {
		return ""
	}
	lf := splitLines(content)

	var others []int
	for i, line := range lf.lines {
		if i+1 == f.Location.Line {
			continue
		}
		for _, candidate := range debugForms {
			if candidate.pattern.MatchString(line) {
				others = append(others, i+1)
				break
			}
		}
	}
	if len(others) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "The same pattern appears elsewhere in %s, at line", f.Location.File)
	if len(others) > 1 {
		b.WriteString("s")
	}
	for i, n := range others {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, " %d", n)
	}
	b.WriteString(". Those were left alone: this change is scoped to the line the finding points at, " +
		"and only this one has been verified. Only the files in this diff were searched.")
	return b.String()
}
