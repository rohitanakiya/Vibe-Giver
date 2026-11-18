package fix

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/rohitanakiya/Vibe-Giver/internal/contract"
)

// corsReflectionStrategy fixes the Python form of
// misconfig.cors-credentialed-wildcard: a response that echoes the request
// Origin header back while allowing credentials.
//
// This is the strategy that demonstrates why a static re-scan is not enough
// on its own. The rule alternative that fires here is a regex:
//
//	(?i)access-control-allow-origin['"]?\s*\]?\s*=\s*request\.headers
//
// so assigning the reflected origin to a local variable first and then into
// the header satisfies the rule completely while leaving every site on the
// internet able to make credentialed calls. The re-scan would say gone. That
// dodge is written out and measured in the strategy test, which is the reason
// this package constrains what a strategy may emit instead of trusting the
// verification to catch a bad fix.
//
// The change made instead is the one both patched fixtures make: an explicit
// allowlist, with the headers set only for an origin on it. Here the list is
// read from the environment rather than written into the source, because
// Giver does not know which origins are legitimate and guessing would either
// break the application or reinstate the hole. Empty means deny, so the
// insecure default is not reachable by omission.
type corsReflectionStrategy struct{}

func (s *corsReflectionStrategy) Name() string {
	return "misconfig.cors-reflection/env-driven-allowlist"
}

func (s *corsReflectionStrategy) Handles(f contract.Finding) bool {
	if f.RuleID != "misconfig.cors-credentialed-wildcard" {
		return false
	}
	// The pack has a Python variant and a JavaScript one under this rule id,
	// and the fix is different code. The evidence key is the only language
	// discriminator the contract exposes.
	switch semgrepRule(f) {
	case "cors-origin-reflected-python":
		return true
	case "":
		// No evidence key: fall back to the file extension rather than
		// assuming, and let Propose refuse if the line is not Python.
		return strings.HasSuffix(f.Location.File, ".py")
	default:
		return false
	}
}

var (
	// The reflected assignment this strategy replaces. The header name is
	// matched case-insensitively because the rule is.
	corsOriginAssign = regexp.MustCompile(
		`(?i)^(\s*)(.*)\[\s*["']access-control-allow-origin["']\s*\]\s*=\s*(request\.headers.*)$`)

	// The credentials line, which is always separate: two regexes in one
	// Semgrep patterns block must match the same range, and these headers are
	// set on different lines, which is why the rule matches the reflection
	// alone.
	corsCredentialsAssign = regexp.MustCompile(
		`(?i)^\s*(.*)\[\s*["']access-control-allow-credentials["']\s*\]\s*=\s*["']true["']\s*$`)
)

// AllowlistEnvVar is the variable the generated code reads.
const AllowlistEnvVar = "CORS_ALLOWED_ORIGINS"

func (s *corsReflectionStrategy) Propose(in Input) (*Proposal, error) {
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

	m := corsOriginAssign.FindStringSubmatch(line)
	if m == nil {
		return nil, errUnrecognized(f, fmt.Sprintf(
			"not an Access-Control-Allow-Origin assignment from request.headers that this build can "+
				"rewrite: %q", strings.TrimSpace(line)))
	}
	indent, responseExpr := m[1], strings.TrimSpace(m[2])
	if responseExpr == "" {
		return nil, errUnrecognized(f, "an assignment with no response object to key into")
	}

	// The credentials header is what turns a permissive origin into a
	// credentialed one, so it moves inside the guard with the origin. It is
	// looked for only immediately around the anchor: a match further away
	// might belong to a different handler.
	credLine := -1
	for _, probe := range []int{f.Location.Line + 1, f.Location.Line - 1} {
		if l, ok := lf.at(probe); ok && corsCredentialsAssign.MatchString(l) {
			credLine = probe
			break
		}
	}

	// Build the replacement block.
	allowSet := fmt.Sprintf(
		`%s_allowed_origins = {o.strip() for o in os.environ.get(%q, "").split(",") if o.strip()}`,
		indent, AllowlistEnvVar)
	readOrigin := fmt.Sprintf(`%s_origin = request.headers.get("Origin", "")`, indent)
	guard := fmt.Sprintf(`%sif _origin in _allowed_origins:`, indent)
	setOrigin := fmt.Sprintf(`%s    %s["Access-Control-Allow-Origin"] = _origin`, indent, responseExpr)
	// Vary: Origin is not decoration. The response now differs by request
	// origin, and a shared cache that does not know that will serve one
	// origin allowed response to another.
	setVary := fmt.Sprintf(`%s    %s["Vary"] = "Origin"`, indent, responseExpr)

	block := []string{allowSet, readOrigin, guard, setOrigin}
	if credLine > 0 {
		block = append(block, fmt.Sprintf(`%s    %s["Access-Control-Allow-Credentials"] = "true"`, indent, responseExpr))
	}
	block = append(block, setVary)

	// Replace the anchored line with the block, and remove the credentials
	// line that moved into the guard. Highest line number first, so the
	// earlier index stays valid.
	if credLine > f.Location.Line {
		lf.lines = append(lf.lines[:credLine-1], lf.lines[credLine:]...)
		lf.lines = replaceLine(lf.lines, f.Location.Line, block)
	} else if credLine > 0 {
		lf.lines = replaceLine(lf.lines, f.Location.Line, block)
		lf.lines = append(lf.lines[:credLine-1], lf.lines[credLine:]...)
	} else {
		lf.lines = replaceLine(lf.lines, f.Location.Line, block)
	}

	addedImport, importOK := ensureImport(lf, "os")
	if !importOK {
		return nil, fmt.Errorf(
			"%s needs `import os` for the allowlist expression, and no top-level import statement was "+
				"found in %s to add it beside; refusing to guess where it belongs",
			f.FindingID, f.Location.File)
	}

	var rationale strings.Builder
	rationale.WriteString(
		"Replaced the reflected Origin header with an explicit allowlist.\n\n" +
			"Before, the response echoed whatever Origin the request carried and allowed credentials " +
			"with it, which is the same thing as allowing every site on the internet to call this API " +
			"as any logged-in user and read the response. Now the headers are set only when the origin " +
			"is on the allowlist.\n\n" +
			"The list is read from the environment rather than written into the source, because the " +
			"legitimate origins for this application are not something that can be inferred from it. " +
			"An unset or empty variable denies every cross-origin request, so the permissive behaviour " +
			"cannot come back by leaving configuration out.")
	if credLine > 0 {
		rationale.WriteString(
			"\n\nThe Access-Control-Allow-Credentials header moved inside the same guard. Leaving it " +
				"unconditional would keep the credentialed half of the original mistake.")
	}
	rationale.WriteString(
		"\n\nAdded a Vary: Origin header: the response now differs by request origin, and a shared " +
			"cache that does not know that can serve a response allowed for one origin to another.")
	if addedImport {
		rationale.WriteString("\n\nAdded `import os`, which the allowlist expression needs.")
	}

	return &Proposal{
		Strategy:  s.Name(),
		Edits:     []FileEdit{{Path: f.Location.File, Content: lf.bytes()}},
		Rationale: rationale.String(),
		RootCause: "The allowed origin was taken from the request instead of from configuration, which " +
			"makes the check vacuous: it always allows whoever is asking.",
		SiblingNote: s.siblings(lf, f),
		EnvVars: []EnvVar{{
			Name: AllowlistEnvVar,
			Purpose: "comma-separated list of origins allowed to make credentialed cross-origin " +
				"requests, for example https://app.example.com,http://localhost:5173",
			Default:  "unset, which denies every cross-origin request",
			Required: true,
		}},
	}, nil
}

func replaceLine(lines []string, n int, with []string) []string {
	out := make([]string, 0, len(lines)+len(with)-1)
	out = append(out, lines[:n-1]...)
	out = append(out, with...)
	out = append(out, lines[n:]...)
	return out
}

// siblings reports other reflected-origin assignments left in the same file.
func (s *corsReflectionStrategy) siblings(lf *lineFile, f contract.Finding) string {
	var others []int
	for i, line := range lf.lines {
		if corsOriginAssign.MatchString(line) {
			others = append(others, i+1)
		}
	}
	if len(others) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s still reflects the request Origin at line", f.Location.File)
	if len(others) > 1 {
		b.WriteString("s")
	}
	for i, n := range others {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, " %d", n)
	}
	b.WriteString(". This change is scoped to the line the finding points at and only that one has been " +
		"verified, so the class is not closed. Only the files in this diff were searched.")
	return b.String()
}

// EnvVarName is exported for the report, which lists what an operator has to
// set before deploying the change.
func (s *corsReflectionStrategy) EnvVarName() string { return AllowlistEnvVar }

var _ = contract.CategoryMisconfiguration
