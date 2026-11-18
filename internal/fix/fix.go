// Package fix generates candidate code changes for findings.
//
// The model proposes, the loop disposes: nothing here is trusted. Every
// proposal goes through the gates in internal/loop, and a proposal that
// cannot be proven is discarded along with its branch.
//
// Two rules shape every strategy in this package.
//
// Fail closed. A strategy that does not recognize the code it was pointed at
// returns an error rather than its best guess. The brief calls this "never
// fabricate a fix"; concretely, a textual edit that happens to satisfy a rule
// is worse than no edit, because it is indistinguishable from a real fix in
// every report and the vulnerability is still there.
//
// Fix the cause, not the pattern. This matters more than it sounds, and is
// the reason strategies are constrained transformations rather than anything
// that makes a re-scan come back clean. A static re-scan proves that a rule
// no longer matches, which is necessary and not sufficient: the CORS rule
// here is a regex over "Access-Control-Allow-Origin = request.headers", and
// assigning the reflected origin through a local variable first silences it
// while changing nothing at all. That is not hypothetical -- it is measured
// in TestAPatternDodgeSilencesTheRuleWithoutFixingAnything. So the output of
// a strategy has to be a change a reviewer would recognize as the fix, and
// where Killer declares a behavioural twin for a static rule, the loop asks
// for that confirmation too.
package fix

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rohitanakiya/Vibe-Giver/internal/contract"
	"github.com/rohitanakiya/Vibe-Giver/internal/project"
)

// FileEdit is the whole new content of one file.
//
// Whole content rather than a patch, because the loop writes it into an
// isolated worktree and lets git compute the diff. One source of truth for
// what changed, and it is the one shown to the reviewer.
type FileEdit struct {
	// Path is repo-relative, forward slashes, as Killer reports it.
	Path    string
	Content []byte
}

// Proposal is a candidate fix.
type Proposal struct {
	Strategy string
	Edits    []FileEdit

	// Rationale is what was changed and why, in the words that go into the
	// commit message and the pull request body.
	Rationale string

	// RootCause restates the underlying mistake, so the reviewer can judge
	// whether the fix addresses it rather than its symptom.
	RootCause string

	// SiblingNote records the same pattern found elsewhere. The brief asks
	// for the broader pattern to be reported even when the landed fix is
	// scoped, so a reviewer knows the class is not closed.
	SiblingNote string

	// EnvVars are environment variables the fix introduces. A fix that
	// defaults to the secure value and reads the permissive one from the
	// environment has changed how the application is configured, and saying
	// so is part of the change, not a footnote.
	EnvVars []EnvVar
}

// EnvVar documents configuration the fix introduces.
type EnvVar struct {
	Name     string
	Purpose  string
	Default  string
	Required bool
}

// Files lists the paths a proposal touches.
func (p *Proposal) Files() []string {
	out := make([]string, 0, len(p.Edits))
	for _, e := range p.Edits {
		out = append(out, e.Path)
	}
	sort.Strings(out)
	return out
}

// Input is everything a strategy may look at.
type Input struct {
	Finding contract.Finding

	// Root is the isolated worktree the fix is being written into.
	Root string

	// Suite is what was detected about the project, so a strategy can match
	// the framework idiom rather than imposing one.
	Suite *project.Suite

	// ReadFile reads a repo-relative path from the worktree.
	ReadFile func(rel string) ([]byte, error)
}

// Strategy turns one finding into a candidate change.
type Strategy interface {
	// Name identifies the strategy in reports and run logs.
	Name() string

	// Handles reports whether this strategy knows this finding kind. It is
	// matched on rule id and, where the pack has per-language variants, on
	// the evidence key -- which carries the Semgrep rule id as
	// "semgrep:<rule>" and is the only language discriminator the contract
	// actually exposes.
	Handles(f contract.Finding) bool

	// Propose returns a candidate, or an error explaining why no safe change
	// could be made. An error is a normal outcome and becomes a fix_failed
	// with the reason, never a silent skip.
	Propose(in Input) (*Proposal, error)
}

// Registry holds the strategies this build knows.
type Registry struct {
	strategies []Strategy
}

// DefaultRegistry is the strategy set keyed off Killer real categories.
//
// v0 covers security-misconfiguration only, which is the brief phase order
// and is also the only category whose honesty does not depend on rule
// fidelity work still outstanding in Killer: the access-control rules are
// being hardened against live fixtures for Killer v1.1, and a silent rule
// there would have Giver certify a non-fix as fixed.
func DefaultRegistry() *Registry {
	return &Registry{strategies: []Strategy{
		&debugModeStrategy{},
		&corsReflectionStrategy{},
	}}
}

// For returns the strategy for a finding.
func (r *Registry) For(f contract.Finding) (Strategy, bool) {
	for _, s := range r.strategies {
		if s.Handles(f) {
			return s, true
		}
	}
	return nil, false
}

// Names lists the registered strategies.
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.strategies))
	for _, s := range r.strategies {
		out = append(out, s.Name())
	}
	return out
}

// Categories lists the finding categories this build can attempt.
func (r *Registry) Categories() []contract.Category {
	return []contract.Category{contract.CategoryMisconfiguration}
}

// --- shared helpers --------------------------------------------------------

// semgrepRule recovers the Semgrep rule id from a finding evidence key.
//
// Killer writes it as "semgrep:<rule-id>", and it is the only thing in the
// contract that distinguishes the per-language variants of one rule id:
// cors-origin-reflected-python and cors-wildcard-with-credentials both report
// rule_id misconfig.cors-credentialed-wildcard, and the fix for them is not
// the same code.
func semgrepRule(f contract.Finding) string {
	const prefix = "semgrep:"
	if strings.HasPrefix(f.Evidence.EvidenceKey, prefix) {
		return strings.TrimPrefix(f.Evidence.EvidenceKey, prefix)
	}
	return ""
}

// lines splits content for line-oriented edits, remembering the ending so a
// file is not silently renormalized.
type lineFile struct {
	lines  []string
	crlf   bool
	noTail bool
}

func splitLines(content []byte) *lineFile {
	s := string(content)
	lf := &lineFile{crlf: strings.Contains(s, "\r\n")}
	if lf.crlf {
		s = strings.ReplaceAll(s, "\r\n", "\n")
	}
	if !strings.HasSuffix(s, "\n") {
		lf.noTail = true
	} else {
		s = strings.TrimSuffix(s, "\n")
	}
	lf.lines = strings.Split(s, "\n")
	return lf
}

func (l *lineFile) bytes() []byte {
	s := strings.Join(l.lines, "\n")
	if !l.noTail {
		s += "\n"
	}
	if l.crlf {
		s = strings.ReplaceAll(s, "\n", "\r\n")
	}
	return []byte(s)
}

// at returns the 1-based line, and false when the line number is outside the
// file -- which means the finding and the file have diverged and no edit
// should be attempted.
func (l *lineFile) at(n int) (string, bool) {
	if n < 1 || n > len(l.lines) {
		return "", false
	}
	return l.lines[n-1], true
}

func indentOf(line string) string {
	return line[:len(line)-len(strings.TrimLeft(line, " \t"))]
}

// ensureImport adds a top-level `import <name>` when the module is not
// already imported.
//
// It is deliberately conservative: it only recognizes a plain `import x` or
// `import x, y`, and inserts after the last existing top-level import so the
// diff is one line in the place a reader expects. If it cannot find an import
// block it returns false, and the caller refuses rather than writing an
// import into the middle of something.
func ensureImport(l *lineFile, name string) (added bool, ok bool) {
	last := -1
	for i, line := range l.lines {
		trimmed := strings.TrimSpace(line)
		if line != trimmed {
			// Indented: inside a function or a try block. Not top level.
			continue
		}
		if trimmed == "import "+name || strings.HasPrefix(trimmed, "import "+name+" ") ||
			strings.HasPrefix(trimmed, "import "+name+",") {
			return false, true
		}
		if strings.HasPrefix(trimmed, "import ") && strings.Contains(trimmed, " "+name) {
			// `import os, sys` style, name already present.
			for _, part := range strings.Split(strings.TrimPrefix(trimmed, "import "), ",") {
				if strings.TrimSpace(part) == name {
					return false, true
				}
			}
		}
		if strings.HasPrefix(trimmed, "import ") {
			last = i
		}
	}
	if last < 0 {
		return false, false
	}
	l.lines = append(l.lines[:last+1], append([]string{"import " + name}, l.lines[last+1:]...)...)
	return true, true
}

// errUnrecognized is the fail-closed outcome: the code at the finding
// location is not a shape this strategy knows how to change safely.
func errUnrecognized(f contract.Finding, saw string) error {
	return fmt.Errorf(
		"no safe change could be generated for %s at %s:%d: the code there is %s.\n"+
			"Refusing to edit it rather than guessing: a textual change that happens to satisfy the rule "+
			"is indistinguishable from a fix in every report, and the weakness would still be there",
		f.RuleID, f.Location.File, f.Location.Line, saw)
}
