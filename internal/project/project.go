// Package project works out how to test, build and lint the repository being
// fixed, and runs those commands.
//
// The honest handling of a missing test suite is the whole design problem
// here. The brief requires that the project existing tests stay green, and
// most of the applications this tool exists for have no tests at all -- that
// is part of what makes them the applications this tool exists for. Measured:
// none of Vibe Killer four fixtures has a test suite.
//
// Reporting "tests passed" for a project with no tests would be a lie of
// exactly the shape this repository is built to avoid: the thing asserting it
// cannot tell a green suite from an absent one. Reporting a verification
// failure would be a different lie, implying the fix broke something.
//
// So a missing suite is neither. It is a Caveat: recorded, never counted as a
// pass, and printed in the report and the pull request body where the person
// reviewing the change will see it. A gate that could not run says so.
package project

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/rohitanakiya/Vibe-Giver/internal/contract"
)

// Check is one command the verification runs.
type Check struct {
	// Name is the gate this command serves: "tests", "build" or "lint".
	Name string

	// Cmd is the executable and its arguments.
	Cmd []string

	// Why explains what passing it establishes, for the report.
	Why string
}

func (c Check) String() string { return strings.Join(c.Cmd, " ") }

// Suite is what was detected about a repository.
type Suite struct {
	// Language and Framework are best-effort labels for the report.
	Language  string
	Framework string

	// Tests is the project own test suite. Empty when there is none, which
	// is a Caveat and not a pass.
	Tests []Check

	// Lint is whatever linter the project already configures. Giver does not
	// introduce one.
	Lint []Check

	// Caveats are the gates that could not be run here, with the reason.
	// They travel all the way to the pull request body.
	Caveats []string

	// syntax builds a compile or parse check for the files a fix touched.
	syntax func(files []string) []Check
}

// Syntax returns a parse or compile check for the changed files.
//
// This is the cheapest gate that catches the most likely way an automated
// edit goes wrong: a change that is textually plausible and not valid code.
// It is worth running even when nothing else can be.
func (s *Suite) Syntax(files []string) []Check {
	if s.syntax == nil {
		return nil
	}
	return s.syntax(files)
}

// Detect works out how to verify a repository.
func Detect(dir string) *Suite {
	switch {
	case exists(dir, "go.mod"):
		return detectGo(dir)
	case exists(dir, "package.json"):
		return detectNode(dir)
	case exists(dir, "requirements.txt"), exists(dir, "pyproject.toml"),
		exists(dir, "setup.py"), exists(dir, "manage.py"), hasPythonFiles(dir):
		return detectPython(dir)
	default:
		return &Suite{
			Language: "unknown",
			Caveats: []string{
				"no recognized project layout, so neither the test suite nor a build could be run: " +
					"nothing was verified about regressions",
			},
		}
	}
}

func detectPython(dir string) *Suite {
	s := &Suite{Language: "python"}
	switch {
	case exists(dir, "manage.py"):
		s.Framework = "django"
	case grepAny(dir, "requirements.txt", "Flask", "flask"):
		s.Framework = "flask"
	case grepAny(dir, "requirements.txt", "fastapi"):
		s.Framework = "fastapi"
	}

	python := pythonExe()
	if python == "" {
		s.Caveats = append(s.Caveats,
			"no python interpreter on PATH, so the changed files could not even be parsed")
	} else {
		s.syntax = func(files []string) []Check {
			var py []string
			for _, f := range files {
				if strings.HasSuffix(f, ".py") {
					py = append(py, filepath.FromSlash(f))
				}
			}
			if len(py) == 0 {
				return nil
			}
			return []Check{{
				Name: "build",
				Cmd:  append([]string{python, "-m", "py_compile"}, py...),
				Why:  "the changed Python files still parse and compile",
			}}
		}
	}

	switch {
	case !hasTestLayout(dir):
		s.Caveats = append(s.Caveats,
			"no test suite was found in this project (no tests/ directory and no test_*.py), "+
				"so nothing was verified about whether the fix changes behaviour elsewhere")
	case python == "":
		s.Caveats = append(s.Caveats, "a test layout exists but there is no python interpreter to run it with")
	case !onPath("pytest") && !moduleAvailable(python, "pytest"):
		s.Caveats = append(s.Caveats,
			"this project has tests but pytest is not installed, so they could not be run")
	default:
		s.Tests = []Check{{
			Name: "tests",
			Cmd:  []string{python, "-m", "pytest", "-q"},
			Why:  "the project own tests still pass",
		}}
	}

	if python != "" && (exists(dir, "ruff.toml") || grepAny(dir, "pyproject.toml", "[tool.ruff]")) && onPath("ruff") {
		s.Lint = []Check{{
			Name: "lint",
			Cmd:  []string{"ruff", "check", "."},
			Why:  "the linter this project already configures still passes",
		}}
	}
	return s
}

func detectNode(dir string) *Suite {
	s := &Suite{Language: "javascript"}
	if grepAny(dir, "package.json", "\"express\"") {
		s.Framework = "express"
	}

	if node := which("node"); node != "" {
		s.syntax = func(files []string) []Check {
			var out []Check
			for _, f := range files {
				if strings.HasSuffix(f, ".js") || strings.HasSuffix(f, ".cjs") || strings.HasSuffix(f, ".mjs") {
					out = append(out, Check{
						Name: "build",
						Cmd:  []string{node, "--check", filepath.FromSlash(f)},
						Why:  "the changed JavaScript still parses",
					})
				}
			}
			return out
		}
	} else {
		s.Caveats = append(s.Caveats, "node is not on PATH, so the changed files could not be parsed")
	}

	switch {
	case !onPath("npm"):
		s.Caveats = append(s.Caveats, "npm is not on PATH, so the project tests could not be run")
	case !hasNpmScript(dir, "test"):
		s.Caveats = append(s.Caveats,
			"package.json declares no test script, so nothing was verified about whether the fix "+
				"changes behaviour elsewhere")
	default:
		s.Tests = []Check{{
			Name: "tests",
			Cmd:  []string{"npm", "test", "--silent"},
			Why:  "the project own tests still pass",
		}}
	}
	return s
}

func detectGo(dir string) *Suite {
	s := &Suite{Language: "go"}
	if !onPath("go") {
		s.Caveats = append(s.Caveats, "the go toolchain is not on PATH, so nothing could be built or tested")
		return s
	}
	s.syntax = func([]string) []Check {
		return []Check{{
			Name: "build",
			Cmd:  []string{"go", "build", "./..."},
			Why:  "the module still builds",
		}}
	}
	s.Tests = []Check{{
		Name: "tests",
		Cmd:  []string{"go", "test", "./..."},
		Why:  "the project own tests still pass",
	}}
	s.Lint = []Check{{
		Name: "lint",
		Cmd:  []string{"go", "vet", "./..."},
		Why:  "go vet still passes",
	}}
	return s
}

// Outcome is one command result.
type Outcome struct {
	Check    Check
	Verdict  contract.Verdict
	ExitCode int
	Output   string
	Elapsed  time.Duration
}

// Run executes one check in dir and turns the result into a verdict.
//
// The mapping is the same discipline as everywhere else. A command that
// passed proves the thing it checks is not broken, which is "gone" in the
// sense the gate means. A command that failed proves it is. A command that
// could not be started proves nothing, and is inconclusive rather than
// either -- a missing interpreter must never read as a green suite.
func Run(ctx context.Context, dir string, c Check, timeout time.Duration) Outcome {
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	cmd := exec.CommandContext(ctx, c.Cmd[0], c.Cmd[1:]...)
	cmd.Dir = dir
	// A test suite that reads the environment should see the operator
	// environment, which is what it would see when they run it themselves.
	cmd.Env = os.Environ()

	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()

	out := Outcome{Check: c, Output: buf.String(), Elapsed: time.Since(start)}

	var ee *exec.ExitError
	switch {
	case err == nil:
		out.ExitCode = 0
		out.Verdict = contract.Gone(c.String(), c.Why)
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		out.ExitCode = -1
		out.Verdict = contract.Inconclusive(fmt.Sprintf(
			"%s did not finish within %s, so it established nothing", c, timeout))
	case errors.As(err, &ee):
		out.ExitCode = ee.ExitCode()
		out.Verdict = contract.StillPresent(c.String(), fmt.Sprintf(
			"%s failed (exit %d): %s", c, ee.ExitCode(), lastLines(buf.String(), 6)))
	default:
		out.ExitCode = -1
		out.Verdict = contract.Inconclusive(fmt.Sprintf(
			"%s could not be started, so it established nothing: %v", c, err))
	}
	return out
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(strings.ReplaceAll(s, "\r\n", "\n"), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// --- detection helpers -----------------------------------------------------

func exists(dir, name string) bool {
	_, err := os.Stat(filepath.Join(dir, name))
	return err == nil
}

func hasPythonFiles(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".py") {
			return true
		}
	}
	return false
}

// hasTestLayout looks for a test suite rather than for a test runner. The
// distinction matters: pytest being installed says nothing about this project
// having tests.
func hasTestLayout(dir string) bool {
	for _, d := range []string{"tests", "test"} {
		if info, err := os.Stat(filepath.Join(dir, d)); err == nil && info.IsDir() {
			return true
		}
	}
	found := false
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || found {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "__pycache__", ".venv", "venv":
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if strings.HasPrefix(name, "test_") && strings.HasSuffix(name, ".py") {
			found = true
		}
		if strings.HasSuffix(name, "_test.py") {
			found = true
		}
		return nil
	})
	return found
}

func hasNpmScript(dir, name string) bool {
	raw, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return false
	}
	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(raw, &pkg); err != nil {
		return false
	}
	script, ok := pkg.Scripts[name]
	if !ok || strings.TrimSpace(script) == "" {
		return false
	}
	// The npm default placeholder exits 1 and is not a test suite.
	return !strings.Contains(script, "no test specified")
}

func grepAny(dir, name string, needles ...string) bool {
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return false
	}
	for _, n := range needles {
		if bytes.Contains(raw, []byte(n)) {
			return true
		}
	}
	return false
}

func onPath(name string) bool { return which(name) != "" }

func which(name string) string {
	p, err := exec.LookPath(name)
	if err != nil {
		return ""
	}
	return p
}

func pythonExe() string {
	for _, c := range []string{"python3", "python", "py"} {
		if p := which(c); p != "" {
			return p
		}
	}
	return ""
}

func moduleAvailable(python, module string) bool {
	if python == "" {
		return false
	}
	return exec.Command(python, "-c", "import "+module).Run() == nil
}
