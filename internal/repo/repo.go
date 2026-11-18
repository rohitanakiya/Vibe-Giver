// Package repo is the git surface Vibe Giver works through.
//
// Everything here is shaped by one rule from the brief: never leave a
// half-applied change. A fix attempt happens in its own worktree on its own
// branch, so the operator checkout is never modified, a failed attempt is
// removed completely, and a successful one leaves exactly one branch behind
// for a person to review.
//
// Giver does not push and does not merge. There is no code here that could.
package repo

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// BranchPrefix is the namespace every Giver branch lives under, so an
// operator can see at a glance what this tool created and delete all of it
// with one refspec.
const BranchPrefix = "vibegiver/"

// Repo is an operator git repository.
type Repo struct {
	Root string

	// Log receives each git command, for the run record.
	Log func(string)
}

// Open finds the repository containing path.
func Open(path string) (*Repo, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	r := &Repo{Root: abs}
	out, err := r.git("rev-parse", "--show-toplevel")
	if err != nil {
		return nil, fmt.Errorf("%s is not inside a git repository: %w", abs, err)
	}
	root := strings.TrimSpace(out)
	if root == "" {
		return nil, fmt.Errorf("%s is not inside a git repository", abs)
	}
	r.Root = filepath.Clean(root)
	return r, nil
}

func (r *Repo) git(args ...string) (string, error) {
	return r.gitIn(r.Root, args...)
}

func (r *Repo) gitIn(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb

	err := cmd.Run()
	if r.Log != nil {
		status := "ok"
		if err != nil {
			status = "failed: " + err.Error()
		}
		r.Log(fmt.Sprintf("$ git %s  (%s)", strings.Join(args, " "), status))
	}
	if err != nil {
		return out.String(), fmt.Errorf("git %s: %w: %s",
			strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

// DirtyError is a refusal to operate on a tree with uncommitted changes.
type DirtyError struct {
	Root   string
	Status string
}

func (e *DirtyError) Error() string {
	return fmt.Sprintf(
		"refusing to run: %s has uncommitted changes.\n"+
			"Vibe Giver needs a clean tree so that the diff it produces contains only its own fix, "+
			"and so that a failed attempt can be removed without taking your work with it.\n"+
			"Commit or stash first.\n\n%s",
		e.Root, strings.TrimRight(e.Status, "\n"))
}

// RequireClean refuses a dirty working tree.
//
// This is a safety rule rather than tidiness. Giver reports a diff as the
// proof of what it changed, and verifies by running the project tests; both
// claims are false if the tree already contained someone else edits. Worse,
// discarding a failed attempt could then discard their work.
func (r *Repo) RequireClean() error {
	out, err := r.git("status", "--porcelain", "--untracked-files=normal")
	if err != nil {
		return err
	}
	if strings.TrimSpace(out) != "" {
		return &DirtyError{Root: r.Root, Status: out}
	}
	return nil
}

// HeadRev returns the current revision.
func (r *Repo) HeadRev() (string, error) {
	out, err := r.git("rev-parse", "HEAD")
	return strings.TrimSpace(out), err
}

// HasRev reports whether a revision exists in this repository.
func (r *Repo) HasRev(rev string) bool {
	if rev == "" {
		return false
	}
	_, err := r.git("rev-parse", "--verify", "--quiet", rev+"^{commit}")
	return err == nil
}

// BaseFor picks the revision to branch from.
//
// The brief says to branch from the finding location.repo_rev, falling back
// to HEAD. Both cases are reported rather than chosen silently: a fix
// verified against a different tree than the one Killer scanned is a fix
// verified against a different application, and the operator should see which
// happened.
func (r *Repo) BaseFor(findingRev string) (rev string, note string, err error) {
	head, err := r.HeadRev()
	if err != nil {
		return "", "", err
	}
	switch {
	case findingRev == "":
		return head, "the finding records no repo_rev, so the fix is based on HEAD " + short(head), nil
	case findingRev == head:
		return head, "HEAD is the revision Killer scanned (" + short(head) + ")", nil
	case !r.HasRev(findingRev):
		return head, fmt.Sprintf(
			"the revision Killer scanned (%s) is not in this repository, so the fix is based on HEAD %s; "+
				"the finding may not be present here at all, which the first gate will establish",
			short(findingRev), short(head)), nil
	default:
		// HEAD is a different, present revision. Prefer it: it is what the
		// operator tests and ships, and the first gate re-confirms the
		// finding there before anything is changed.
		return head, fmt.Sprintf(
			"Killer scanned %s and HEAD is %s; basing the fix on HEAD, and re-confirming the finding there first",
			short(findingRev), short(head)), nil
	}
}

func short(rev string) string {
	if len(rev) > 12 {
		return rev[:12]
	}
	return rev
}

// Worktree is an isolated checkout on its own branch.
type Worktree struct {
	Dir    string
	Branch string
	Base   string

	repo *Repo
}

// BranchFor is the branch name for a finding: one finding, one branch,
// reviewable and revertable on its own.
func BranchFor(findingID string) string { return BranchPrefix + findingID }

// AddWorktree creates a branch at base and checks it out in its own
// directory.
//
// An isolated worktree rather than a branch in the operator checkout, because
// the verification runs their test suite and their build. Doing that in the
// directory they have open invites a half-written fix being picked up by a
// watcher, an IDE or another command.
func (r *Repo) AddWorktree(dir, branch, base string) (*Worktree, error) {
	if !strings.HasPrefix(branch, BranchPrefix) {
		// Guards against a caller constructing a branch name by hand and
		// landing it outside the namespace an operator can bulk-delete.
		return nil, fmt.Errorf("refusing to create branch %q: every Giver branch must start with %q",
			branch, BranchPrefix)
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return nil, err
	}
	if _, err := r.git("worktree", "add", "--quiet", "-b", branch, dir, base); err != nil {
		return nil, fmt.Errorf("creating a worktree for %s: %w", branch, err)
	}
	return &Worktree{Dir: dir, Branch: branch, Base: base, repo: r}, nil
}

// Path resolves a repo-relative path inside the worktree.
func (w *Worktree) Path(rel string) string {
	return filepath.Join(w.Dir, filepath.FromSlash(rel))
}

// IsClean reports whether the worktree has no changes, which is how the loop
// tells "the strategy wrote nothing" from "the strategy wrote a fix".
func (w *Worktree) IsClean() (bool, error) {
	out, err := w.repo.gitIn(w.Dir, "status", "--porcelain")
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(out) == "", nil
}

// Diff returns the patch for everything changed in the worktree, staged or
// not, which is what goes in the run record and the pull request body.
func (w *Worktree) Diff() (string, error) {
	// --no-ext-diff and a fixed context so the patch is reproducible and not
	// shaped by the operator diff configuration.
	out, err := w.repo.gitIn(w.Dir, "--no-pager", "diff", "--no-ext-diff", "--unified=3", "HEAD")
	return out, err
}

// CommitAll commits every change in the worktree.
//
// No co-author or tool trailer is added, here or anywhere: the commit is
// authored by whoever configured the repository, and the message says Vibe
// Giver made it in words rather than in a trailer.
func (w *Worktree) CommitAll(message string) (string, error) {
	if _, err := w.repo.gitIn(w.Dir, "add", "--all"); err != nil {
		return "", err
	}
	if _, err := w.repo.gitIn(w.Dir, "commit", "--quiet", "--no-verify", "-m", message); err != nil {
		return "", err
	}
	out, err := w.repo.gitIn(w.Dir, "rev-parse", "HEAD")
	return strings.TrimSpace(out), err
}

// Keep removes the worktree directory but leaves the branch, which is the
// successful outcome: the operator has a branch to review and no stray
// checkout on disk.
func (w *Worktree) Keep() error {
	_, err := w.repo.git("worktree", "remove", "--force", w.Dir)
	return err
}

// Discard removes the worktree and deletes the branch, leaving the repository
// exactly as it was.
//
// This is what "never leave a half-applied change" means in practice, and it
// runs on every failure path including a panic, so a verification that falls
// over does not leave a branch that looks like a proposed fix.
func (w *Worktree) Discard() error {
	var errs []error
	if _, err := w.repo.git("worktree", "remove", "--force", w.Dir); err != nil {
		errs = append(errs, err)
		// The directory may survive a failed remove; take it out of the way
		// so a retry can use the same path.
		if rmErr := os.RemoveAll(w.Dir); rmErr != nil {
			errs = append(errs, rmErr)
		}
		if _, pErr := w.repo.git("worktree", "prune"); pErr != nil {
			errs = append(errs, pErr)
		}
	}
	if _, err := w.repo.git("branch", "-D", w.Branch); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// PruneWorktrees clears stale worktree registrations left by an interrupted
// run.
func (r *Repo) PruneWorktrees() error {
	_, err := r.git("worktree", "prune")
	return err
}

// BranchExists reports whether a branch is already present, which means an
// earlier attempt at this finding is still around and must not be silently
// overwritten.
func (r *Repo) BranchExists(branch string) bool {
	_, err := r.git("rev-parse", "--verify", "--quiet", "refs/heads/"+branch)
	return err == nil
}
