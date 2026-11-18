// Package cli is the command-line surface of Vibe Giver.
//
// It stays thin: parsing arguments and printing results. The work belongs to
// the packages below it, so the same operation can be driven from a test
// without going through argv.
package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

// Version carries -dev between releases, for the same reason Killer's does: a
// fix report records which build proved a weakness gone, and a report from an
// unreleased build must not be mistakable for one from the release it
// follows. `go install ...@vX.Y.Z` passes no ldflags, so for anyone who
// installs rather than builds, this constant is the reported version.
var Version = "0.1.0-dev"

// Exit codes. Deliberately few, stable, and aligned with Killer's so a
// pipeline running both does not have to learn two schemes.
const (
	// ExitOK means the command completed.
	ExitOK = 0

	// ExitUnfixed means the command completed and something is still open:
	// a finding Giver could not prove fixed, or one that needs a person.
	// This is what fails a build.
	ExitUnfixed = 1

	// ExitError means the command could not complete.
	ExitError = 2

	// ExitRefused means the operation was refused on contract or safety
	// grounds: an envelope this build cannot read, a dirty working tree, a
	// repository the operator does not control. Distinct from ExitError so a
	// pipeline can tell a refusal from a crash.
	ExitRefused = 3
)

type exitCodeError struct {
	code    int
	message string
}

func (e *exitCodeError) Error() string {
	if e.message != "" {
		return e.message
	}
	return fmt.Sprintf("exit %d", e.code)
}

func exitWith(code int, format string, args ...any) error {
	return &exitCodeError{code: code, message: fmt.Sprintf(format, args...)}
}

// Main runs the CLI and returns the process exit code.
func Main() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	root := newRootCmd()
	root.SetContext(ctx)

	if err := root.Execute(); err != nil {
		var ec *exitCodeError
		if errors.As(err, &ec) {
			if ec.message != "" {
				fmt.Fprintln(os.Stderr, ec.message)
			}
			return ec.code
		}
		fmt.Fprintf(os.Stderr, "vibegiver: %v\n", err)
		return ExitError
	}
	return ExitOK
}

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vibegiver",
		Short: "Propose verified fixes for the weaknesses Vibe Killer reports",
		Long: `Vibe Giver reads the findings Vibe Killer produces and, for the findings it can
safely fix, proposes a code change whose correctness is proven by re-running
Killer's own check and the project's own test suite. It opens the change as a
pull request for a person to review.

Three guarantees, in the order they matter:

  Pull requests only. Vibe Giver never merges. A bad security patch can break
  authorization, payments or access control silently, so a person reviews
  every change.

  Every fix is proven gone. A fix counts only when the check that found the
  weakness runs again and no longer reports it, the existing tests stay green,
  and the re-scan introduces nothing new.

  Nothing is concluded from silence. A skipped check, a failed check, a
  refused reproduction or an envelope this build cannot read are all
  "unknown". Never "clean", never "fixed". Absence of a finding is only
  evidence when something actually looked.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       Version,
	}

	cmd.AddCommand(
		newContractCmd(),
		newInspectCmd(),
		newFixCmd(),
	)
	return cmd
}
