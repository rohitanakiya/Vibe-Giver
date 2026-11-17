// Command vibegiver proposes verified fixes for the weaknesses Vibe Killer
// reports.
//
// It never merges, it never claims a fix it has not proven, and it never
// concludes that an application is clean from the absence of findings.
package main

import (
	"os"

	"github.com/rohitanakiya/Vibe-Giver/internal/cli"
)

func main() {
	os.Exit(cli.Main())
}
