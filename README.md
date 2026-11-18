# Vibe Giver

Reads the findings [Vibe Killer](https://github.com/rohitanakiya/Vibe-Killer)
produces and, for the ones it can safely fix, proposes a code change whose
correctness is **proven** — by re-running Killer's own check and the project's
own test suite — and opens it as a pull request for a person to review.

Killer finds the weakness and proves it is real. Giver closes it and proves it
is gone. Neither tool is allowed to assert anything it has not measured.

> **Status: v0.** The contract binding and the fix→verify loop are built, and
> `vibegiver fix` proposes verified fixes for `security-misconfiguration`
> findings — on a branch and a patch, no pull requests yet. Proven end to end
> against Vibe Killer's own Flask fixture. The roadmap is at the bottom.

## Three guarantees

**Pull requests only.** Vibe Giver never merges, and there is no flag to make
it. A bad security patch breaks authorization, payments or access control
silently, and the failure surfaces later and somewhere else. One finding
becomes one branch, `vibegiver/<finding_id>`, reviewable and revertable on its
own.

**Every fix is proven gone.** A change counts as a fix only when the check
that found the weakness runs again and no longer reports it, the existing
tests stay green, a re-scan of the touched area introduces nothing new, and
the build and linters pass. Any one of those failing discards the branch and
records `fix_failed` with the captured reason. Giver never reports a fix it
has not proven.

**Nothing is concluded from silence.** A skipped check, a failed check, a
refused reproduction, a findings file this build cannot fully read — all of
these are *unknown*. Never "clean", never "fixed". Verification has three
outcomes and only one of them is a pass:

| | |
|---|---|
| `gone` | a check that demonstrably ran looked, and the weakness is not there |
| `still-present` | the weakness was observed again |
| `inconclusive` | the check could not say — **a verification failure, never a pass** |

## Why the third one is the whole design

Killer's recurring bug through its whole build was *a feature that looked
alive because the only thing asserting it could not tell the difference.* A
Semgrep rule that matches nothing and a Semgrep rule that is satisfied produce
identical output, so no amount of reading finds the broken one; every real
instance was caught by running it against a case that should match and a case
that should not.

Giver's version of that bug is worse, because its output is the sentence "this
vulnerability is closed":

> **A fix looks successful whenever the verification cannot tell "vulnerability
> gone" from "could not re-check."**

A false `gone` closes a real hole as done. So the three outcomes are a type,
not a convention — `Verdict`'s zero value is `inconclusive`, so every missed
assignment, every struct returned beside an error, every unmapped future case
fails closed — and `inconclusive` is a failure at every gate.

That principle was load-bearing immediately. Two traps were found while
binding to the contract, both of which would have produced a tool that looked
like it worked:

**`vibekiller reproduce` can exit 0 without checking anything.** The build
brief hangs Giver's whole loop on this command, and exit 0 normally means "no
longer reproducible". But when a finding's rule maps to a check that cannot
re-run a single finding, and the finding carries reproduction steps, the
command prints those steps and returns success. Nothing was sent. In Killer
v1.0.0 that is the state of `misconfig.cors-reflection`,
`misconfig.missing-security-headers`, `misconfig.verbose-error` and
`ssrf.internal-canary-fetch` — the first three being the entire dynamic
misconfiguration category, which the brief names as the place to start because
its diffs are the smallest and safest. A Giver that read exit 0 as proof would
have certified every one of those fixes by running a command that sent no
traffic. So exit 0 is read as `gone` only when the dynamic sentinel line is
present; every other exit 0 is `inconclusive` and says why.

**A static re-scan cannot tell a fix from a dodge.** The rule behind the CORS
finding is a regex over `Access-Control-Allow-Origin ... = request.headers`.
Assigning the reflected origin to a local variable first satisfies it
completely, and changes nothing: every site on the internet is still echoed
back with credentials allowed. The re-scan says `gone`. That is measured, not
hypothesised — `TestAPatternDodgeSilencesTheRuleWithoutFixingAnything` writes
the dodge out and asserts the rule stops matching it. So strategies here are
constrained transformations checked against the patched fixture as an answer
key, rather than anything that makes a scan come back clean, and a strategy
that does not recognise the code it was pointed at refuses instead of guessing.

**A focused re-scan can mask its own result.** Re-checking one finding means
`vibekiller scan --only <rule>`, and Killer records every check it did not
schedule as skipped. Killer's own join — rule id, then layer when that source
produced nothing — then fires on those deselections and reports the finding as
not re-checked, which is correct for comparing two whole runs and wrong for a
focused re-check: the fix would be discarded as unverifiable precisely when it
worked. Giver joins on the *producing check* instead, and the test asserts both
that the precise join returns `gone` and that the layer join would not have.

## Contract binding

Giver is a consumer, so the contract is vendored from a pinned published
artifact rather than copied from a document:

```
$ vibegiver contract
Bound to Vibe Killer v1.0.0 (fbe32e04f803)
  sha256         0d78219ce7f7538b2e4013b1a0e02b6113a4599b2b28427be20721f7a6734ae3
Per-finding schema_version   1.0 (pinned by "const" in the published schema)
Envelope schema_version      1.2
Envelopes this build reads   1.0, 1.1, 1.2
```

The vendored schema came from the module proxy artifact for
`Vibe-Killer@v1.0.0`, not from a working tree, and CI re-fetches it at the
pinned commit every build and weekly on a schedule.

A **git submodule was the going-in preference and was rejected on a
measurement**: a submodule is a gitlink in its parent's tree, not a tree, so
the archive the Go module proxy serves for a tag contains the submodule's
directory and nothing inside it. `go install`-ing a Giver whose schema came
from a submodule would ship a binary with no schema in it. Killer has already
paid for that class of bug from the other side, when a gitignore entry came one
slash from excluding its own embedded rule pack.

The version gate is deliberately **asymmetric**. An older envelope is merely
less informative. A newer one is refused outright, because it may record a
kind of non-coverage this build does not read, and an unread non-coverage entry
is exactly how a finding nobody checked gets reported as fixed. An unmodelled
top-level key is refused for the same reason, even at a version this build
knows.

One consequence is worth stating plainly, because it is a place where Giver
**deliberately disagrees with Killer**: a `1.0` envelope predates the
`skipped` and `failed` arrays, so it cannot distinguish a check that found
nothing from one that never ran. Killer reads those absences as fixes for its
own diff, which is a defensible call for a report a human reads. For Giver it
would close unchecked holes as done, so no fix can be proven against a `1.0`
document and `inspect` says so.

## What Giver will not touch

- **Secrets are never "fixed" in code.** A leaked credential produces rotation
  and history-scrub instructions. An edit that hides the secret while it stays
  valid reads as a fix and is the most dangerous thing this tool could do, so
  the loader refuses a document that claims a secrets finding is auto-fixable
  at all.
- Anything whose `status` is not `open`, or whose
  `remediation.fixable_by_giver` is false. Both are required; neither is
  inferred.
- Any repository the operator does not control, and any dirty working tree.

Everything it will not fix goes into a prioritized human-action report with the
reason and the exact steps — never a pretend fix.

## Usage

```bash
go install github.com/rohitanakiya/Vibe-Giver/cmd/vibegiver@latest
```

```bash
vibegiver contract
```

```bash
vibegiver inspect runs/20261118-120000-123456
```

```bash
vibegiver fix runs/20261118-120000-123456 --repo .
```

`fix` handles each finding in its own git worktree on its own branch,
`vibegiver/<finding_id>`, so your checkout is never modified. Every gate has to
return `gone`: the finding reproduced here before anything changed, it is gone
after, the same re-scan introduced nothing new, the project's tests still pass,
and the changed files still parse and build. If they all pass, the branch is
kept with one commit and the patch, the pull request body and the full gate
output land in the run directory. If any gate fails, **the branch is deleted
and nothing is left behind** — the rejected diff is kept in the run record
instead. It requires a clean working tree, and it never pushes or merges.

### What "no test suite" does

Most of the applications this tool exists for have no tests — none of Killer's
four fixtures does. Reporting "tests passed" there would be the exact failure
this project is built to avoid: the thing asserting it cannot tell a green
suite from an absent one. Reporting a failure would be a different lie.

So a missing suite is a **caveat**: recorded, never counted as a pass, and
printed in the summary, the commit message and the pull request body under
"What was not verified". A gate that could not run says so, where the person
reviewing the change will read it.

`inspect` changes nothing. It validates a run against the contract and reports
what Giver would attempt, what needs a person, how each finding would be
verified, and what the run could not establish.

Exit codes match Killer's so a pipeline running both learns one scheme: `0`
done, `1` something still open, `2` could not complete, `3` refused. But `0`
requires **both** that there is nothing to fix and that the run actually
looked — a distinction CI caught the hard way.

On a bare runner with no Semgrep, osv-scanner or gitleaks installed, Killer
scans a deliberately vulnerable Flask fixture, prints "No findings from the
checks that ran", lists all fourteen checks as skipped, and **exits 0**. Every
signal a pipeline normally gates on says clean, on real infrastructure, with
nothing misconfigured. So `vibegiver inspect` exits `1` there and says the run
established nothing. Zero findings is a clean result only when something
looked.

> Measure exit codes against the built binary, not `go run`, which reports its
> own exit `1` for any non-zero exit — collapsing all four codes into one.

## Development

```bash
go test ./...
```

```bash
bash scripts/schema-drift-check.sh
```

The test corpus is real Killer output, not hand-written, and
[`internal/contract/testdata/PROVENANCE.md`](internal/contract/testdata/PROVENANCE.md)
records exactly which run produced it and the one field that was redacted. A
hand-written sample would have agreed with whatever this package happened to
implement. Never tune it to make a test pass.

## Roadmap

- **v0** — *done.* Contract binding (schema, envelope gate, three-outcome
  verdict, coverage join, CLI binding, `inspect`), and the fix→verify loop on
  `security-misconfiguration`, with branch and local patch output and no PRs.
  Two strategies: `misconfig.debug-mode-enabled` (Flask, Django, FastAPI and
  uvicorn forms) and the Python `misconfig.cors-credentialed-wildcard`. Proven
  end to end on Killer's Flask fixture: both findings fixed, and both confirmed
  absent by a Killer scan run separately from the one Giver used to verify.
- **v1** — `injection` and `broken-access-control`; regression-test generation;
  PR creation; `fix_report.json`.
- **v2** — cross-file root-cause detection, dependency bumps,
  retry-with-feedback.
- **v3** — human-action reports, PR bodies, the full round trip on Killer's own
  fixtures.

v1's access-control work is **gated on Killer v1.1**, which hardens the four
frameworks currently tested against a parser rather than a running application.
The reason is this tool's whole premise: Giver's "proven gone" is only as
honest as Killer's rules, and a silent rule would make Giver certify a non-fix
as fixed — `reproduce` would report `gone` because the rule says nothing, not
because the hole closed. That is precisely what Killer's flagship IDOR rule was
doing in all three language variants until a live Django fixture caught it. v0
is unaffected, which is why it starts with misconfiguration.

## License

Apache-2.0. Same as Killer.
