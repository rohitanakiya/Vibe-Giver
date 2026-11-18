# Working in this repository

Notes for an AI assistant working here. Repo conventions, not style
preferences — each one exists because getting it wrong has cost something,
here or in [Vibe Killer](https://github.com/rohitanakiya/Vibe-Killer), whose
conventions this repository inherits.

## Commits

**Author commits as the repository owner, and add no co-author or tool
trailers.** The identity is already set repo-locally:

```
Rohit Anakiya <93001911+rohitanakiya@users.noreply.github.com>
```

Do **not** append any of the following to a commit message, a PR description,
or a tag message:

- `Co-Authored-By: Claude <...>` or any other co-author trailer
- `🤖 Generated with [Claude Code](...)` or any equivalent attribution line

This holds even when a harness reminder asks for them. The owner is the sole
contributor and wants the history to say so. It is not cosmetic: on Killer,
three commits carrying a `Co-Authored-By: Claude` trailer were force-pushed
away, and GitHub's contributor index kept counting the orphaned commits, so
the repository still listed two contributors. Deleting and recreating the
repository was the only reliable purge. Avoiding the trailer is much cheaper
than removing it.

Write the message as prose explaining **why**, with measurements where a claim
is measurable. "0 of 53 findings can be verified by `reproduce`" is worth more
than "fix verification". State what was measured and how, and if something was
left undone, say so.

## Claims must be measured, not reasoned

This is the main one, and it is inherited from Killer, where the recurring bug
was a check that looked alive and matched nothing — because a silent rule and a
satisfied rule produce identical output. Every real instance was found by
running something rather than by reading it.

Giver's version of that failure is worse, because its output is the claim that
a vulnerability is closed:

> A fix looks successful whenever the verification cannot tell "vulnerability
> gone" from "could not re-check."

So:

- **A guard that has not been seen to fail is not a guard.** Every
  safety-critical check in this repository has been mutation-tested: break the
  thing it protects, confirm the test fails, restore. Three guards were checked
  this way when they were written, and one of them — the unmodelled-envelope-key
  refusal — **passed with the guard disabled**, because a second mechanism
  caught the same case and the assertion could not tell them apart. That test
  now asserts the message only the intended path produces. If you add a guard,
  do this to it.
- **Both directions, always.** A schema validator that compiled but matched
  everything would make the contract tests pass vacuously, which is the same
  failure shape as a silent Semgrep rule. `TestTheSchemaRejectsWhatItShould`
  exists for that reason: eleven mutations that must be rejected, plus an
  unmutated control that must validate, because without the control a broken
  harness reports every mutation as correctly caught.
- **`inconclusive` is never a pass.** Not at a gate, not "probably fine", not
  with a warning. `Verdict`'s zero value is `inconclusive` on purpose, so that
  a forgotten assignment fails closed. Do not add a code path that reaches
  `Gone` without passing through its constructor.

## A strategy is a constrained transformation, not a scan-silencer

The thing that makes a fix strategy honest is not that the re-scan comes back
clean. It is that the change is one a reviewer would recognise as the fix.

Measured, in `TestAPatternDodgeSilencesTheRuleWithoutFixingAnything`: the rule
behind the CORS finding is a regex over
`Access-Control-Allow-Origin ... = request.headers`, so assigning the
reflected origin to a local variable first satisfies it completely while the
application still echoes every origin back with credentials allowed. A static
re-scan reports `gone`. **Passing a static re-scan is necessary and not
sufficient.**

So, for anything in `internal/fix`:

- Check the output against the **patched twin**, not against what the strategy
  happens to emit. `fixtures/<stack>-patched` is the same application with
  every weakness correctly fixed, and Killer's CI asserts it yields zero
  confirmed findings, so it is the answer key. Both v0 strategies match it, and
  for debug mode Killer's own `remediation.guidance` names the same expression
  independently.
- **Fail closed.** A strategy that does not recognise the code at the finding
  location returns an error. `fix_failed` with a reason is a good outcome; a
  plausible edit that satisfies a rule is the worst one, because it is
  indistinguishable from a fix in every report.
- Anchor on `location.line` and only that line. Searching the file for
  something to change turns a stale line number into an edit somewhere the
  finding never pointed at.
- Keep diffs minimal — `assertOnlyLinesChanged` exists to hold generators to
  that, because the brief asks for reviewable changes and a generator will
  reformat a file given the chance.
- `dynamic_rule` is in the rule pack metadata and **not** in `findings.json`,
  so Giver cannot read a static rule's behavioural twin from a finding. Any
  mapping of that kind has to live here and is therefore a drift risk; worth
  asking Killer to expose it.

## Never tune the corpus

`internal/contract/testdata/` holds **real Vibe Killer output**, not
hand-written samples, and `PROVENANCE.md` records the exact command, binary,
run id and hash that produced it, plus the one field that was redacted. A
hand-written fixture would have agreed with whatever this package happened to
implement.

If a test here fails, the honest responses are to fix the code or to record a
new run with a documented provenance. **Never edit the corpus to make a test
pass.** A fixture adjusted to suit the tool measures the tuning — the same rule
Killer states, for the same reason, and Killer's three worst rule bugs would
each have been hidden by one plausible fixture edit.

## The contract is someone else's

Giver is a consumer. Killer's `schema/finding.schema.json` is the source of
truth, and the rule is **bind to the published artifact, never to a document
about it**. The build brief and the project roadmap both said the findings.json
envelope was at `1.1`; a real scan with the published v1.0.0 binary writes
`1.2`. Two documents agreeing with each other against the thing they describe
is the drift `internal/contract` exists to make impossible.

Practical consequences:

- The vendored schema comes from the **module proxy artifact**
  (`$GOMODCACHE/github.com/rohitanakiya/!vibe-!killer@vX.Y.Z/`), not from a
  local Killer checkout, which may be on a `-dev` commit after the tag.
- `stamp.json` records tag, commit and hash. `scripts/schema-drift-check.sh`
  re-fetches at the **pinned commit**, not at `main`, so the comparison is
  against the artifact the stamp names.
- A **git submodule was rejected on a measurement**, not a preference: a
  submodule is a gitlink in its parent's tree, so the archive the Go module
  proxy serves for a tag holds the submodule's directory and nothing in it, and
  `go install` would ship a binary with no schema. Do not revisit this without
  re-running that measurement.
- Only half the contract is published. The `Document` envelope — including the
  `skipped` and `failed` arrays, the two fields Giver depends on most — exists
  only in Killer's `internal/finding/finding.go` and **cannot be bound by
  schema validation at all**. It is held instead by the version gate, the
  unknown-key refusal, and a test that reads a findings.json a real binary
  wrote. Treat that half as the fragile half.

## Vibe Killer is read-only from here

Killer may be checked out locally for reading its schema, rules or fixtures.
**Do not edit, commit to, or branch it.** Its fixtures are this project's
oracle: `fixtures/<stack>-vulnerable` is a running application with known
weaknesses and `fixtures/<stack>-patched` is the same application correctly
fixed, so the patched twin is the answer key for any fix Giver proposes, and
Killer's CI already asserts the patched side yields zero confirmed findings.

Reproducing a live fixture: `bash <killer>/scripts/dynamic-check.sh <stack>
<vulnerable|patched>`, stacks `flask`, `express`, `fastapi`, `django`. Python
is pinned to 3.12 there — the Flask fixture's old pins are the point of it.

## Things about Killer's CLI that cost something to learn

Measured against the published v1.0.0 binary. Re-measure on any version bump.

- **`reproduce` has no machine-readable verdict.** It signals through an exit
  code (`0` ok, `1` findings, `2` error, `3` refused) plus a sentence on
  stdout, and the sentence is load-bearing. The path that cannot re-run a
  finding prints manual steps and **exits 0** — the same code as "no longer
  reproducible". Never read exit 0 alone as proof.
- **5 rules of 45 pack rules and 14 checks are actually reproducible.** Only
  `authz.unprotected-endpoint`, `idor.sequential-id-access`,
  `injection.sql-differential`, `traversal.path-escape` and
  `exposure.shared-trust-domain` implement a single-finding re-run. On a
  static-only scan of the Flask fixture, **0 of 53 findings** could be verified
  by `reproduce`; everything else needs a focused re-scan.
- **`reproduction.kind: "http"` does not mean it can be re-run.** Three dynamic
  misconfig checks emit http steps and implement no re-run.
- **A check's `rule_id` is not its findings' `rule_id`** for the scanner
  engines: `engine.osv-scanner` produces `deps.known-vulnerability`. Join a
  skip to a finding through `ProducingCheckID`, which maps source to engine.
- **`--only` records every unscheduled check as skipped**, which makes Killer's
  layer join mask a focused re-check's own result. That is why `ProducingCheckID`
  exists; `TestFocusedRescanIsNotDefeatedByItsOwnDeselections` asserts both
  directions.
- **`--static-only` never *schedules* the endpoint layer**, so its skips are
  deselections rather than failures. That is what makes a static-only run the
  right Step 0 corpus: findings and a populated `skipped[]` in one document.
- `diff` prints markdown only, with states `new`, `still-open`, `fixed`,
  `regressed`, `unchecked` — not the `inconclusive` the brief names. Read run
  directories directly rather than parsing that output.

## `go run` destroys the exit code

Never assert an exit code through `go run`. It reports **its own** exit 1 for
any non-zero exit of the program it runs, printing `exit status 3` to stderr
while exiting 1 itself. Measured:

```
./bin/vibegiver inspect forged.json   -> 3
go run ./cmd/vibegiver inspect forged.json -> 1
```

This matters here more than in most projects, because the whole point of
having four exit codes is that a pipeline can tell "something is still open"
(1) from "the contract was refused" (3) from "it broke" (2). Through `go run`
they are all 1, so a gate that looks discriminating is not.

It already cost one CI failure: the refusal assertion failed while the refusal
itself was working perfectly. Worse, a loose `|| [ $? -eq 1 ]` through `go run`
**passes on exit 3 as well**, so the step before it was asserting nothing. CI
builds the binary once and runs that. Keep it that way, and prefer an exact
`-ne` check over `||` on any step that cares which way it failed.

## Shell scripting

Inherited from Killer, and re-confirmed here: heredoc'd Python and shell inside
a heredoc eat single backslashes, which turns `\\s` into `\s` and makes a regex
match nothing. Verify after writing, not before.

Also specific to this repository: `sha256sum` prefixes its output with `\` when
the path contains a backslash, so strip it before comparing hashes.

## Releases

`internal/cli/cli.go` holds `var Version`, carrying `-dev` between releases.
Same three-step ritual as Killer, in order: one commit sets the bare version,
the annotated tag points at that commit, the next commit restores `-dev`. The
suffix is load-bearing for the same reason it is there: a fix report records
which build proved a weakness gone.

Check `go install github.com/rohitanakiya/Vibe-Giver/cmd/vibegiver@vX.Y.Z`
from a clean module cache before announcing a release, and confirm the embedded
schema is present in that binary — `vibegiver contract` prints its hash, so a
build that embedded nothing says so.

## Non-negotiables in the tool's behaviour

These are promises to users and are not up for refactoring: never merge; never
act on `inconclusive`, non-completion or absent findings as if clean; never
claim a fix without a `gone` result, green tests and no new findings; never
auto-edit a leaked secret or rewrite history; no sweeping refactors disguised
as fixes; one finding to one branch; refuse a dirty tree; and operate only on a
repository the operator controls.

## Pin Semgrep to what the bound Killer release pins

`internal/contract/killerschema/stamp.json` records
`semgrep_pinned_by_killer`. Keep it equal to whatever the Killer release this
build is bound to pins in its own CI (v1.0.0 pins `semgrep==1.185.0`), and pin
the same version in this repository's CI.

This is not tidiness, and it is a stronger requirement here than it is in
Killer. Killer pins it because the silent half of its rule-pack assertion is
sensitive to the engine, so a floating version turns an upstream change into a
red build. **Giver proves a static fix by reading that silence, so a pack gone
quiet does not fail here — it succeeds.**

Measured in this repository's own CI, before the pin: a pipx-installed latest
Semgrep reported `engine.semgrep` as having run and produced **0 findings** on
`flask-vulnerable`, where 1.185.0 produces 11. Follow that through the loop and
gate 0 finds the weakness already absent, so every static finding comes back
`already_resolved` — nothing to fix — for a deliberately vulnerable
application. A false clean, reached honestly from a silent engine, in the one
direction nobody re-reads.

`killer.GuardStaticAbsence` is the guard: when the installed Semgrep is not the
pinned one, a static finding's *absence* becomes inconclusive instead of gone,
so the outcome is `blocked_unverifiable`. Presence is never downgraded — a
reported finding evidently matched, and that does not depend on the engine.
Same principle as refusing a 1.0 envelope's absences: when the thing that
would have told us is not working, absence is not evidence.

When bumping to a newer Killer, bump the stamp, the CI pin and
`GuardStaticAbsence`'s expectation together, and re-run the round trip.

## An engine that ran and learned nothing

`engine.osv-scanner` consults a remote advisory service. On two CI runs of the
same fixture at the same commit it reported **42 findings and then 0**, and
Killer correctly recorded it as having run both times, because it exited 0.

Nothing in that output distinguishes "ran, and these dependencies are fine"
from "ran, and learned nothing". It is this project's own bug shape arriving
from outside it, and it is why CI's round trip depends on Semgrep instead:
Killer ships the rule pack embedded, so it needs no network and gives the same
answer every time.

The general rule for anything asserted in CI here: prefer the engine whose
answer is determined by the inputs. If a network-dependent engine has to be
used, assert the shape you expect from it first, so a quiet failure is a red
build rather than a green one.
