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
