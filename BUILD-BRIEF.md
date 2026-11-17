# Build Brief — Vibe Giver (verified remediation tool, twin of Vibe Killer)

> Paste as the project brief for Claude Code. Separate repository from Vibe
> Killer. Go. Build in the phases below, to the safety rules in §3.

## What this is

**Vibe Giver** reads the findings that **Vibe Killer** produces and, for the
findings it can safely fix, proposes a **verified** code change: one whose
correctness is proven by re-running Killer's own check and the project's own
test suite. It opens the change as a pull request for a human to review. It
never merges, and it never claims a fix it hasn't proven.

It is a defensive developer tool — it *repairs* the weaknesses Killer reports.
Build Vibe Giver only; treat Killer's output as a fixed input contract.

## 0. The governing principle (from Killer's own hardest lesson)

Across Killer's build, the recurring bug was *a feature that looked alive
because the only thing asserting it couldn't tell the difference.* Vibe Giver's
version of that trap is precise and fatal:

> **A fix looks successful whenever the verification can't tell "vulnerability
> gone" from "couldn't re-check."**

So the verification must distinguish three outcomes, not two —
**gone / still-present / inconclusive** — and **only "gone" counts as fixed.**
`inconclusive` is a verification *failure*, never a pass. This is the Giver-side
mirror of the `inconclusive` contract Killer shipped in `1f79802`; honor it or
reproduce the whole class of bug on the remediation side.

## 1. Bind to Killer's real contract first (build Step 0, before any fix logic)

Vibe Giver is a *consumer*. Do not hand-copy Killer's schema from this document —
**bind to the published artifacts** so the two can't drift:

- **Source of truth:** Killer's `schema/finding.schema.json`. Vendor it (git
  submodule or a checked-in copy with a version stamp), generate/validate the Go
  structs against it, and **fail loudly on a `schema_version` mismatch** (the
  Document envelope is at `1.1`; the per-finding schema is `"const": "1.0"`).
- **Fixture the parser** against a real `findings.json` from an actual Killer
  run — one that contains both findings and a `skipped[]` / non-completion
  entry, so the "don't act on non-completion" path is tested from day one.
- **Bind to Killer's CLI**, don't reimplement it. Read the exact flags and
  **exit codes** from `vibekiller --help` / its README and depend on those:
  - `vibekiller reproduce <finding_id>` — re-verify one finding. Giver's whole
    loop hinges on this; treat its `inconclusive` result as "not verified."
  - `vibekiller diff <runA> <runB>` — states `new` / `fixed` / `regressed` /
    `inconclusive`.
  - `vibekiller scan --repo . [--target … --i-own-this-target | --static-only]`.
- **Enumerate the real rule-id / category set** from Killer's rule pack (≈25
  contract categories across languages as of this writing) and key the fix
  strategies (§5) off that actual list, not a guessed one.

## 2. What Giver acts on (and what it must not)

- Process **only** findings the contract marks genuinely actionable:
  `status: open` **and** `remediation.fixable_by_giver: true`.
- **Never act on non-completion or absence.** A `skipped` / failed / missing
  finding, or an `inconclusive` diff/reproduce, is "unknown" — never "clean" and
  never "safe to touch." Giver never concludes an app is fixed from an absence
  of findings.
- Everything not auto-fixable → a human-action report (§7), never a pretend fix.

## 3. Hard safety rules (build to these exactly)

- **Never auto-merge.** Output is a pull request / patch on a branch; a human
  reviews and merges. A bad security patch can silently break auth, payments, or
  access control.
- **One finding → one branch** `vibegiver/<finding_id>`, reviewable and
  revertable independently.
- **Clean working tree required**; refuse to run on a dirty tree.
- **Operate only on a repo the operator controls.**
- **Never fabricate a fix.** If Giver can't make the check report *gone* while
  keeping tests green, it marks the finding `fix_failed` with the captured
  reason — it never reports success on an unverified or `inconclusive` change.
- **Secrets are never "fixed" in code.** A leaked-credential finding
  (`fixable_by_giver:false`) produces rotation + history-scrub instructions,
  never an edit that hides the secret.

## 4. The fix → verify loop (the core)

For each actionable finding:

1. **Branch** `vibegiver/<finding_id>` from the finding's `location.repo_rev`
   (or current HEAD if clean and newer).
2. **Confirm it still reproduces here** via `vibekiller reproduce <finding_id>`.
   - `gone` → mark `already_resolved`, stop (don't "fix" a non-issue).
   - `inconclusive` → **cannot verify a fix for this, so don't attempt one** —
     mark `blocked_unverifiable` with the reason. Attempting a blind fix is the
     exact trap in §0.
   - `still-present` → proceed.
3. **Generate a candidate fix** (§5) targeting the root cause.
4. **Verify — every gate must pass:**
   a. `vibekiller reproduce <finding_id>` now returns **`gone`** (not
      `inconclusive` — that's a fail).
   b. the project's existing **test suite stays green**.
   c. a focused Killer re-scan of the touched area introduces **no new finding**.
   d. lint / build / typecheck pass.
5. **All pass** → open the PR (§6), set `status: fixed`. **Any fail** → retry up
   to N with the failure fed back into generation; after N, discard the branch,
   mark `fix_failed` with the reason. Never leave a half-applied change.

Log every step to `runs/giver/<finding_id>/`.

## 5. Fix generation — root cause, not band-aid

- Start from `remediation.root_cause_hint`, `category`, and `rule_id`.
- **Fix the class, not the one line.** For `broken-access-control`, scan for
  sibling endpoints with the same pattern and prefer a single shared mechanism
  (middleware / guard / policy) over N scattered checks; note the broader pattern
  in the PR even when the landed fix is scoped.
- **Minimal, reviewable diffs** — no drive-by refactors, no reformatting, no
  dependency bumps beyond what the fix needs.
- **Match the codebase's conventions** (framework idioms, existing middleware).
- **Add a regression test** encoding the vulnerability (failing-before /
  passing-after), committed with the fix.
- **Strategy registry keyed by Killer's actual categories.** Canonical starts:
  - `broken-access-control` → ownership/authz guard at the data layer, shared.
  - `injection` → parameterized queries / safe builder; never string-built SQL.
  - `security-misconfiguration` → tighten CORS, add security headers, disable
    debug, sanitize error output.
  - `auth` (JWT) → enforce verify + expiry, reject `alg:none`, secret to env.
  - `vulnerable-dependency` → bump to nearest safe version, run tests, flag a
    required major bump for human sign-off.
  - `secrets-exposure` → **human-required**: rotation + history-scrub steps,
    no code edit.

## 6. PR / output

Per landed fix, open a PR (or write patch + PR body to disk if no remote):

- **Title:** `[Vibe Giver] Fix <title> (<finding_id>)`
- **Body:** the finding (what / severity / CWE / where); **proof it was real**
  (Killer's reproduce output, before); **proof it's fixed** (Killer reproduce
  returning `gone`, after + test result + "no new findings" result); the diff
  rationale and root-cause note; any follow-up (sibling occurrences found).
- **Never merges.**

Also emit `fix_report.json` mapping each `finding_id` →
`{status, branch, pr_url, verification_results}` so Killer / the human can
reconcile on the next scan. `status` ∈ `fixed | already_resolved |
blocked_unverifiable | fix_failed | human_required`.

## 7. Findings Giver won't fix

For `fixable_by_giver:false`, non-completion, or `blocked_unverifiable`: a clear,
prioritized **human-action report** with the reason and exact steps (e.g. "rotate
this key in the provider console, purge from history with `git filter-repo`,
confirm it's gone from the client bundle"). Never pretend these are auto-fixable.

## 8. Stack — Go, matched to Killer's house style

- Go (same major version as Killer); `cobra` CLI; single installable binary.
- Git automation: `go-git` or shell `git`; branch-per-finding.
- Fix generation via the coding agent/LLM, but **every candidate is gated by the
  deterministic loop in §4** — the model proposes, the loop disposes.
- PR creation via `gh` or the host API behind an interface (so it can also just
  write patches locally).
- Run tests/builds in an **isolated worktree or container**.
- Study Killer's repo layout and CI for conventions to mirror.

## 9. Build in phases (ship each end-to-end before the next)

- **v0:** Step-0 contract binding (schema structs + validation + sample
  `findings.json` fixture) → load findings → the §4 loop skeleton on ONE
  category, `security-misconfiguration` (smallest, safest diffs: CORS / headers /
  debug) → branch + local patch output, no PR yet. **Honor `inconclusive` from
  day one.**
- **v1:** `injection` + `broken-access-control` strategies; regression-test
  generation; PR creation; `fix_report.json`.
- **v2:** cross-file root-cause/pattern detection; dependency bumps;
  retry-with-feedback.
- **v3:** human-action reports; polish PR bodies; full loop demo.

## 10. Deliverables

- Installable Go CLI.
- Contract-bound findings model, validated against Killer's published
  `schema/finding.schema.json`, failing loudly on version mismatch.
- The §4 verify loop and the §5 strategy registry.
- **End-to-end proof using Killer's own vulnerable fixtures as targets:** run
  Killer → feed findings to Giver → Giver fixes → Killer re-scan reports the
  fixtures clean. That round trip is the demo and the test.
- README leading with the three guarantees: **PR-only, every fix proven `gone`,
  never acts on `inconclusive`/non-completion.**

## 11. Non-goals

- No auto-merging, ever.
- No acting on `inconclusive`, non-completion, or absent findings as if clean.
- No claiming a fix without a `gone` result + green tests + no new findings.
- No auto-editing of leaked secrets; no destructive history rewrites without
  explicit human action.
- No sweeping refactors disguised as fixes; no running on repos not controlled.
