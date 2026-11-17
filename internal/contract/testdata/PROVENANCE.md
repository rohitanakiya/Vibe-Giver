# Where this test corpus came from

Not hand-written. Every file here is output from a real Vibe Killer run, and
the point of recording how it was produced is that a hand-written sample would
have agreed with whatever this package happened to implement.

## `flask-vulnerable-static-only.json`

Produced on 2026-11-18 by the **published** Vibe Killer v1.0.0 binary —
installed with `go install github.com/rohitanakiya/Vibe-Killer/cmd/vibekiller@v1.0.0`
from the module proxy, not built from a working tree — scanning a copy of
Killer's own `fixtures/flask-vulnerable`:

```
vibekiller init                 # starter config, in the fixture copy
vibekiller scan --repo app --static-only --runs-dir <scratch>/runs
```

Command exited 1 (`ExitFindings`: an open finding at or above the `high`
threshold), which is the expected outcome for a deliberately vulnerable
fixture.

What it contains, and why this particular run was chosen:

| | |
|---|---|
| envelope `schema_version` | `1.2` |
| findings | 53 (11 `sast`, 42 `deps`) |
| `skipped` entries | 11 (8 endpoint, 2 runtime, 1 exposure) |
| `failed` entries | 0 — the key is absent, since Killer omits it when empty |
| per-finding `schema_version` | `1.0` for all 53 |
| `status` | `open` for all 53 |
| `fixable_by_giver` | `true` for all 53 |

`--static-only` is what makes it the right fixture for Step 0. It never
*schedules* the endpoint, runtime or exposure layers, and Killer records each
deselected check in `skipped[]` with the reason. So this one document exercises
both halves of the contract the brief asks to be tested from day one: findings
that are present, and eleven checks whose silence means nothing at all.

It also happens to be a document on which a broken filter is invisible — all 53
findings are open and all 53 are marked auto-fixable, so a triage filter that
matched everything would look identical to a correct one. The tests therefore
feed the filter synthetic findings that must be *rejected* as well as this run.

### The one alteration

`repo_path` was the only machine-specific field in the document. It was
rewritten from the scratch directory the fixture copy lived in to the literal
string `fixtures/flask-vulnerable`, and the file was re-serialised with
two-space indentation. Nothing else was touched: `findings`, `skipped` and
`counts` compare byte-equal as parsed JSON against the original, which is
asserted in the commit message rather than only claimed here.

- sha256 of the unaltered run output: `b7d34b274dc1288b462d52277a6cd90dad36ec6ad51a79246b60e935fa9ade86`
- Killer run id: `20261117-231333-382284`

No finding, skip, severity or count in this file has been adjusted to suit
Vibe Giver, and none should be. A fixture tuned to the tool measures the
tuning — the same rule Killer's own `CLAUDE.md` states, for the same reason.
If a test here fails, the honest responses are to fix this package or to
record a new run, never to edit this file.
