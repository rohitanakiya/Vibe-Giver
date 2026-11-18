# Where this strategy corpus came from

These are Vibe Killer's own fixture applications, copied unmodified from the
v1.0.0 tree. They are not samples written to suit this package, and that is the
point: a strategy tested against an input somebody wrote for it will pass
whatever the strategy does.

| file | source in Vibe Killer v1.0.0 | sha256 |
|---|---|---|
| `flask-vulnerable-app.py` | `fixtures/flask-vulnerable/app.py` | `05647c3b772acd2bd02ec0778953102ee7811304373d486d29035ce8eb18a34d` |
| `flask-patched-app.py` | `fixtures/flask-patched/app.py` | `1f5c18c08888a41970ae2c9537b1c61f58747a3f42d8523bb212a44d47ae8e19` |
| `django-vulnerable-settings.py` | `fixtures/django-vulnerable/config/settings.py` | `176132c14a82013f411caff33c878233b8005eb87b5add8b500b4847096107e5` |

Copied byte for byte. Nothing was adjusted, and nothing should be.

## Why the patched twin is here

`flask-patched/app.py` is the same application as `flask-vulnerable/app.py`
with every weakness correctly fixed, and Killer's own CI asserts that the
patched side yields **zero confirmed findings**. So it is not another test
input — it is the **answer key**. A strategy is checked against what the
project already treats as the correct fix, rather than against this package's
idea of one.

For the two findings v0 handles, the answer key says:

- `misconfig.debug-mode-enabled` → `debug=os.environ.get("FLASK_DEBUG") == "1"`
  (flask-patched), and `DEBUG = os.environ.get("DJANGO_DEBUG") == "1"`
  (django-patched line 19). Killer's own `remediation.guidance` for the rule
  names the first of those independently, which is two sources agreeing.
- `misconfig.cors-credentialed-wildcard` → an explicit allowlist with the
  origin and credentials headers set only for an origin on it, plus
  `Vary: Origin` (which express-patched also sets).

The generated fix is not a copy of the patched file. The patched twin is a
wholesale rewrite of its vulnerable version — different docstring, reordered
imports, removed scaffolding — and the brief requires minimal reviewable diffs
with no drive-by edits. So the twin settles *what correct means* and the
strategy produces the smallest change that gets there;
`assertOnlyLinesChanged` holds it to that.

## The line numbers

`debugFinding()` and `corsFinding()` in `fix_test.go` carry the finding ids,
rule ids, evidence keys and **line numbers that a real Killer v1.0.0 scan
reported** against this exact file — 277 and 104. They were copied from the run
recorded in `internal/contract/testdata/`, not chosen by reading the file.

If a line number here stops matching, the right response is to re-run Killer
and record what it says, not to edit the number until the test passes.

## The one thing in here that is not from Killer

`TestAPatternDodgeSilencesTheRuleWithoutFixingAnything` writes out a
*deliberately bad* fix: assigning the reflected origin through a local variable
so that Killer's CORS regex no longer matches while the application still
echoes every origin back with credentials allowed.

That is not a fixture, it is a measurement, and it is the justification for the
whole shape of this package. It demonstrates that passing a static re-scan is
**not** sufficient evidence that a weakness is gone, which is why strategies
here are constrained transformations rather than anything that makes a scan
come back clean.
