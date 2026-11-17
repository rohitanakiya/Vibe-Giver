#!/usr/bin/env bash
#
# Re-fetch Vibe Killer's published finding schema at the tag this build is
# pinned to, and compare it against the vendored copy.
#
# This is the anti-drift property a git submodule would have given, recovered
# without a submodule. A submodule was measured and rejected: its content is a
# gitlink in the parent tree, not a tree, so the archive the Go module proxy
# serves for a tag contains the submodule directory and nothing inside it, and
# a //go:embed over that path would build on a developer checkout and ship an
# empty schema to anyone who ran `go install`.
#
# So the file is vendored, and this script is what notices if the upstream
# contract moves under it. It fetches by commit sha rather than by branch, so
# the comparison is against the artifact the stamp names and not against
# whatever main happens to hold today.
#
# Exit codes mirror the CLI: 0 identical, 2 could not check, 3 drifted.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

STAMP="internal/contract/killerschema/stamp.json"
VENDORED="internal/contract/killerschema/finding.schema.json"

for f in "$STAMP" "$VENDORED"; do
    if [ ! -f "$f" ]; then
        echo "missing $f" >&2
        exit 2
    fi
done

read_stamp() {
    python -I -c "import json,sys;print(json.load(open(sys.argv[1],encoding='utf-8'))[sys.argv[2]])" "$STAMP" "$1"
}

COMMIT="$(read_stamp pinned_commit)"
TAG="$(read_stamp pinned_tag)"
PATH_IN_REPO="$(read_stamp source_path)"
WANT_HASH="$(read_stamp sha256)"

# The hash in the stamp has to describe the file next to it, or the comparison
# below is against a number nobody checked.
HAVE_HASH="$(sha256sum "$VENDORED" | awk '{print $1}' | tr -d '\\')"
if [ "$HAVE_HASH" != "$WANT_HASH" ]; then
    echo "FAIL: the vendored schema does not match its own stamp." >&2
    echo "  file:  $HAVE_HASH" >&2
    echo "  stamp: $WANT_HASH" >&2
    echo "One of the two was edited without the other. Nothing upstream is implicated." >&2
    exit 3
fi

URL="https://raw.githubusercontent.com/rohitanakiya/Vibe-Killer/${COMMIT}/${PATH_IN_REPO}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "Fetching Killer $TAG ($COMMIT) schema"
echo "  $URL"
if ! curl -fsSL --max-time 30 -o "$WORK/upstream.json" "$URL"; then
    echo "could not fetch the upstream schema; treating as a failure to check, not as agreement" >&2
    exit 2
fi

UPSTREAM_HASH="$(sha256sum "$WORK/upstream.json" | awk '{print $1}' | tr -d '\\')"

if [ "$UPSTREAM_HASH" = "$WANT_HASH" ]; then
    echo "OK: vendored schema is identical to Killer $TAG."
    exit 0
fi

echo "FAIL: the vendored schema differs from Killer $TAG." >&2
echo "  vendored: $WANT_HASH" >&2
echo "  upstream: $UPSTREAM_HASH" >&2
echo >&2
diff -u "$VENDORED" "$WORK/upstream.json" >&2 || true
echo >&2
echo "A tag is immutable, so this means the vendored copy was edited by hand." >&2
echo "To move to a newer Killer, update the stamp and re-vendor from the module" >&2
echo "proxy artifact, then run the contract tests: they read a real findings.json" >&2
echo "and will say whether the envelope moved too." >&2
exit 3
