#!/usr/bin/env bash
# Every vendored schema matches its pin: `git hash-object <file>` equals the pin's `blob`, so the copy is byte for byte
# the upstream file at the pinned commit. Offline, and what CI runs. With --upstream it also asks GitHub whether the
# WATCHED ref still carries that blob, which says when upstream has moved on (informational, never a failure).
#
# `branch` and `watch` are two questions, and a pin that answers them with one field gets one of them wrong. `branch`
# is where the bytes CAME FROM and must stay true, which for a copy taken at a tag means the tag. `watch` is where
# upstream DEVELOPS, and it is what the poll asks about; a poll pointed at a tag can never fire, and would report
# success forever. window-ml's `scripts/check-pins.mjs` got this right first (window-ml #180); this is the same
# shape. `watch` defaults to `branch`, which is correct when a schema is vendored from a moving branch, as ours is.
set -euo pipefail
cd "$(dirname "$0")/.."
status=0
while IFS= read -r pin; do
    file="${pin%.pin.json}"
    read -r repo branch watch path blob < <(python3 -c 'import json,sys; p=json.load(open(sys.argv[1])); print(p["repo"], p["branch"], p.get("watch", p["branch"]), p["path"], p["blob"])' "$pin")
    actual=$(git hash-object "$file")
    if [[ "$actual" == "$blob" ]]; then
        echo "ok      $file"
    else
        echo "STALE   $file: blob $actual, pin says $blob (replace the file from $repo@$branch:$path or update the pin)"
        status=1
    fi
    if [[ "${1:-}" == "--upstream" ]]; then
        # A ref that is not a BRANCH does not move, so asking whether it still carries the blob answers yes forever.
        # That reads exactly like a check that is working, which is the one thing a check must never do.
        if ! gh api "repos/$repo/branches/$watch" --jq .name >/dev/null 2>&1; then
            echo "        cannot watch $watch: not a branch of $repo, so this poll can never fire (set \"watch\")"
        else
            head=$(gh api "repos/$repo/contents/$path?ref=$watch" --jq .sha 2>/dev/null || echo "unknown")
            [[ "$head" == "$blob" ]] && echo "        upstream $watch still carries it" || echo "        upstream $watch now has blob $head"
        fi
    fi
done < <(find proto -name '*.pin.json' | sort)
exit $status
