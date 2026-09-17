#!/usr/bin/env bash
# Every vendored schema matches its pin: `git hash-object <file>` equals the pin's `blob`, so the copy is byte for byte
# the upstream file at the pinned commit. Offline, and what CI runs. With --upstream it also asks GitHub whether the
# pinned branch still carries that blob, which says when upstream has moved on (informational, never a failure).
set -euo pipefail
cd "$(dirname "$0")/.."
status=0
while IFS= read -r pin; do
    file="${pin%.pin.json}"
    read -r repo branch path blob < <(python3 -c 'import json,sys; p=json.load(open(sys.argv[1])); print(p["repo"], p["branch"], p["path"], p["blob"])' "$pin")
    actual=$(git hash-object "$file")
    if [[ "$actual" == "$blob" ]]; then
        echo "ok      $file"
    else
        echo "STALE   $file: blob $actual, pin says $blob (replace the file from $repo@$branch:$path or update the pin)"
        status=1
    fi
    if [[ "${1:-}" == "--upstream" ]]; then
        head=$(gh api "repos/$repo/contents/$path?ref=$branch" --jq .sha 2>/dev/null || echo "unknown")
        [[ "$head" == "$blob" ]] && echo "        upstream $branch still carries it" || echo "        upstream $branch now has blob $head"
    fi
done < <(find proto -name '*.pin.json' | sort)
exit $status
