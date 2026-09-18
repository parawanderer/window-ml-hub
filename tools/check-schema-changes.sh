#!/usr/bin/env bash
# A change to a schema this repository OWNS has to say so in proto/wmlhub/CHANGES.md.
#
# Other repositories vendor these files, and from their side a schema change is invisible until something needs the
# field: the reader's code is correct against the schema it has, so nothing fails, it is simply absent. window-ml
# spent a fortnight with a `Presence` that had no `chain` for exactly that reason, and its stale copy also had the
# certificate window rule backwards, which is the kind of gap that is only found by the thing it breaks.
#
# So this is a gate rather than a habit: the note cannot be forgotten, because the change cannot land without it.
set -euo pipefail
cd "$(dirname "$0")/.."
base="${1:-origin/main}"
notes="proto/wmlhub/CHANGES.md"

changed=$(git diff --name-only "$base...HEAD" -- proto/wmlhub/ || true)
[[ -z "$changed" ]] && { echo "ok      no schema this repository owns was changed"; exit 0; }

if grep -qx "$notes" <<<"$changed"; then
    echo "ok      $(grep -vx "$notes" <<<"$changed" | wc -l | tr -d ' ') schema file(s) changed, and $notes says so"
    exit 0
fi
cat >&2 <<MSG
UNNOTED $notes was not touched, but these were:
$(sed 's/^/          /' <<<"$changed")

        Add an entry saying what changed and whether a reader has to do anything about it. Additive fields that a
        reader can ignore still get a line: what it costs them is knowing it is there, and that is the whole reason
        this file exists.
MSG
exit 1
