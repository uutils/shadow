#!/usr/bin/env bash
#
# Fail the build if AI tooling artifacts appear in the changes under review.
#
# The project's public face carries no AI tooling attribution: commits, PRs and
# tracked files read as ordinary engineering work. This runs on pull requests
# and inspects only what the PR changes, so existing history is not rewritten
# and unrelated files are not scanned.
#
# Usage: no-ai-traces.sh [BASE_REF]        (default: origin/main)
#        PR_TITLE / PR_BODY may be set in the environment to also check them.

set -uo pipefail

BASE="${1:-origin/main}"
status=0

# Tool names that must not appear in commit messages, PR text, or added lines.
# Genuinely word-boundaried: without \b, "llm" matched "smallmap" and
# "anthropic" matched "philanthropic", failing unrelated changes. The trailing
# alternatives carry their own boundaries.
TOOLS='\b(claude|copilot|anthropic|chatgpt|openai|gemini|codex|llms?)\b'
TOOLS="$TOOLS"'|\bgpt-?[0-9o]|\bai[ -](generated|assisted)\b|co-authored-by:.*\[bot\]'

# Paths deliberately exempt from the added-lines scan:
#   - this script (it necessarily contains the patterns)
#   - the clean-room audit records, which must disclose their own methodology
#     to be usable as compliance evidence
#   - CONTRIBUTING.md, which states the project's policy on these tools and so
#     must be able to name them
EXEMPT='^(\.github/scripts/no-ai-traces\.sh|CONTRIBUTING\.md|docs/CLEAN-ROOM-AUDIT-.*\.md)$'

fail() { printf '::error::%s\n' "$1"; status=1; }

# ---------------------------------------------------------------------------
# 1. Local-only files must never become tracked.
# ---------------------------------------------------------------------------
FORBIDDEN='^(CLAUDE\.md|PLAN-shadow-rs\.md|docs/(claude|gemini|copilot)-review-.*)$'
while IFS= read -r f; do
    [ -n "$f" ] && fail "tracked file must stay local and gitignored: $f"
done < <(git ls-files | grep -iE "$FORBIDDEN" || true)

# ---------------------------------------------------------------------------
# 2. Commit messages introduced by this PR.
# ---------------------------------------------------------------------------
while IFS= read -r sha; do
    [ -z "$sha" ] && continue
    if git log -1 --format='%B' "$sha" | grep -qiE "$TOOLS"; then
        subject=$(git log -1 --format='%s' "$sha")
        fail "commit $(git rev-parse --short "$sha") mentions an AI tool: $subject"
    fi
done < <(git rev-list "$BASE..HEAD" 2>/dev/null || true)

# ---------------------------------------------------------------------------
# 3. Pull request title and body (passed in via the environment, never
#    interpolated into the shell by the workflow).
# ---------------------------------------------------------------------------
for field in PR_TITLE PR_BODY; do
    value="${!field-}"
    if [ -n "$value" ] && printf '%s' "$value" | grep -qiE "$TOOLS"; then
        fail "pull request ${field#PR_} mentions an AI tool"
    fi
done

# ---------------------------------------------------------------------------
# 4. Lines this PR adds to tracked files.
# ---------------------------------------------------------------------------
while IFS= read -r file; do
    [ -z "$file" ] && continue
    printf '%s' "$file" | grep -qE "$EXEMPT" && continue
    hits=$(git diff "$BASE...HEAD" -- "$file" \
           | grep '^+' | grep -v '^+++' | grep -inE "$TOOLS" || true)
    if [ -n "$hits" ]; then
        fail "$file adds a line mentioning an AI tool:"
        printf '%s\n' "$hits" | head -5 | sed 's/^/    /'
    fi
done < <(git diff --name-only --diff-filter=d "$BASE...HEAD" 2>/dev/null || true)

if [ "$status" -eq 0 ]; then
    echo "no AI tooling artifacts found in this change"
fi
exit "$status"
