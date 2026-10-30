#!/usr/bin/env bash
# One feed update on a self-hosted runner (le11). Safe to run by hand or from the systemd timer.
set -euo pipefail
cd "$(dirname "$0")/../.."

# One run at a time; a slow run must not overlap the next tick.
exec 9>/tmp/zeroday-watch.lock
flock -n 9 || { echo "another run is active, skipping"; exit 0; }

# This clone only mirrors origin; throw away anything a failed run left behind.
git fetch -q origin main
git reset -q --hard origin/main

if ! python3 -m unittest discover -s tests -t . > /tmp/zeroday-watch-tests.log 2>&1; then
  tail -20 /tmp/zeroday-watch-tests.log
  echo "tests failed, not publishing" >&2
  exit 1
fi

# Settings (judge backend, optional secrets) load only after the tests, which must pass on a clean env.
# ZDW_JUDGE, ZDW_CLAUDE_BIN, OPENROUTER_API_KEY, GITHUB_TOKEN, X_BEARER_TOKEN live in the env file.
if [ -f "$HOME/.config/zeroday-watch/env" ]; then set -a; . "$HOME/.config/zeroday-watch/env"; set +a; fi

python3 -m zdwatch.run

git add docs state
if git diff --cached --quiet; then echo "no change"; exit 0; fi
git commit -q -m "chore: update feed (le11)"
git push -q origin HEAD:main
echo "published"
