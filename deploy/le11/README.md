# Running zeroday-watch on le11

GitHub's `schedule:` trigger is late and skips runs, so the feed is refreshed from a machine that is always on.

- `run.sh` fetches origin, runs the tests, builds the feed, and pushes `docs/` and `state/` with a deploy key.
- `zeroday-watch.timer` runs it at :07 and :37 past each hour (`Persistent=true` catches up after downtime).
- Optional secrets go in `~/.config/zeroday-watch/env` (`KEY=value` lines, mode 600). Without them the LLM judge, X source and authenticated GitHub calls are skipped.

Install (as the user that owns the clone, which needs the deploy key in `~/.ssh` and remote `git@github-zdw:...`):

    mkdir -p ~/.config/systemd/user
    cp deploy/le11/zeroday-watch.{service,timer} ~/.config/systemd/user/
    systemctl --user daemon-reload
    systemctl --user enable --now zeroday-watch.timer

Check: `systemctl --user list-timers zeroday-watch.timer` and `journalctl --user -u zeroday-watch -n 30`.
Revoke: delete the deploy key in the repo settings, then `systemctl --user disable --now zeroday-watch.timer`.
