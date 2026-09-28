#!/usr/bin/env bash
# Shell-profile persistence scenario (T1037.004, check_persistence_write).
#
# check_persistence_write (crates/rules/src/stateless.rs) fires on a write-intent
# FileOpenEvent whose path contains a known persistence location (.bashrc, .zshrc,
# /etc/cron.d/, /etc/systemd/system/, /etc/profile.d/, launchd directories on macOS).
# Appending a line to a shell profile is one of the oldest, plainest Linux malware
# persistence moves — cryptominers and simple backdoors do it because it needs no
# special privilege beyond what the compromised user already has, and it survives
# every new interactive shell. This scenario is that shape against the user's own
# ~/.bashrc, with a clearly marked, harmless comment line — never sourced as a real
# command, and removed again in cleanup.
#
# Usage:
#   1) terminal A: sudo target/release/agent run
#   2) terminal B: ./lab/scenarios/persistence-write.sh
#   3) expected in terminal A, two alerts (#431 review): the append below, then one
#      more when cleanup restores the file on exit — restoring is itself a
#      write-intent open on a path containing ".bashrc":
#      T1037.004/T1053.003 — pid=...: write to a known persistence path (.bashrc): ...

set -euo pipefail

TARGET="$HOME/.bashrc"
MARKER="# edr-lab-test-persistence-marker (harmless — added and removed by lab/scenarios/persistence-write.sh)"

# A backup-and-restore cleanup, not the old grep-filter-into-a-new-file dance: that
# approach created a new inode on restore, losing permissions and — for a dotfile
# manager's symlinked .bashrc — replacing the symlink with a plain file (#431
# review). cp -p preserves both; restoring by writing the backup's content back in
# place keeps the original inode. The backup's own name deliberately doesn't
# contain ".bashrc", so creating/removing it never itself matches the rule.
EXISTED=0
[ -e "$TARGET" ] && EXISTED=1
BACKUP=$(mktemp /tmp/edr-lab-profile.XXXXXX)
[ "$EXISTED" -eq 1 ] && cp -p "$TARGET" "$BACKUP"

cleanup() {
    if [ "$EXISTED" -eq 1 ]; then
        cat "$BACKUP" > "$TARGET"
    else
        rm -f "$TARGET"
    fi
    rm -f "$BACKUP"
}
trap cleanup EXIT

# No `touch` first: GNU coreutils touch opens an existing file O_WRONLY to set its
# time, which is itself a write-intent open on a persistence path — a third,
# unwanted alert on Ubuntu/Debian (busybox touch uses utimensat instead, which is
# why this didn't show up testing on Alpine). `>>` already creates the file if it's
# missing, so touch was never needed (#431 review).
echo "Appending a marker comment to $TARGET (a real write-intent open, never sourced as a command)..."
echo "$MARKER" >> "$TARGET"

echo "Done. Check the agent terminal for two T1037.004/T1053.003 alerts: this append,"
echo "and one more when cleanup restores the file on exit."
