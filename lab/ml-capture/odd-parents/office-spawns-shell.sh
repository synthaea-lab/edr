#!/usr/bin/env bash
# Odd parent #2 for the T1 capture (#617): a process named like an Office application that runs a
# shell (the macro shape: `winword` starting `sh -c ...`).
#
# Odd by: comm
# (Run from the user's own directory, not `/var/tmp`: see webapp-spawns-shell.sh.)
#
# `lineage.py::OFFICE_COMMS` has no Linux application in it, so on a real Linux host this lineage
# never occurs and the feature is constant 0 in any benign capture: an Isolation Forest cannot
# split on a column that never varies in training, so this scenario measures what the model does
# with a value it has never seen (the trainer's feature-bounds guard is the thing that should
# catch it), not a learned lineage. Say so when reporting a number.
#
# Lab VM only; nothing is attacked or changed. No sidecar `.yaml`.

set -euo pipefail

BASH_BIN="$(command -v bash)"
D=""
trap '[ -n "$D" ] && rm -rf "$D"' EXIT
mkdir -p "${HOME:?HOME must be set}/.local/share"
D="$(mktemp -d "$HOME/.local/share/edr-odd-office.XXXXXX")" && [ -d "$D" ] || { D=""; echo "no work directory" >&2; exit 1; }

for name in winword excel outlook; do
    cp "$BASH_BIN" "$D/$name"
    for round in 1 2 3; do
        # A subshell in parentheses so the inner shell forks instead of exec-ing in place.
        "$D/$name" -c '(sh -c "whoami; hostname; ls /etc | head -2")'
        sleep 1
    done
    echo "  $name done"
done
