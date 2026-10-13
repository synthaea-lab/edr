#!/usr/bin/env bash
# Runs the Linux lab scenarios one after another, for the T1 retrain capture (#617), and writes
# what `t1_lineage_gain` needs to tell the scenarios' processes from the host's own.
#
# Lab VM only, as root (some scenarios write under /var/log and ~/.bashrc, restoring them).
#
#   terminal A:  agent capture-events --output events-malicious.jsonl     (as root)
#   terminal B:  sudo ./malicious-run.sh <out-dir>
#
# <out-dir>/run.json gets the runner's pid and the window of the run in ns since the epoch:
#   python -m synthaea_ml.evaluation.t1_lineage_gain ... --root-pid <pid> --start-ns .. --end-ns ..
# The runner is this script's own process: every scenario is its descendant. Anything else the
# capture saw in the window (the agent, ssh, cron) is not counted as an attack.
#
# What this is NOT: a representative set of attacks. These are the repository's own benign-by-
# construction simulations; most start from a shell, so a lineage gain can only show on the ones
# whose parent is odd (`lineage.sh`: a process named like a web server spawns a shell). Say so
# when reporting a number. Windows-only (`dns-exfil`) and service-dependent scenarios (web
# servers, MySQL), `signal.sh` (aims at the agent) and the ransomware ones (they exercise the
# response path, not behavior scoring) are left out.

set -u

[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo $0 <out-dir>" >&2; exit 1; }
OUT="${1:?usage: $0 <out-dir>}"
mkdir -p "$OUT"
SCENARIO_DIR="$(cd "$(dirname "$0")/../scenarios" && pwd)"
ODD_DIR="$(cd "$(dirname "$0")/odd-parents" && pwd)"
GAP="${GAP:-8}"          # seconds between scenarios, so each one's window is its own
TIMEOUT="${TIMEOUT:-120}"

SCENARIOS=(beacon bind-shell dropper-chain lineage persistence-write respawn-beacon argv log-clear)
command -v cc >/dev/null 2>&1 && SCENARIOS+=(ld-preload-hijack)
# Scenarios whose PARENT is odd (a web application or an Office-named process running a shell,
# a dropped binary running children): the ones a lineage feature has a chance to help on. They
# live beside this script (`odd-parents/`), not in lab/scenarios, because they have no rule
# sidecar: they exist for this capture.
SCENARIOS+=(odd-parents/webapp-spawns-shell odd-parents/office-spawns-shell odd-parents/dropped-binary-spawns-children)

START_NS="$(date +%s%N)"
RAN=()
FAILED=()
for name in "${SCENARIOS[@]}"; do
    case "$name" in
        odd-parents/*) script="$ODD_DIR/${name#odd-parents/}.sh" ;;
        *) script="$SCENARIO_DIR/$name.sh" ;;
    esac
    log="$OUT/${name//\//-}.log"
    [ -x "$script" ] || { echo "skip $name: $script not executable" >&2; continue; }
    echo "== $name"
    if timeout "$TIMEOUT" "$script" > "$log" 2>&1; then
        RAN+=("$name")
    else
        echo "   exit $? (log: $log)" >&2
        FAILED+=("$name")
    fi
    sleep "$GAP"
done
END_NS="$(date +%s%N)"

printf '{\n  "root_pid": %s,\n  "start_ns": %s,\n  "end_ns": %s,\n  "ran": [%s],\n  "failed": [%s]\n}\n' \
    "$$" "$START_NS" "$END_NS" \
    "$(printf '"%s",' "${RAN[@]:-}" | sed 's/,$//; s/^""$//')" \
    "$(printf '"%s",' "${FAILED[@]:-}" | sed 's/,$//; s/^""$//')" > "$OUT/run.json"
cat "$OUT/run.json"

# A run in which nothing ran is not a capture of malicious behavior: say so, so a script
# driving this does not go on to label an empty window.
[ "${#RAN[@]}" -gt 0 ] || { echo "no scenario ran (see the skips and failures above)" >&2; exit 1; }
