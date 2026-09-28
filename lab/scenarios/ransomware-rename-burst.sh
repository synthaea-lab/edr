#!/usr/bin/env bash
# Mass-rename ransomware scenario (T1486, check_mass_rename_pattern, issue #262).
#
# check_mass_rename_pattern (crates/rules/src/state.rs) fires when
# RANSOMWARE_RENAME_THRESHOLD (20) or more files are renamed within
# RANSOMWARE_RENAME_WINDOW_NS (5s), each rename keeping the original filename intact
# and appending a new suffix (invoice.pdf -> invoice.pdf.locked) — real ransomware's
# near-universal tell, extension-agnostic by design (matches on "old_path is a
# strict prefix of new_path", not a hardcoded extension list). The burst is counted
# both per-pid and per-ppid, so it fires whether one process does all the renames or
# a shell loop spawns one `mv` per file.
#
# This scenario creates its own throwaway directory of empty files and renames only
# those — no real data touched, nothing actually encrypted, matching the
# benign-by-construction convention of the rest of lab/scenarios/.
#
# Usage:
#   1) terminal A: sudo target/release/agent run
#   2) terminal B: ./lab/scenarios/ransomware-rename-burst.sh [single|loop]
#        single (default) — one python3 process renames every file (per-pid counter)
#        loop             — a shell `mv` loop, one short-lived pid per file, all
#                           sharing this script's shell as ppid (per-ppid counter)
#   3) expected in terminal A, one T1486 alert:
#        single: pid=... comm=python3: 20 files renamed with an appended suffix ...
#        loop:   ppid=...: 20 files renamed with an appended suffix by short-lived
#                children ... (shell-loop pattern)

set -euo pipefail

MODE="${1:-single}"

# $HOME, not /tmp: keeps this scenario independent of the /tmp write-intent carve-out
# (issue #325/#426) — renames aren't filtered there either way (mutation events are
# never dropped, only reads), but $HOME is also the more representative target: real
# ransomware goes after documents, not scratch space.
DIR="$(mktemp -d "$HOME/edr-lab-ransomware-XXXXXX")"
COUNT=22 # a couple past RANSOMWARE_RENAME_THRESHOLD (20) for timing margin

cleanup() { rm -rf "$DIR"; }
trap cleanup EXIT

echo "Creating $COUNT throwaway files in $DIR..."
for i in $(seq 0 $((COUNT - 1))); do
    : > "$DIR/file${i}.docx"
done

case "$MODE" in
single)
    # One process for every rename — like a real encryptor's single binary. Caught by
    # the per-pid counter.
    echo "[single] Renaming all $COUNT files, appending .locked, from one process..."
    python3 - "$DIR" "$COUNT" <<'EOF'
import os, sys
d, n = sys.argv[1], int(sys.argv[2])
for i in range(n):
    src = os.path.join(d, f"file{i}.docx")
    os.rename(src, src + ".locked")
EOF
    ;;
loop)
    # A shell `mv` loop: each `mv` is its own short-lived pid, so the per-pid counter
    # never climbs — but every child shares this script's shell as ppid, which the
    # per-ppid counter catches. This is a real Linux ransomware shape, not just a lab
    # artifact (issue #262 review).
    echo "[loop] Renaming all $COUNT files, appending .locked, one mv per file..."
    for i in $(seq 0 $((COUNT - 1))); do
        mv "$DIR/file${i}.docx" "$DIR/file${i}.docx.locked"
    done
    ;;
*)
    echo "unknown mode: $MODE (expected 'single' or 'loop')" >&2
    exit 2
    ;;
esac

echo "Done. Check the agent terminal for the T1486 alert."
