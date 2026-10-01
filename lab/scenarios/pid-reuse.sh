#!/usr/bin/env bash
# Recycled-pid scenario (T1486, check_mass_rename_pattern's in-place-edit exclusion,
# issue #519).
#
# RuleState remembers the image a pid exec'd (`pid_image_path`) so the T1486 rule can
# tell a real `sed -i.bak` (a trusted /bin/sed renaming 20+ files, a legitimate burst)
# from an encryptor. Without a process-incarnation stamp that memory outlives the
# process: when the kernel recycles the pid, a forked child that only sets its comm to
# `sed` inherits the real sed's exclusion and renames its files unseen.
#
# This scenario forces the recycling, which is what makes it deterministic: it runs a
# real `sed`, remembers its pid, then writes `pid-1` into /proc/sys/kernel/ns_last_pid
# so the very next fork receives that pid. The child sets comm=sed (prctl) and renames
# its own throwaway files with a `.bak` suffix, exactly the shape of the exclusion.
#
# Needs root (ns_last_pid), python3 and /bin/sed. No real data is touched: the files
# are empty, created in a throwaway directory.
#
# Usage:
#   1) terminal A: sudo target/release/agent run --alerts /tmp/a --events /tmp/e
#   2) terminal B: sudo ./lab/scenarios/pid-reuse.sh [recycled|real]
#        recycled (default) - the renames come from a recycled pid: one T1486 alert
#        real               - control: a real `sed -i.bak` over the same files: no alert
#   3) expected in terminal A:
#        recycled: pid=<X> comm=sed: 22 files renamed with an appended suffix ...
#        real:     nothing (the exclusion is intact: the stamp must not break it)

set -euo pipefail

MODE="${1:-recycled}"

if [ "$(id -u)" -ne 0 ]; then
    echo "needs root: it writes /proc/sys/kernel/ns_last_pid" >&2
    exit 2
fi

DIR="$(mktemp -d "$HOME/edr-lab-pid-reuse-XXXXXX")"
COUNT=22 # a couple past RANSOMWARE_RENAME_THRESHOLD (20) for timing margin

cleanup() { rm -rf "$DIR"; }
trap cleanup EXIT

echo "Creating $COUNT throwaway files in $DIR..."
for i in $(seq 0 $((COUNT - 1))); do
    : > "$DIR/s${i}.conf"
done

case "$MODE" in
real)
    # The legitimate shape: a real sed in-place edit with a backup suffix.
    echo "[real] sed -i.bak over $COUNT files..."
    sed -i.bak 's/^/#/' "$DIR"/s*.conf
    ;;
recycled)
    echo "[recycled] real sed first, then its pid recycled by a forked child..."
    python3 - "$DIR" "$COUNT" <<'PY'
import ctypes
import os
import sys
import time

d, n = sys.argv[1], int(sys.argv[2])
PR_SET_NAME = 15

# 1. A real exec of sed: the agent learns "this pid is /bin/sed". Its stdout is
#    discarded; only the pid and the exec matter.
pid = os.fork()
if pid == 0:
    devnull = os.open(os.devnull, os.O_WRONLY)
    os.dup2(devnull, 1)
    os.execv("/bin/sed", ["sed", "--version"])
os.waitpid(pid, 0)
print(f"real sed ran as pid {pid}", flush=True)
time.sleep(1)  # let the agent drain the exec before the pid is reused

# 2. Make the next fork return that same pid. Retry: any other fork on the box in
#    between steals the number.
for attempt in range(50):
    with open("/proc/sys/kernel/ns_last_pid", "w") as f:
        f.write(str(pid - 1))
    child = os.fork()
    if child == 0:
        # The recycled process: comm=sed, no exec, renames its files with a .bak suffix.
        libc = ctypes.CDLL(None)
        libc.prctl(PR_SET_NAME, b"sed", 0, 0, 0)
        for i in range(n):
            src = os.path.join(d, f"s{i}.conf")
            os.rename(src, src + ".bak")
        os._exit(0)
    os.waitpid(child, 0)
    if child == pid:
        print(f"forked child got the recycled pid {child} (attempt {attempt + 1})", flush=True)
        break
else:
    sys.exit("could not get the pid recycled; rerun on a quieter machine")
PY
    ;;
*)
    echo "unknown mode: $MODE (expected 'recycled' or 'real')" >&2
    exit 2
    ;;
esac

echo "Done. Check the agent terminal."
