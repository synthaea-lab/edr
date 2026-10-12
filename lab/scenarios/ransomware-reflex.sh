#!/usr/bin/env bash
# Ransomware reflex acceptance scenario (issue #82): a benign "encryptor" that reads the
# canaries and then renames its way through the directory must be killed before it has
# processed more than N files.
#
# The reflex (agent/src/ransomware_join.rs) kills a process that raised the ransomware burst
# rule (T1486: RANSOMWARE_RENAME_THRESHOLD = 20 renames in 5 s) AND touched a planted canary
# within 60 s. So the earliest it can act is the 20th rename; N must be at least that plus
# the detection latency (sensor, ring buffer, drain, join). MAX_ENCRYPTED defaults to 60.
#
# This scenario creates and renames only its own throwaway files (doc_<n>.docx, 0 bytes) in
# the canary directory, and only reads the canaries; nothing is encrypted or deleted.
#
# Setup (Linux, root, eBPF):
#   1) pick a directory that is NOT under /tmp, /var/tmp or /dev/shm (the sensor drops
#      read-only opens there, so a read of a canary would never be seen) and that the agent
#      user can write, e.g. /srv/synthaea-lab-canaries; export CANARY_DIR to it
#   2) agent.toml:
#        [deception]
#        canary_dirs = ["/srv/synthaea-lab-canaries"]
#      (with the packaged unit add the directory to ReadWritePaths, docs/operations/deception.md)
#   3) terminal A, ENFORCE:  sudo target/release/agent run --enable-kill
#      terminal A, OBSERVE:  sudo target/release/agent run
#      Start it BEFORE this script and let it plant the canaries (it logs "canaries planted").
#   4) terminal B:           CANARY_DIR=... EXPECT=enforce ./lab/scenarios/ransomware-reflex.sh
#                            CANARY_DIR=... EXPECT=observe ./lab/scenarios/ransomware-reflex.sh
#
# Expected in alerts.ndjson (see ransomware-reflex.yaml): the canary detection (T1083,
# "canary file touched"), T1486, and RESPONSE-KILL: "killed pid N on a corroborated
# ransomware signal ..." when enforcing, "... would have been killed ... (observe-only)" when
# not. This script checks its own side and exits non-zero if it is not what EXPECT says:
#   enforce: the encryptor was SIGKILLed and at most MAX_ENCRYPTED files were renamed
#   observe: the encryptor ran to completion and every file was renamed
# It does not read the agent's alert log; that is what the replay engine is for.

set -uo pipefail

EXPECT="${EXPECT:?set EXPECT=enforce or EXPECT=observe to match how the agent was started}"
case "$EXPECT" in enforce | observe) ;; *) echo "EXPECT must be enforce or observe" >&2; exit 2 ;; esac
CANARY_DIR="${CANARY_DIR:?set CANARY_DIR to the directory listed in [deception] canary_dirs}"
COUNT="${COUNT:-300}"                 # files the encryptor would process if nothing stopped it
MAX_ENCRYPTED="${MAX_ENCRYPTED:-60}"  # the acceptance bound N (see above)
PAUSE="${PAUSE:-0.04}"                # seconds between renames: a real encryptor does work per file

case "$CANARY_DIR" in
  /tmp | /var/tmp | /dev/shm | /tmp/* | /var/tmp/* | /dev/shm/*)
    echo "CANARY_DIR must not be under /tmp, /var/tmp or /dev/shm: the sensor does not report reads there" >&2
    exit 2 ;;
esac
[ -d "$CANARY_DIR" ] || { echo "$CANARY_DIR is not a directory" >&2; exit 2; }
command -v python3 >/dev/null || { echo "needs python3" >&2; exit 2; }

# The canaries are the files the agent planted: each starts with the decoy header.
mapfile -t CANARIES < <(grep -l -m1 '^# SYNTHAEA DECOY' "$CANARY_DIR"/* 2>/dev/null)
if [ "${#CANARIES[@]}" -eq 0 ]; then
  echo "no canary in $CANARY_DIR: start the agent with [deception] canary_dirs first" >&2
  exit 2
fi
echo "canaries found: ${#CANARIES[@]}"

cleanup() { rm -f "$CANARY_DIR"/doc_*.docx "$CANARY_DIR"/doc_*.docx.locked "${ENCRYPTOR_PY:-}"; }
trap cleanup EXIT
cleanup
for i in $(seq 0 $((COUNT - 1))); do : > "$CANARY_DIR/doc_${i}.docx"; done
echo "created $COUNT throwaway files in $CANARY_DIR"

# The encryptor: ONE process (the join is per pid), reads every canary by absolute path
# first (as one enumerating the directory does), then renames file after file.
ENCRYPTOR_PY="$(mktemp "${TMPDIR:-/tmp}/synthaea-reflex-encryptor-XXXXXX.py")"
cat > "$ENCRYPTOR_PY" <<'PY'
import os, sys, time
d, count, pause = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
for canary in sys.argv[4:]:
    with open(canary, "rb") as f:
        f.read(64)
for i in range(count):
    src = os.path.join(d, f"doc_{i}.docx")
    os.rename(src, src + ".locked")
    time.sleep(pause)
PY
python3 "$ENCRYPTOR_PY" "$CANARY_DIR" "$COUNT" "$PAUSE" "${CANARIES[@]}" &
ENCRYPTOR_PID=$!
echo "encryptor pid $ENCRYPTOR_PID"
wait "$ENCRYPTOR_PID"
RC=$?
sleep 2

renamed=$(find "$CANARY_DIR" -maxdepth 1 -name 'doc_*.docx.locked' | wc -l)
killed=no
[ "$RC" -eq 137 ] && killed=yes   # 128 + SIGKILL
echo "encryptor exit status: $RC (killed: $killed); files renamed: $renamed of $COUNT"

status=0
if [ "$EXPECT" = enforce ]; then
  [ "$killed" = yes ] || { echo "FAIL: expected the encryptor to be SIGKILLed" >&2; status=1; }
  [ "$renamed" -le "$MAX_ENCRYPTED" ] \
    || { echo "FAIL: $renamed files renamed before the kill, more than N=$MAX_ENCRYPTED" >&2; status=1; }
else
  [ "$killed" = no ] || { echo "FAIL: observe-only must not kill the encryptor" >&2; status=1; }
  [ "$renamed" -eq "$COUNT" ] \
    || { echo "FAIL: observe-only must let the encryptor finish ($renamed of $COUNT)" >&2; status=1; }
fi
[ "$status" -eq 0 ] && echo "OK ($EXPECT): this script's side matches; check the T1083 canary detection, T1486 and RESPONSE-KILL in the agent's alerts.ndjson"
exit "$status"
