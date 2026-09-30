#!/usr/bin/env bash
# RESPONSE validation scenario (issue #25): automated kill + quarantine.
#
# One process beacons quickly to a local listener while a payload carrying a YARA
# marker is written to disk. With response enabled the agent kills the beaconing
# process and quarantines the payload, and audits both; with response off it does
# neither and audits that it would have (observe-only).
#
# Why this shape, not beacon.sh's: the kill fires on the correlator's `BAYES`
# verdict (crates/correlator), and beacon.sh's four connections 2s apart from four
# separate `nc` pids do not reach it. A single long-lived process that reconnects
# every second does (measured through the real detection path in
# agent/src/sink.rs's `a_beacon_with_a_dropped_payload_...` tests, in-process;
# this script is the same stream on a real kernel).
#
# Setup:
#   1) install lab/scenarios/response-marker.yar under <content-dir>/rules/yara/
#      (see that file), so the agent loads it at start
#   2) terminal A, ENFORCE:  sudo target/release/agent run --enable-kill --enable-quarantine
#      terminal A, OBSERVE:  sudo target/release/agent run
#   3) terminal B:           EXPECT=enforce ./lab/scenarios/response.sh
#                            EXPECT=observe ./lab/scenarios/response.sh
#
# Expected in alerts.ndjson (see response.yaml): BAYES, RESPONSE-KILL and
# RESPONSE-QUARANTINE. The message says which: "killed pid N ..." and
# "quarantined <path> ..." when enforcing, "... (observe-only)" when not.
# Afterwards the payload can be put back:
#   agent quarantine --alerts <alerts.ndjson> list | restore <sha256>
#
# This script checks its own side and exits non-zero if it is not what EXPECT says:
#   enforce: the beaconing process was SIGKILLed and the payload is gone
#   observe: the beaconing process ran to completion and the payload is untouched
# It does not read the agent's alert log; that is what the replay engine is for.

set -uo pipefail

EXPECT="${EXPECT:?set EXPECT=enforce or EXPECT=observe to match how the agent was started}"
case "$EXPECT" in enforce | observe) ;; *) echo "EXPECT must be enforce or observe" >&2; exit 2 ;; esac

PORT="${PORT:-4444}"
CONNECTIONS="${CONNECTIONS:-30}"   # 30s of beaconing: enough for the verdict, far more than needed
PAYLOAD="${PAYLOAD:-/tmp/synthaea-response-payload.bin}"
MARKER="SYNTHAEA-RESPONSE-SCENARIO-MARKER"

command -v nc >/dev/null || { echo "needs nc for the listener" >&2; exit 2; }

# Listener in its own session, cleaned up as a group (same reasoning as beacon.sh, #113).
setsid bash -c '
  while true; do
    nc -l -p "$1" >/dev/null 2>&1 || nc -l "$1" >/dev/null 2>&1
  done
' bash "$PORT" &
LISTENER_PGID=$!
trap 'kill -- -"$LISTENER_PGID" 2>/dev/null || true; rm -f "$PAYLOAD"' EXIT
sleep 1

# The dropped payload: opened for writing, which is what queues a YARA scan.
printf 'dropped payload %s\n' "$MARKER" > "$PAYLOAD"
echo "payload written: $PAYLOAD"

# The implant: ONE process that connects, closes, sleeps 1s, repeats. A subshell or a
# fresh `nc` per connection would be a new pid each time, and a kill only ever lands on
# the pid of the event that crossed the threshold.
bash -c '
  for _ in $(seq 1 "$1"); do
    { exec 3<>"/dev/tcp/127.0.0.1/$2"; } 2>/dev/null
    exec 3>&- 3<&-
    sleep 1
  done
' implant "$CONNECTIONS" "$PORT" &
IMPLANT_PID=$!
echo "implant pid $IMPLANT_PID beaconing to 127.0.0.1:$PORT (${CONNECTIONS} connections, 1s apart)"

wait "$IMPLANT_PID"
IMPLANT_RC=$?
sleep 3   # the YARA scan and the quarantine run off the event path

killed=no
[ "$IMPLANT_RC" -eq 137 ] && killed=yes        # 128 + SIGKILL
payload=present
[ -e "$PAYLOAD" ] || payload=gone

echo "implant exit status: $IMPLANT_RC (killed: $killed)"
echo "payload: $payload"

status=0
if [ "$EXPECT" = enforce ]; then
  [ "$killed" = yes ]    || { echo "FAIL: expected the implant to be SIGKILLed" >&2; status=1; }
  [ "$payload" = gone ]  || { echo "FAIL: expected the payload to be quarantined" >&2; status=1; }
else
  [ "$killed" = no ]     || { echo "FAIL: observe-only must not kill the implant" >&2; status=1; }
  [ "$payload" = present ] || { echo "FAIL: observe-only must not move the payload" >&2; status=1; }
fi
[ "$status" -eq 0 ] && echo "OK ($EXPECT): this script's side matches; check RESPONSE-KILL / RESPONSE-QUARANTINE in the agent's alerts.ndjson"
exit "$status"
