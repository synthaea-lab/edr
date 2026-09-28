#!/usr/bin/env bash
# BIND-SHELL validation scenario (T1571, issue #263's "bind shell test").
#
# Serves an interactive shell on a local TCP port, the textbook backdoor
# listener: `sh` wired to a listening `nc` through a FIFO. Loopback only
# (127.0.0.1), so nothing outside the host can reach it, and it is torn down
# as soon as the one test connection ends.
#
# What it exercises:
#   - LISTENER-DRIFT (crates/rules/src/state.rs, check_listen_port_drift): a
#     listener absent from the agent's startup snapshot. The rule reads the
#     netlink sock_diag poll (NETLINK_POLL_INTERVAL, 10s, agent/src/commands/
#     linux.rs), so the listener stays up LISTEN_HOLD seconds before the client
#     connects, long enough for at least one poll to see it.
#   - eBPF socket telemetry from #263 (SocketBind, SocketListen, SocketAccept
#     for the listening `nc`): captured in the event log, no rule consumes
#     them yet.
#
# The FIFO form instead of `nc -e` works with every nc variant (busybox,
# traditional, OpenBSD); only the listen syntax differs, hence the fallback.
#
# Usage:
#   1) terminal A: sudo target/release/agent run      (start it FIRST: the
#      rule alerts on listeners not seen at startup)
#   2) terminal B: ./lab/scenarios/bind-shell.sh
#   3) expected in terminal A, within ~10s of the listener opening:
#      T1571 — pid=... comm=nc new listener on 127.0.0.1:4445 — not seen at agent startup

set -euo pipefail

PORT=4445
LISTEN_HOLD=12

WORKDIR="$(mktemp -d)"
FIFO="$WORKDIR/shell.fifo"
mkfifo "$FIFO"

# Listener in its own session (process group), so cleanup reaches the nc and
# sh children too, not just the wrapper (same pattern as beacon.sh, #113).
setsid bash -c '
  fifo=$1 port=$2
  sh -i <"$fifo" 2>&1 | { nc -l -s 127.0.0.1 -p "$port" 2>/dev/null || nc -l 127.0.0.1 "$port"; } >"$fifo"
' bash "$FIFO" "$PORT" &
LISTENER_PGID=$!
cleanup() {
    kill -- -"$LISTENER_PGID" 2>/dev/null || true
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

sleep 1
echo "Bind shell listening on 127.0.0.1:$PORT; holding ${LISTEN_HOLD}s for the agent's listener poll..."
sleep "$LISTEN_HOLD"

echo "Connecting and running 'id' through the shell..."
REPLY="$(printf 'id\nexit\n' | nc -w3 127.0.0.1 "$PORT" 2>/dev/null || true)"
if ! grep -q 'uid=' <<<"$REPLY"; then
    # Fail loudly: a scenario that "succeeds" without a working shell behind the
    # port validates nothing.
    echo "FAIL: no shell answered on 127.0.0.1:$PORT (reply: ${REPLY:-<empty>})" >&2
    exit 1
fi
echo "  shell answered: $(grep -o 'uid=[^ ]*' <<<"$REPLY")"

echo "Done. Check for the T1571 alert in the agent terminal."
