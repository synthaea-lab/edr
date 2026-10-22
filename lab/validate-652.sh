#!/usr/bin/env bash
# Runs INSIDE the fedora41 VM (repo in /synthaea, build in /var/synthaea/target); see
# lab/vagrant-hyperv/README.md to bring the VM up and put the checkout in /synthaea.
# #652: the kill gate refuses a system service's main process (image under a trusted
# path, ppid 1), still kills the implant.
#
# Scenarios B and C's beacon is `lab/scenarios/v652-beacon.rs`, a compiled binary installed to
# /usr/libexec/v652-beacon (old-dov, 2026-10-20): `204b5ff` made `service_main_path_is_trusted`
# exclude shells and interpreters, so a `bash -c '...'` unit main (what this script used before)
# is no longer a protected service main at all — B and C would stop testing the refusal this PR
# adds and instead just exercise the ordinary kill path, the same gap A already covers.
#   A  enforce, response.sh implant (bash child of a shell)            -> SIGKILLed, RESPONSE-KILL "killed"
#   B  enforce, same beacon as a systemd-run unit (v652-beacon, ppid 1) -> survives, "refused to kill"
#   C  observe, same unit                                               -> survives, "refused" not "would have"
set -uo pipefail
cd /synthaea
[ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"
export CARGO_TARGET_DIR=/var/synthaea/target
BIN=$CARGO_TARGET_DIR/release/agent
W=/tmp/v652; sudo rm -rf "$W"; mkdir -p "$W"
PASS=0; FAILS=0
pass() { echo "[PASS] $*"; PASS=$((PASS+1)); }
fail() { echo "[FAIL] $*"; FAILS=$((FAILS+1)); }
echo "== $(. /etc/os-release; echo "$PRETTY_NAME") kernel $(uname -r) selinux $(getenforce 2>/dev/null) =="

echo "== build =="; cargo build --release -p agent 2>&1 | tail -2
[ -x "$BIN" ] || { echo "[FAIL] no agent binary"; exit 1; }
sudo mkdir -p /etc/synthaea; sudo cp crates/config/data/default-agent.toml /etc/synthaea/agent.toml

echo "== build beacon =="; rustc -O -o /tmp/v652-beacon lab/scenarios/v652-beacon.rs
sudo install -m 0755 /tmp/v652-beacon /usr/libexec/v652-beacon
[ -x /usr/libexec/v652-beacon ] || { echo "[FAIL] no beacon binary"; exit 1; }

start_agent() { # $1=tag $2..=flags
  local tag=$1; shift
  sudo pkill -9 -f "[t]arget/release/agent run" 2>/dev/null; sleep 1
  sudo rm -rf /sys/fs/bpf/synthaea /run/synthaea; sudo mkdir -p /run/synthaea
  sudo setsid env RUST_LOG=info "$BIN" run "$@" --alerts "$W/$tag.nd" >"$W/$tag.log" 2>&1 &
  sleep 8
  pgrep -f "[t]arget/release/agent run" >/dev/null || { tail -20 "$W/$tag.log"; fail "agent did not start ($tag)"; return 1; }
}
stop_agent() { sudo pkill -INT -f "[t]arget/release/agent run"; sleep 3; sudo chmod a+r "$W"/*.nd 2>/dev/null; }

service_beacon() { # beacon as a systemd unit: exe /usr/libexec/v652-beacon, parent pid 1
  local unit=$1
  sudo systemd-run --quiet --unit="$unit" --collect /usr/libexec/v652-beacon
  sleep 1; systemctl show -p MainPID --value "$unit"
}
alive() { ! journalctl -u "$1" --no-pager | grep -qiE "killed|signal|SIGKILL|failed"; } # a clean run ends "Deactivated successfully"
listener() { setsid bash -c 'while true; do nc -l -p 4444 >/dev/null 2>&1 || nc -l 4444 >/dev/null 2>&1; done' & LPID=$!; sleep 1; }
unlisten() { kill -- -"$LPID" 2>/dev/null; sudo pkill -f "nc -l" 2>/dev/null; }

echo "== A: enforce, implant from a shell =="
start_agent A --enable-kill --enable-quarantine && {
  EXPECT=enforce bash lab/scenarios/response.sh > "$W/A.script" 2>&1; grep -E "^implant exit|^payload" "$W/A.script"; grep -q "killed: yes" "$W/A.script" && pass "A: implant SIGKILLed" || fail "A: implant not killed"; true
  stop_agent
  grep -c 'RESPONSE-KILL' "$W/A.nd" | sed 's/^/  RESPONSE-KILL alerts: /'
  grep -q "refused to kill" "$W/A.nd" && fail "A: a refusal was raised for the implant" || pass "A: no refusal for the implant"
}

echo "== B: enforce, same beacon as a unit =="
listener
start_agent B --enable-kill --enable-quarantine && {
  PID=$(service_beacon v652-b); echo "  unit main pid $PID, ppid $(ps -o ppid= -p "$PID" 2>/dev/null), exe $(readlink /proc/$PID/exe 2>/dev/null)"
  sleep 45
  alive v652-b && pass "B: service main process not killed by the agent" || fail "B: service main process was killed"
  stop_agent
  grep -q "BAYES" "$W/B.nd" && pass "B: BAYES still raised" || echo "[info] B: no BAYES crossing (beacon too slow to judge)"
  grep -h "refused to kill" "$W/B.nd" | head -2
  grep -q "refused to kill pid $PID" "$W/B.nd" && pass "B: refusal audited" || fail "B: no refusal for pid $PID"
}
sudo systemctl stop v652-b 2>/dev/null

echo "== C: observe, same unit =="
start_agent C && {
  PID=$(service_beacon v652-c); sleep 45
  alive v652-c && pass "C: not killed" || fail "C: killed"
  stop_agent
  grep -h "refused to kill\|would have" "$W/C.nd" | head -3
  grep -q "refused to kill pid $PID" "$W/C.nd" && pass "C: says refused" || fail "C: no refusal"
  grep -q "would have killed pid $PID" "$W/C.nd" && fail "C: claims it would have killed" || pass "C: no would-have-killed claim"
}
sudo systemctl stop v652-c 2>/dev/null; unlisten
echo "== $PASS pass, $FAILS fail =="
exit $FAILS
