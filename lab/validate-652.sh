#!/usr/bin/env bash
# Runs INSIDE the fedora41 VM (repo in /synthaea, build in /var/synthaea/target); see
# lab/vagrant-hyperv/README.md to bring the VM up and put the checkout in /synthaea.
# Validated 2026-10-07 on Fedora 41, kernel 6.17.7, SELinux Enforcing: 8 pass, 0 fail.
# #652: the kill gate refuses a system service's main process (image under a trusted
# path, ppid 1), still kills the implant.
#   A  enforce, response.sh implant (bash child of a shell)      -> SIGKILLed, RESPONSE-KILL "killed"
#   B  enforce, same beacon as a systemd-run unit (bash, ppid 1) -> survives, "refused to kill"
#   C  observe, same unit                                        -> survives, "refused" not "would have"
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

start_agent() { # $1=tag $2..=flags
  local tag=$1; shift
  sudo pkill -9 -f "[t]arget/release/agent run" 2>/dev/null; sleep 1
  sudo rm -rf /sys/fs/bpf/synthaea /run/synthaea; sudo mkdir -p /run/synthaea
  sudo setsid env RUST_LOG=info "$BIN" run "$@" --alerts "$W/$tag.nd" >"$W/$tag.log" 2>&1 &
  sleep 8
  pgrep -f "[t]arget/release/agent run" >/dev/null || { tail -20 "$W/$tag.log"; fail "agent did not start ($tag)"; return 1; }
}
stop_agent() { sudo pkill -INT -f "[t]arget/release/agent run"; sleep 3; sudo chmod a+r "$W"/*.nd 2>/dev/null; }

service_beacon() { # beacon as a systemd unit: exe /usr/bin/bash, parent pid 1
  local unit=$1
  sudo systemd-run --quiet --unit="$unit" --collect bash -c '
    exec 9>/dev/null
    for _ in $(seq 1 90); do { exec 3<>/dev/tcp/127.0.0.1/4444; } 2>/dev/null; exec 3>&- 3<&-; sleep 1; done' 
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
