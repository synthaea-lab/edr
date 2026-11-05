#!/bin/bash
# usage: run-case.sh <case> <TZ-or-"-"> <offset-or-"-"> <nolocaltime:0|1> <account>...
# Starts the agent in the VM (detached, root, observe-only), logs on from the host as each
# account, stops the agent, copies alerts/events/log to lab/captures/test-1090-20261102/<case>/.
set -u
CASE=$1; TZV=$2; OFF=$3; NOLT=$4; shift 4
VM=edr-lab@192.168.100.38
SSH="ssh -o StrictHostKeyChecking=no -o BatchMode=yes"
OUT=$HOME/Documents/synthea/lab/captures/test-1090-20261102/$CASE
mkdir -p "$OUT"
$SSH $VM "bash -s" <<EOS
set -e
echo <lab-password> | sudo -S -p "" true
cd ~/lab1090; sudo rm -rf run-$CASE state-$CASE; mkdir run-$CASE state-$CASE
cp base.toml cfg-$CASE.toml
sed -i "s#/home/edr-lab/lab1090/state#/home/edr-lab/lab1090/state-$CASE#; s#/home/edr-lab/lab1090/log#/home/edr-lab/lab1090/run-$CASE#; s#/home/edr-lab/lab1090/run/agent.sock#/home/edr-lab/lab1090/run-$CASE/agent.sock#" cfg-$CASE.toml
if [ "$OFF" != "-" ]; then printf '\n[detection]\nutc_offset_minutes = $OFF\n' >> cfg-$CASE.toml; fi
ENVTZ=""; [ "$TZV" != "-" ] && ENVTZ="TZ=$TZV"
echo <lab-password> | sudo -S -p '' true
if [ "$NOLT" = 1 ]; then sudo mv /etc/localtime /etc/localtime.off; fi
sudo bash -c "cd /home/edr-lab/edr-1090 && setsid nohup env -u TZ \$ENVTZ SYNTHAEA_MTLS_PASSPHRASE=x ./target/release/agent --config /home/edr-lab/lab1090/cfg-$CASE.toml run --standalone --content-dir . --alerts /home/edr-lab/lab1090/run-$CASE/alerts.ndjson --events /home/edr-lab/lab1090/run-$CASE/events.ndjson > /home/edr-lab/lab1090/run-$CASE/agent.out 2>&1 < /dev/null &" > /dev/null 2>&1 < /dev/null
EOS
for i in $(seq 1 30); do $SSH $VM 'pgrep -x agent >/dev/null' && break; sleep 1; done
sleep 8
date -u +"host start %F %T UTC" > "$OUT/logons.txt"
for a in "$@"; do
  $SSH -o ConnectTimeout=10 $a@192.168.100.38 'true' ; echo "$(date -u +%T) UTC logon $a rc=$?" >> "$OUT/logons.txt"
  sleep 4
done
sleep 6
$SSH $VM "echo <lab-password> | sudo -S -p '' pkill -x agent; sleep 2; [ -e /etc/localtime.off ] && echo <lab-password> | sudo -S -p '' mv /etc/localtime.off /etc/localtime; ls -l /etc/localtime | cut -c1-80; cd ~/lab1090; cp cfg-$CASE.toml run-$CASE/; echo <lab-password> | sudo -S -p '' chown -R edr-lab run-$CASE" >> "$OUT/logons.txt" 2>&1
scp -q -r $VM:lab1090/run-$CASE/. "$OUT/"
echo "== $CASE: alerts"; cat "$OUT/alerts.ndjson" 2>/dev/null | cut -c1-400; echo "== agent.out"; head -20 "$OUT/agent.out"
