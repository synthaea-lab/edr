#!/bin/bash
# #1090: the 8 h quiet period of ODD-HOUR-LOGON. utc_offset_minutes=600 puts "now" outside the work window.
# edr-lab logs on twice (second must not repeat), the VM clock is moved +9 h, edr-lab logs on twice again:
# the third must alert (the 8 h passed in event time), the fourth must not. The clock is restored from the host.
set -u
VM=edr-lab@192.168.100.38
SSH="ssh -o StrictHostKeyChecking=no -o BatchMode=yes"
OUT=$HOME/Documents/synthea/lab/captures/test-1090-20261102/F-expiry-8h
mkdir -p "$OUT"
$SSH $VM "bash -s" <<'EOS'
set -u
echo <lab-password> | sudo -S -p "" true
cd ~/lab1103; sudo rm -rf runx statex; mkdir runx statex
sed "s#/home/edr-lab/lab1103/state#/home/edr-lab/lab1103/statex#; s#/home/edr-lab/lab1103/log#/home/edr-lab/lab1103/runx#; s#/home/edr-lab/lab1103/run/agent.sock#/home/edr-lab/lab1103/runx/agent.sock#" base.toml > cfgx.toml
printf '\n[detection]\nutc_offset_minutes = 600\n' >> cfgx.toml
sudo bash -c "cd /home/edr-lab/edr-1103 && setsid nohup env SYNTHAEA_MTLS_PASSPHRASE=x ./target/release/agent --config /home/edr-lab/lab1103/cfgx.toml run --standalone --content-dir . --alerts /home/edr-lab/lab1103/runx/alerts.ndjson --events /home/edr-lab/lab1103/runx/events.ndjson > /home/edr-lab/lab1103/runx/agent.out 2>&1 < /dev/null &" > /dev/null 2>&1 < /dev/null
for i in $(seq 1 40); do grep -q "signal watch list" runx/agent.out 2>/dev/null && break; sleep 1; done
sleep 6
EOS
{
  echo "host start $(date -u +%F\ %T) UTC; VM $($SSH $VM date -u +%F\ %T) UTC"
  for n in 1 2; do $SSH $VM true; echo "$(date -u +%T) host: logon $n edr-lab rc=$?"; sleep 4; done
  $SSH $VM "echo <lab-password> | sudo -S -p '' date -s '+9 hours' >/dev/null; date -u +'VM clock now %F %T UTC'"
  sleep 3
  for n in 3 4; do $SSH $VM true; echo "$(date -u +%T) host: logon $n edr-lab rc=$?"; sleep 4; done
} > "$OUT/logons.txt" 2>&1
sleep 5
$SSH $VM "echo <lab-password> | sudo -S -p '' pkill -x agent; sleep 2; echo <lab-password> | sudo -S -p '' date -s '$(date "+%Y-%m-%d %H:%M:%S")' >/dev/null; date; cd ~/lab1103; echo <lab-password> | sudo -S -p '' chown -R edr-lab runx" >> "$OUT/logons.txt" 2>&1
scp -q -r $VM:lab1103/runx/. "$OUT/" 2>/dev/null
echo "== logons"; cat "$OUT/logons.txt"
echo "== ODD-HOUR alerts"; grep -i "ODD-HOUR\|odd-hour\|odd hour" "$OUT/alerts.ndjson" | cut -c1-300
echo "== count"; grep -ci "odd-hour\|odd hour" "$OUT/alerts.ndjson"
echo "== agent.out (zone/rule)"; grep -i "odd\|zone\|detection" "$OUT/agent.out" | head -4
