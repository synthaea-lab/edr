#!/bin/bash
# runs ON the Fedora VM (Europe/Paris) as edr-lab: #1090 8 h quiet period by moving the clock, `main` agent, no setting (platform zone), default window 07-20.
set -u
echo <lab-password> | sudo -S -p "" true
echo "edr-lab ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/zz-lab-x1090 >/dev/null   # temporary: the clock jumps invalidate the sudo timestamp; removed at the end
mkdir -p ~/lab1090c; cd ~/lab1090c; sudo rm -rf run state; mkdir run state
LOG=run/scenario.log; log() { echo "$*" >> $LOG; }
sudo systemctl stop chronyd 2>/dev/null; sudo timedatectl set-ntp false 2>/dev/null
[ -f ~/.ssh/id_lab ] || ssh-keygen -q -t ed25519 -N "" -f ~/.ssh/id_lab
U=ob_q; id $U >/dev/null 2>&1 || sudo useradd -m $U; sudo mkdir -p /home/$U/.ssh; sudo cp ~/.ssh/id_lab.pub /home/$U/.ssh/authorized_keys; sudo chown -R $U:$U /home/$U/.ssh; sudo chmod 700 /home/$U/.ssh; sudo chmod 600 /home/$U/.ssh/authorized_keys; sudo restorecon -R /home/$U/.ssh 2>/dev/null
sed "s#/home/edr-lab/lab1103/state#/home/edr-lab/lab1090c/state#; s#/home/edr-lab/lab1103/log#/home/edr-lab/lab1090c/run#; s#/home/edr-lab/lab1103/run/agent.sock#/home/edr-lab/lab1090c/run/agent.sock#" ~/lab1103/base.toml > cfg.toml
sudo bash -c "cd /home/edr-lab/edr-1103 && setsid nohup env SYNTHAEA_MTLS_PASSPHRASE=x /home/edr-lab/edr-main/agent --config /home/edr-lab/lab1090c/cfg.toml run --standalone --content-dir . --alerts /home/edr-lab/lab1090c/run/alerts.ndjson --events /home/edr-lab/lab1090c/run/events.ndjson > /home/edr-lab/lab1090c/run/agent.out 2>&1 < /dev/null &" >/dev/null 2>&1 < /dev/null
for i in $(seq 1 40); do grep -q "listening for" run/agent.out 2>/dev/null && break; sleep 1; done; sleep 4
sed 's/\x1b\[[0-9;]*m//g' run/agent.out | grep -i "odd-hour\|time zone" | head -2 | cut -c1-160 >> $LOG
logon() { ssh -i ~/.ssh/id_lab -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=5 $U@localhost true >> $LOG 2>&1; }
step() { sudo date -s "$1" >/dev/null; log "STEP $1 ($(date +%Z)) $2"; logon; sleep 3; }
step "2026-11-04 21:00:00" "first odd-hour logon of $U: alert expected"
sudo date -s "2026-11-04 21:00:04" >/dev/null; log "STEP 21:00:04 second logon 4 s later: silent expected"; logon; sleep 3
step "2026-11-05 04:30:00" "7 h 30 after the first alert: silent expected (quiet period 8 h)"
step "2026-11-05 05:30:00" "8 h 30 after the first alert: alert expected"
step "2026-11-05 06:00:00" "30 min after the second alert: silent expected"
step "2026-11-06 03:00:00" "21 h later: alert expected"
sleep 4; sudo pkill -x agent; sleep 2
sudo timedatectl set-ntp true 2>/dev/null; sudo systemctl start chronyd 2>/dev/null
sudo userdel -r $U 2>/dev/null; rm -f ~/.ssh/id_lab ~/.ssh/id_lab.pub
sudo chown -R edr-lab run; sudo rm -f /etc/sudoers.d/zz-lab-x1090
python3 - <<'PY'
import json,os,datetime,zoneinfo
tz=zoneinfo.ZoneInfo('Europe/Paris'); d=os.path.expanduser('~/lab1090c/run')
print(open(d+'/scenario.log').read())
for l in open(d+'/alerts.ndjson'):
    a=json.loads(l); m=a.get('message','')
    if a.get('technique')=='T1078' and 'ob_q' in m:
        print('ALERT',datetime.datetime.fromtimestamp(a['timestamp_ns']/1e9,tz).strftime('%m-%d %H:%M:%S %Z'),m[:110])
PY
touch run/DONE
