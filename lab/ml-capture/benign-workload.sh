#!/usr/bin/env bash
# Benign workload with VARIED PROCESS LINEAGE, for the T1 retrain capture (#617).
#
# Why this exists: the T1 model scores a process on its command line, its correlation context
# and its parents. An Isolation Forest never splits on a feature that is constant in training,
# so a benign capture whose processes all hang under one shell can never teach it that another
# parent is odd (ml/synthaea_ml/evaluation/t1_lineage_gain.py). This script runs ordinary, harmless commands from
# many different kinds of parent: a login-style shell, `sh -c`, `systemd-run` units (parent
# systemd), `xargs`, `timeout`, `env`, `setsid`, `nohup`, python and perl scripts that spawn
# children, a web client and server, web-application processes that run one program (never a
# shell), and a few user-installed binaries under the user's own directory acting as parents (a
# real admin's or developer's tools: benign). One job runs a script from /tmp, which is ordinary
# (installers, test runners) and keeps "parent in /tmp" from being an alarm by itself; the first
# capture of #617 ran ALL the user tools from /tmp, which made a suspicious parent path 4.9 % of
# the benign execs against 2.3 % of the malicious ones, an anti-signal that is an artefact of
# where the workload put its tools, not of how real hosts look. With the Linux sensor filling
# parent_image_path (#769) the path-based lineage features are live, so the workload's own
# habits matter.
#
# It does nothing destructive: it reads, lists, archives and deletes only its own files under
# a private work directory, and talks to a server it starts itself on 127.0.0.1.
#
# Usage (on the lab VM, as the user whose normal activity you want to model; root also works
# and adds the systemd-run units with the system manager as parent):
#   terminal A:  agent capture-events --output events.jsonl      (as root)
#   terminal B:  DURATION=1200 ./benign-workload.sh
# then stop the capture. DURATION is in seconds (default 900). SEED makes the order of jobs
# repeatable. The script prints the start and end (ns since the epoch) of the run.

set -u

DURATION="${DURATION:-900}"
SEED="${SEED:-1}"
# Unchecked, a failing mktemp (a full /tmp is enough) leaves WL empty and `set -u` does not
# fire on an empty value: as root, the mkdir/cp below would then write /bin, /data and /out.
WL="$(mktemp -d /tmp/edr-ml-workload.XXXXXX)" && [ -n "$WL" ] && [ -d "$WL" ] \
    || { echo "cannot create the working directory under /tmp" >&2; exit 1; }
mkdir -p "$WL/bin" "$WL/data" "$WL/out"
# The user's own tool directory (not /tmp): where a real user's installed tools live.
# Remember whether the parent directory is ours to remove: a `.local/share` that did not exist
# before this run is not left behind (as root that would be /root/.local/share).
[ -d "${HOME:?HOME must be set}/.local/share" ] || MADE_SHARE=1
mkdir -p "$HOME/.local/share"
TOOLS="$(mktemp -d "$HOME/.local/share/edr-ml-workload.XXXXXX")" && [ -d "$TOOLS" ] \
    || { echo "cannot create the tool directory under $HOME" >&2; rm -rf "$WL"; exit 1; }
RANDOM="$SEED"
PORT="${PORT:-18080}"

HTTP_PID=""
cleanup() {
    [ -n "$HTTP_PID" ] && kill "$HTTP_PID" 2>/dev/null
    rm -rf "$WL" "$TOOLS"
    if [ "${MADE_SHARE:-0}" = 1 ]; then rmdir "$HOME/.local/share" "$HOME/.local" 2>/dev/null || true; fi
}
trap cleanup EXIT

now_ns() { date +%s%N; }

# Files to read and archive.
for i in 1 2 3 4 5 6 7 8; do
    seq 1 $((200 * i)) | sed "s/^/line-$i-/" > "$WL/data/file$i.txt"
done

# User-installed "tools": copies of system binaries in the user's own directory.
for tool in bash python3; do
    src="$(command -v "$tool" 2>/dev/null)" && cp "$src" "$TOOLS/user-$tool" 2>/dev/null
done
# Web-application processes: python under the names of the usual application servers (the kernel
# takes `comm` from the file name), so the web-server lineage appears in the benign data the
# way it does on a host that runs one.
WEBAPPS=(gunicorn uwsgi php-fpm node httpd nginx)
if command -v python3 >/dev/null 2>&1; then
    for name in "${WEBAPPS[@]}"; do ln -s "$(command -v python3)" "$TOOLS/$name"; done
fi

# A local web server to be a network peer.
if command -v python3 >/dev/null 2>&1; then
    (cd "$WL/data" && exec python3 -m http.server "$PORT" --bind 127.0.0.1 >/dev/null 2>&1) &
    HTTP_PID=$!
    sleep 1
fi

# ---- jobs: each runs a handful of ordinary commands from a different kind of parent ----

job_login_shell() { bash -lc 'ls -la '"$WL"'/data | head -5; id; uname -a; df -h / | tail -1'; }
job_sh_c() { sh -c 'cat '"$WL"'/data/file1.txt | wc -l; date; hostname'; }
job_pipeline() { cat "$WL"/data/file*.txt | sort | uniq -c | sort -rn | head -3 >/dev/null; }
job_find_xargs() { find "$WL/data" -type f -name '*.txt' | xargs -n 2 wc -l >/dev/null; }
job_tar() { tar -czf "$WL/out/a.tgz" -C "$WL" data && tar -tzf "$WL/out/a.tgz" >/dev/null && rm -f "$WL/out/a.tgz"; }
job_timeout() { timeout 5 sleep 0.3; timeout 5 grep -c line "$WL/data/file3.txt" >/dev/null; }
job_env() { env LC_ALL=C sort "$WL/data/file2.txt" | head -1 >/dev/null; }
job_setsid() { setsid -w sh -c 'ps -eo pid,comm | head -3 >/dev/null'; }
job_nohup() { nohup sh -c 'sleep 0.2; ls /usr/bin | head -3' >/dev/null 2>&1; }
job_python_children() {
    command -v python3 >/dev/null 2>&1 || return 0
    python3 -c 'import subprocess,sys; [subprocess.run(c, shell=True, capture_output=True) for c in ("uname -r","id -u","ls /etc | head -3")]'
}
job_perl_children() { command -v perl >/dev/null 2>&1 && perl -e 'system("date"); system("hostname")' >/dev/null; }
job_curl_local() {
    command -v curl >/dev/null 2>&1 || return 0
    curl -s -o /dev/null "http://127.0.0.1:$PORT/file$((RANDOM % 8 + 1)).txt"
}
job_rpm_query() { command -v rpm >/dev/null 2>&1 && rpm -qa 2>/dev/null | head -20 >/dev/null; }
job_dpkg_query() { command -v dpkg >/dev/null 2>&1 && dpkg -l 2>/dev/null | head -20 >/dev/null; }
job_journal() { command -v journalctl >/dev/null 2>&1 && journalctl -n 20 --no-pager >/dev/null 2>&1; }
job_net_state() { ss -tn >/dev/null 2>&1; ip -br addr >/dev/null 2>&1; }
job_systemd_run() {
    command -v systemd-run >/dev/null 2>&1 || return 0
    if [ "$(id -u)" -eq 0 ]; then
        systemd-run --quiet --wait --collect sh -c 'uname -a; ls /etc | head -3' >/dev/null 2>&1
    else
        systemd-run --user --quiet --wait --collect sh -c 'uname -a; ls /etc | head -3' >/dev/null 2>&1
    fi
}
job_webapp_children() {
    local name="${WEBAPPS[$((RANDOM % ${#WEBAPPS[@]}))]}"
    [ -x "$TOOLS/$name" ] || return 0
    # One program with fixed arguments, never a shell: what an application server really runs.
    "$TOOLS/$name" -c 'import subprocess
for argv in (["date"], ["uname", "-r"], ["id", "-u"], ["hostname"]):
    subprocess.run(argv, capture_output=True)'
}
job_user_bash() { [ -x "$TOOLS/user-bash" ] && "$TOOLS/user-bash" -c 'ls '"$WL"'/data | head -2; id -un' >/dev/null; }
job_user_python() {
    [ -x "$TOOLS/user-python3" ] && "$TOOLS/user-python3" -c 'import subprocess; subprocess.run(["date"], capture_output=True)'
}
job_script_from_tmp() {
    printf '#!/bin/sh\nls %s/data | wc -l\nid -u\n' "$WL" > "$WL/bin/job.sh"
    chmod +x "$WL/bin/job.sh" && "$WL/bin/job.sh" >/dev/null
}
job_make_like() { sh -c 'for f in '"$WL"'/data/file[1-4].txt; do wc -c < "$f" >/dev/null; done'; }

JOBS=(
    job_login_shell job_sh_c job_pipeline job_find_xargs job_tar job_timeout job_env
    job_setsid job_nohup job_python_children job_perl_children job_curl_local
    job_rpm_query job_dpkg_query job_journal job_net_state job_systemd_run
    job_user_bash job_user_python job_script_from_tmp job_make_like
    job_webapp_children job_webapp_children
)

START_NS="$(now_ns)"
END_AT=$(( $(date +%s) + DURATION ))
RUNS=0
while [ "$(date +%s)" -lt "$END_AT" ]; do
    "${JOBS[$((RANDOM % ${#JOBS[@]}))]}" || true
    RUNS=$((RUNS + 1))
    sleep "0.$((RANDOM % 9 + 1))"
done
END_NS="$(now_ns)"

echo "benign workload done: $RUNS jobs over ${DURATION}s as uid $(id -u)"
echo "start_ns=$START_NS"
echo "end_ns=$END_NS"
