#!/usr/bin/env bash
# Odd parent #1 for the T1 capture (#617): a web-application process that runs a shell and
# reconnaissance commands (the webshell shape: `id; uname -a; cat /etc/passwd`).
#
# A process "named like a web server" is a link or copy of a real interpreter under a web-server
# name (the kernel takes `comm` from the file name that was executed). Four names from
# `lineage.py::WEBSERVER_COMMS`, each spawning `sh -c` with commands a web application has no
# reason to run. The benign workload has web-application parents too (`job_webapp_children`), but
# they run one program with fixed arguments and never a shell: what differs is the child.
#
# Not a simulation of an exploit: nothing is attacked, read beyond /etc/passwd's first lines, or
# changed. Lab VM only. No sidecar `.yaml`: this is used by the ML capture, not by the rule suite.

set -euo pipefail

PY="$(command -v python3)" || { echo "python3 is needed" >&2; exit 1; }
D="$(mktemp -d /var/tmp/edr-odd-webapp.XXXXXX)" && [ -d "$D" ] || { echo "no work directory" >&2; exit 1; }
trap 'rm -rf "$D"' EXIT

for name in gunicorn php-fpm uwsgi httpd; do
    ln -s "$PY" "$D/$name"
    for round in 1 2; do
        "$D/$name" -c 'import subprocess; subprocess.run(["sh", "-c", "id; uname -a; cat /etc/passwd | head -3; ps -ef | head -3"], capture_output=True)'
        sleep 1
    done
    echo "  $name done"
done
