#!/usr/bin/env bash
# Odd parent #1 for the T1 capture (#617): a web-application process that runs a shell and
# reconnaissance commands (the webshell shape: `id; uname -a; cat /etc/passwd`).
#
# Odd by: comm
# (The parent runs from the user's own directory, like the benign workload's tools, so the
# only thing odd about it is its name; `ml/tests/test_odd_parent_scenarios.py` keeps it so.
# From `/var/tmp` it would also trip `parent_path_is_suspicious` and a gain measured on it
# could not be credited to either feature: the review of #787.)
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
D=""
trap '[ -n "$D" ] && rm -rf "$D"' EXIT
mkdir -p "${HOME:?HOME must be set}/.local/share"
D="$(mktemp -d "$HOME/.local/share/edr-odd-webapp.XXXXXX")" && [ -d "$D" ] || { D=""; echo "no work directory" >&2; exit 1; }

for name in gunicorn php-fpm uwsgi httpd; do
    ln -s "$PY" "$D/$name"
    for round in 1 2; do
        "$D/$name" -c 'import subprocess; subprocess.run(["sh", "-c", "id; uname -a; cat /etc/passwd | head -3; ps -ef | head -3"], capture_output=True)'
        sleep 1
    done
    echo "  $name done"
done
