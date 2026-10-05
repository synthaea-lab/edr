#!/usr/bin/env bash
# Web access-log signatures and the web-shell correlation (T1505.003, issue #478 level 2,
# ADR-0022).
#
# The agent tails the web server's access log (an `access_combined` source in
# agent.toml). A request that matches a detection signature becomes an `HttpRequest`
# event; every request is counted in one `HttpSummary` per 60 s window. When a shell is
# then spawned by the web server, the correlator pairs it with the nearest signature
# request and raises T1505.003: this is what an uploaded web shell, or an exploited
# application running a command, looks like from the host.
#
# This scenario sends one request per signature to a real local web server, then starts a
# shell whose parent is named like a web server (a copy of a shell binary called `nginx`,
# as lineage.sh does). It changes no data on the server: the requests are 404s or reads.
#
# Prerequisites (a real server, not a mock):
#   - nginx or Apache listening on 127.0.0.1:80, curl installed, access log in the default
#     combined format (Ubuntu/Debian: /var/log/nginx/access.log or
#     /var/log/apache2/access.log). A custom LogFormat is not supported in v1.
#   - agent.toml declares it, with the path of YOUR server's log:
#         [[logs.sources]]
#         path = "/var/log/nginx/access.log"
#         kind = "access_combined"
#   - The agent can read the log: root, or CAP_DAC_READ_SEARCH (the packaged unit has it).
#
# Usage:
#   1) terminal A: sudo target/release/agent --config /etc/synthaea/agent.toml run \
#        --alerts /tmp/a --events /tmp/e
#   2) terminal B: ./lab/scenarios/web-webshell.sh
#   3) expected, within a few seconds:
#      in /tmp/a:  T1505.003 — shell spawned by a web server ... from a WebshellLike
#                  request (GET /uploads/c99.php param=cmd, ...)
#                  and T1059 from the web-server-spawns-shell rule (lineage)
#      in /tmp/e:  four http_request events, one per signature (sql_injection,
#                  path_traversal, webshell_like, scanner_user_agent), the evidence value
#                  cut but not yet credential-redacted (#550), no query value of any other parameter
#      after about 65 s in /tmp/e: one http_summary for the source, with the request
#                  count and the failing clients
#
# Not covered here: Apache (same format, same parser, run the same way), PHP-FPM as the
# spawning parent (the rule matches `php-fpm*` by prefix), a custom LogFormat (see the
# misparsing alert in mysql-failed-login's notes: same `LOG-SOURCE` alert).

set -euo pipefail

BASE=${1:-http://127.0.0.1}
FAKE_WEBSERVER=/tmp/nginx

command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }
curl -s -o /dev/null --max-time 3 "$BASE/" || { echo "no web server answers at $BASE" >&2; exit 1; }

cleanup() { rm -f "$FAKE_WEBSERVER"; }
trap cleanup EXIT

echo "Sending one request per signature to $BASE ..."
# SQL injection marker in a parameter value
curl -s -o /dev/null "$BASE/index.php?id=1%20union%20select%20username,password%20from%20users"
# path traversal in a parameter value
curl -s -o /dev/null "$BASE/download.php?file=../../../../etc/passwd"
# a scanner user agent
curl -s -o /dev/null -A "sqlmap/1.7.2#stable (https://sqlmap.org)" "$BASE/"
# a webshell-like request: a command in a parameter of a script under uploads/
curl -s -o /dev/null "$BASE/uploads/c99.php?cmd=id"
# an ordinary request, which must NOT produce an event (it only counts in the summary)
curl -s -o /dev/null "$BASE/index.html"

# Give the agent's one-second poll time to read the log before the shell appears, so the
# request precedes it in the correlator's window.
sleep 3

SH_TARGET=$(readlink -f /bin/sh 2>/dev/null || echo /bin/sh)
if [[ "$SH_TARGET" == *busybox* ]]; then
    cp "$BASH" "$FAKE_WEBSERVER"
else
    cp /bin/sh "$FAKE_WEBSERVER"
fi
echo "Spawning a shell from a process named 'nginx' ($FAKE_WEBSERVER) ..."
# The subshell forces the fork that `sh -c` would otherwise skip (see lineage.sh).
"$FAKE_WEBSERVER" -c '(/bin/sh -c "id >/dev/null")'

echo "done. Alerts file: T1505.003 and T1059. Events file: four http_request events now,"
echo "one http_summary after about a minute."
