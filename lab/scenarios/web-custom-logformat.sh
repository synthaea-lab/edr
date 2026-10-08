#!/usr/bin/env bash
# A custom Apache LogFormat against an `access_combined` source: the misparsing alert
# (issue #478 level 2, ADR-0022).
#
# A source whose lines mostly fail to parse is reported once, as a LOG-SOURCE alert,
# instead of staying silently blind (MIN_LINES = 10 lines in a 60 s window, at least half
# rejected). This scenario points an `access_combined` source at a log written in a
# format that is NOT combined and sends enough requests to trip it.
#
# Prerequisites:
#   - Apache on 127.0.0.1:8081 (or the port given), with a vhost writing a custom log:
#         LogFormat "%t %>s %U" synthaea_custom
#         CustomLog /var/log/apache2/custom-format.log synthaea_custom
#   - agent.toml declares it as access_combined:
#         [[logs.sources]]
#         path = "/var/log/apache2/custom-format.log"
#         kind = "access_combined"
#
# Usage:
#   1) terminal A: sudo target/release/agent --config /etc/synthaea/agent.toml run \
#        --alerts /tmp/a --events /tmp/e
#   2) terminal B: ./lab/scenarios/web-custom-logformat.sh
#   3) expected in /tmp/a, once the 60 s window closes (the script waits for it):
#      LOG-SOURCE naming /var/log/apache2/custom-format.log

set -euo pipefail

BASE=${1:-http://127.0.0.1:8081}
command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }
curl -s -o /dev/null --max-time 3 "$BASE/" || { echo "no web server answers at $BASE" >&2; exit 1; }

echo "Sending 20 requests to a vhost whose log is not in combined format ..."
for i in $(seq 1 20); do curl -s -o /dev/null "$BASE/page$i"; done
echo "Waiting for the 60 s window to close ..."
sleep 65
# The window closes on the first poll after it expires; one more request makes sure there is one.
curl -s -o /dev/null "$BASE/last"
sleep 3
echo "done: check the alerts file for LOG-SOURCE."
