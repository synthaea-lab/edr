#!/usr/bin/env bash
# MariaDB/MySQL failed-login burst (T1110, issue #478 level 2, ADR-0022).
#
# The agent tails the database's error log (a `mysql_error` source in agent.toml),
# turns each "Access denied" line into a failed-logon AuthEvent, and the existing
# brute-force rule (AUTH_FAILURE_THRESHOLD = 5 in 60 s per target user and source)
# fires. This scenario produces that burst against a real server with a made-up
# account name; it changes no data and no real account.
#
# Prerequisites (a real server, not a mock):
#   - MariaDB or MySQL listening on 127.0.0.1:3306, mariadb/mysql client installed.
#   - The error log must be a FILE. Ubuntu/Debian MariaDB logs to the journal by
#     default (`skip_log_error`) and writes no file: set `log_error` first, e.g.
#         [mysqld]
#         log_error = /var/log/mysql/error.log
#     and restart the server. MariaDB logs "Access denied" at the default
#     log_warnings = 2; MySQL 8 needs log_error_verbosity = 3.
#   - agent.toml declares it:
#         [[logs.sources]]
#         path = "/var/log/mysql/error.log"
#         kind = "mysql_error"
#   - The agent can read the file: root, or CAP_DAC_READ_SEARCH (the packaged unit
#     has it; checked with `setpriv`: an unprivileged user cannot read the 0660
#     mysql-owned log, the same user with that capability can).
#
# Usage:
#   1) terminal A: sudo target/release/agent --config /etc/synthaea/agent.toml run \
#        --alerts /tmp/a --events /tmp/e
#   2) terminal B: ./lab/scenarios/mysql-failed-login.sh
#   3) expected in /tmp/a (within a couple of seconds):
#      T1110 — target=edr_lab_victim source=local: 5 failed authentications in 60s
#
# `source=local` because MariaDB logs the client as 'localhost' (a resolved name, not
# an IP), which the rule keys as local rather than inventing a loopback address.

set -euo pipefail

CLIENT=$(command -v mariadb || command -v mysql) || { echo "no mariadb/mysql client" >&2; exit 1; }
USER_NAME=${1:-edr_lab_victim}

echo "Sending 6 failed logins as '$USER_NAME' (T1110 Brute Force)..."
for _ in 1 2 3 4 5 6; do
  "$CLIENT" -h127.0.0.1 -u"$USER_NAME" -pwrong-on-purpose -e 'select 1' >/dev/null 2>&1 || true
done
echo "done: check the agent's alerts file for T1110 on target=$USER_NAME"
