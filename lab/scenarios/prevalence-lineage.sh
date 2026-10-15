#!/usr/bin/env bash
# Fleet-prevalence scenario (issue #76, box 1): a detection whose exec event carries a
# parent -> child transition that is rare or shared on purpose.
#
# Same shape as lineage.sh (a process named "nginx" spawns a shell, so the T1059
# `check_web_server_spawns_shell` rule fires on the child's exec), but the fake web server
# lives in a directory named by TAG. The Linux sensor resolves `parent_image_path`, so the
# server records the transition `/tmp/prevalence-<TAG>/nginx -> <shell image>` as a
# prevalence key. Two hosts running the same TAG share that key; a TAG run on one host is
# "seen on 1 host" and nothing else. Without a unique directory the key would be
# `/tmp/nginx -> ...` on every host and the scenario could not tell hosts apart.
#
# Usage (agent enrolled and uploading: `agent run --server ...`, not --standalone):
#   host A:  TAG=shared  ./lab/scenarios/prevalence-lineage.sh
#   host B:  TAG=shared  ./lab/scenarios/prevalence-lineage.sh
#   host A:  TAG=only-a  ./lab/scenarios/prevalence-lineage.sh
#   then, on the control plane, run the grouping cron and read each case:
#     expected: the `shared` case shows "seen on 2 hosts, first <date>" and the `only-a`
#     case shows "seen on 1 host, first <date>" on its transition line
#     (`server/lib/prevalence.ts` triageLines; the line counts the detection's own event).
#
# A host that never uploads, or a build without `parent_image_path` (#768), yields the
# T1059 alert but no transition key: the triage line is then absent, which is a failure
# of this scenario, not a quiet result.

set -euo pipefail

TAG="${TAG:?set TAG, e.g. TAG=shared}"
case "$TAG" in *[!A-Za-z0-9_-]*) echo "TAG must be [A-Za-z0-9_-]+" >&2; exit 2 ;; esac
DIR="/tmp/prevalence-$TAG"
FAKE_WEBSERVER="$DIR/nginx"
ITERATIONS=3

mkdir -p "$DIR"
trap 'rm -rf "$DIR"' EXIT

# See lineage.sh: busybox dispatches on argv[0], so use bash there; the explicit subshell
# forces the fork that a tail-called `-c` would skip.
SH_TARGET=$(readlink -f /bin/sh 2>/dev/null || echo /bin/sh)
if [[ "$SH_TARGET" == *busybox* ]]; then
    cp "$BASH" "$FAKE_WEBSERVER"
else
    cp /bin/sh "$FAKE_WEBSERVER"
fi
INNER_CMD='(/bin/sh -c "id >/dev/null")'

echo "TAG=$TAG: spawning $ITERATIONS shells from $FAKE_WEBSERVER..."
for i in $(seq 1 "$ITERATIONS"); do
    "$FAKE_WEBSERVER" -c "$INNER_CMD"
    echo "  iteration $i done"
    sleep 1
done

echo "Done. Expect $ITERATIONS T1059 alerts in the agent; the prevalence key is"
echo "'$FAKE_WEBSERVER -> <shell image>'."
