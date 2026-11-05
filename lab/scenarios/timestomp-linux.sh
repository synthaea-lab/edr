#!/usr/bin/env bash
# Linux timestomp validation scenario (T1070.006, #1036/#1044).
#
# Sets file times explicitly three ways (what `inode_setattr` sees as ATTR_*_SET), then does
# three things that touch a file's attributes without choosing a time (a write, a plain
# `touch`, a chmod): those must stay silent.
#
# Usage:
#   1) terminal A: sudo target/release/agent run   (needs bpf in the active lsm= list)
#   2) terminal B: ./lab/scenarios/timestomp-linux.sh
#   3) expected in terminal A: three T1070.006 alerts (touch -d, python utime, touch -m -d),
#      none for the write, the plain touch and the chmod.

set -euo pipefail

DIR=$(mktemp -d "${HOME}/timestomp-XXXXXX")
trap 'rm -rf "$DIR"' EXIT
mkdir -p "$DIR/sub/deeper"
F="$DIR/sub/deeper/stomp.txt"
echo x > "$F"
echo y > "$DIR/sub/direct.txt"

# Explicit times: must report.
touch -d "2010-01-01 00:00:00" "$F"
python3 -c 'import os,sys; os.utime(sys.argv[1], (1262304000, 1262304000))' "$F"
touch -m -d "2011-02-03 04:05:06" "$DIR/sub/direct.txt"

# No time chosen: must stay silent.
echo more >> "$F"   # a write: the kernel sets the mtime
touch "$F"          # UTIME_NOW
chmod 600 "$F"      # not a time change
sleep 2
