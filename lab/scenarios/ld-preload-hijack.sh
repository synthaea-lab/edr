#!/usr/bin/env bash
# Dynamic linker hijack scenario (T1574.006, issue #363/#401).
#
# check_ld_preload_hijack (crates/rules/src/stateless.rs) fires when an ExecEvent's
# captured LD_PRELOAD/LD_AUDIT value (issue #363: parse_proc_environ_security reads
# /proc/<pid>/environ for a fixed allowlist — presence only, never the full
# environment) points outside the dynamic linker's own trust set. That trust set
# (crates/rules/src/ld_trust.rs) is two layers, not just LD_TRUST_PREFIXES: the
# built-in baseline (/lib, /lib64, /usr/lib, /usr/lib64, /usr/local/lib) plus
# whatever /etc/ld.so.conf (and its `include`s) declares on the host — except
# /tmp, /var/tmp, and /dev/shm, which are never trusted even if ld.so.conf lists
# them. This scenario is that shape with no payload beyond proving the hook
# actually loaded: the "hijack" library's constructor writes one line to a file
# and does nothing else — no hooked libc symbols, no hiding, no backdoor. What a
# real LD_PRELOAD rootkit (Azazel, Jynx2, vlany, ...) does with that same
# loaded-constructor moment is out of scope here by design; this scenario asserts
# the detection surface, not a live implant.
#
# Usage:
#   1) terminal A: sudo target/release/agent run
#   2) terminal B: ./lab/scenarios/ld-preload-hijack.sh
#   3) expected in terminal A:
#      T1574.006 — pid=...: LD_PRELOAD=/tmp/edr-test-preload.so loads a shared
#      object outside the dynamic linker's trusted search path

set -euo pipefail

SRC=/tmp/edr-test-preload.c
LIB=/tmp/edr-test-preload.so
MARKER=/tmp/edr-test-preload.marker

cleanup() { rm -f "$SRC" "$LIB" "$MARKER"; }
trap cleanup EXIT

command -v cc >/dev/null 2>&1 || {
    echo "cc not found — install a C compiler (Alpine: apk add build-base; Debian: apt install build-essential) and retry." >&2
    exit 1
}

cat > "$SRC" <<'C'
/* Proves the LD_PRELOAD constructor ran — nothing else. No hooked symbols,
 * no process/file/network hiding, no backdoor. */
#include <stdio.h>
__attribute__((constructor))
static void mark_loaded(void) {
    FILE *f = fopen("/tmp/edr-test-preload.marker", "w");
    if (f) {
        fputs("loaded\n", f);
        fclose(f);
    }
}
C

echo "Compiling the benign preload library ($LIB, outside the linker trust set)..."
cc -fPIC -shared -o "$LIB" "$SRC"

echo "Running 'sleep' with LD_PRELOAD=$LIB (untrusted path)..."
# env_security (the captured LD_PRELOAD value) is read from /proc/<pid>/environ at
# drain time, same path as the argv read — a short-lived process can exit before
# the drain runs, leaving env_security empty and no alert (argv.sh hit this on 6.1
# under load, see argv.yaml's notes). `sleep 0.3` stays alive long enough, and it's
# a single exec: a `sh -c '...; sleep'` wrapper would put LD_PRELOAD on two execs
# (sh, and the child that inherits it), so the alert count would be 1 or 2
# depending on which ones the drain catches (#419 review).
LD_PRELOAD="$LIB" sleep 0.3

if [ -f "$MARKER" ]; then
    echo "Constructor ran (marker file present) — the preload actually loaded."
else
    echo "WARNING: marker file missing — the preload may not have loaded." >&2
fi

echo "Done. Check the agent terminal for the T1574.006 alert."
