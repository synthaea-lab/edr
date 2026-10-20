#!/usr/bin/env bash
# Validation scenario for DNS tunnelling / exfiltration over DNS (T1048.003/T1071.004).
#
# Simulates a process that, within one correlation window (60s), issues many DNS
# queries under a single parent domain where each leftmost label is a long,
# high-entropy chunk — the shape produced by iodine / dnscat2 / DNSExfiltrator when
# they encode data into subdomains. Exercises the correlator's rule_dns_exfil
# (crates/correlator).
#
# Telemetry note: on Windows this reaches the ETW DNS-Client sensor (EID 3008).
# On Linux it reaches the `getaddrinfo(3)` uprobe (issue #267 Phase 1, #397,
# merged 2026-09-24), glibc-only, pid-attributed to whoever calls it — see why
# that dictates the single Python process below, not a shell loop over a CLI
# tool.
#
# Usage:
#   1) host with agent running:  agent run --enable-dns-capture (Linux) / agent run (Windows)
#   2) this box:                 ./lab/scenarios/dns-exfil.sh [PARENT_DOMAIN]
#   3) expected in the agent output:
#      T1048.003/T1071.004 — pid=... comm=...: N distinct high-entropy subdomains
#      of <parent> within the window — suspected DNS tunnelling / exfiltration

set -euo pipefail

PARENT="${1:-tunnel.example.invalid}"   # .invalid: never resolves, never leaves the resolver
QUERIES=16

# One Python process issues every query, for two independent reasons, both
# confirmed live (fedora-lab, 2026-10-20):
#
# 1. `rule_dns_exfil` aggregates per (pid, generation) (`events_for_pid` in
#    `crates/correlator/src/rules.rs`). The previous version of this script
#    forked a fresh `dig`/`nslookup`/`getent` per query — 16 different pids,
#    each with exactly one query, never enough for the rule's
#    `DNS_TUNNEL_MIN_QUERIES` (10) to be reached under any single pid. One
#    process making all the calls is what the rule can actually see as one
#    entity.
# 2. Separately, none of `dig`, `nslookup`, `getent hosts` call glibc's public
#    `getaddrinfo(3)` at all: `dig`/`nslookup` build and parse DNS packets
#    themselves, and `getent hosts` resolves through `gethostbyname2_r`, a
#    different NSS entry point. The uprobe is attached to the `getaddrinfo`
#    symbol specifically (`sensor-linux-uprobes`), so it sees none of their
#    traffic regardless of process layout — confirmed by capturing zero
#    `DnsQuery` events from either across repeated runs, versus one per call
#    from `python3 -c 'socket.getaddrinfo(...)'`, which CPython implements by
#    calling that same libc symbol.
#
# `python3` is assumed present — every current lab image has it.
python3 - "$PARENT" "$QUERIES" <<'PYEOF'
import random
import socket
import string
import sys
import time

parent, queries = sys.argv[1], int(sys.argv[2])
print(f"Sending {queries} encoded-subdomain queries under .{parent} ...")
for i in range(1, queries + 1):
    label = "".join(random.choices(string.ascii_lowercase + "234567", k=36))
    name = f"{label}.{parent}"
    try:
        socket.getaddrinfo(name, None)
    except OSError:
        pass  # NXDOMAIN / unreachable resolver — expected for .invalid
    print(f"  q{i}: {name}")
    time.sleep(0.3)
PYEOF

echo "Done. Check for the T1048.003/T1071.004 alert in the agent output."
