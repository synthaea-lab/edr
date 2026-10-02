# ADR-0014: Self-protection vs. hiding — which malware-style techniques we adopt

- **Status**: accepted
- **Date**: 2026-09-18

## Context

Issue #104 asked a focused question: adversaries routinely try to kill or blind the
endpoint agent as step one of an intrusion, and malware has a well-catalogued set of
persistence/self-protection/anti-tamper techniques for surviving removal. Some of those
same technique *classes* are legitimate for a consented, admin-installed security agent
to use on itself. Some cross into rootkit territory — hiding from the very operator who
installed the agent — and must be refused regardless of how effective they'd be.

This ADR is the record of that line, decided *after* shipping the concrete
self-protection work the survey needed to be grounded in rather than speculative:
`tamper` (heartbeat, integrity primitives), watchdog install-surface hardening and
binary pinning (#103), and the agent's sensor-silence detection, protected-resource
monitoring, and kill-loudness (#71). `docs/architecture/threat-model.md` is the living
document for *how* each shipped control works; this ADR is *why* each technique class
was in or out of scope in the first place, so the answer is on record rather than
implied by what happened to get built.

The trust boundary from the threat model applies here unchanged: we design for an
adversary with administrator/root but not ring-0. A kernel-mode adversary defeats any
user-mode control, ours included — that ceiling is named, not hidden, and only moves
with the kernel-floor milestones (#39 Windows driver/PPL/ELAM, #91 Linux BPF-LSM, macOS
System Extensions).

## Decision

Five technique classes, each classified **adopt / reject / defer**, mapped to
MITRE ATT&CK where a mapping exists:

### 1. Persistence redundancy (T1547, T1543) — **Adopt**

Multiple independent restart anchors, so removing one doesn't disable protection.
Already shipped and load-bearing: the agent and watchdog mutually supervise each other
(`PR_SET_PDEATHSIG`, #216) *and* the OS service manager restarts the watchdog
independently (`systemd Restart=always` / SCM `sc failure` / launchd `KeepAlive`) — two
layers, neither a single point of failure. The line that keeps this out of malware
territory: every restart anchor is a **declared, admin-visible service unit**, not a
hidden scheduled task or registry run key planted without the operator's knowledge.
`systemctl status`/`sc query`/`launchctl list` shows exactly what's supervising what.

### 2. Process/service protection (PPL, ES system extension, hardened unit) — **Adopt**

Overlaps tamper resistance directly. Already shipped on Linux: `watchdog::tamper`
(#103) refuses to install into a world-writable directory, hardens the installed
binaries'/unit file's permissions, hash-pins the running agent binary and re-verifies it
every supervise-loop tick, and detects service-definition drift (content or
enabled-state) against a snapshot taken at install time. Windows PPL and the macOS
System Extension equivalents are **the same decision, deferred on implementation**
(they need the kernel-floor milestone #39, not a different verdict) — adopted in
principle now, shipped per-platform as each milestone lands.

### 3. Watchdog mutual-guard — **Adopt, conditioned on staying observable**

A pattern shared with malware "guardian" threads: two cooperating processes that
restart each other. The technique itself is neutral; what makes it legitimate here is
that every restart is **logged, not concealed** — the watchdog's supervise loop prints
and records every exit/respawn cycle, backoff decisions are visible
(`ExitClass::FastCrash` vs. `Healthy`), and #71's kill-loudness now additionally
attributes *who* triggered a termination attempt before the process dies. A guardian
pattern that hid its own restarts from the process list or system logs would fail this
condition and move to reject — we did not build one.

### 4. Anti-tamper hooks / self-defense drivers — **Defer**

Kernel callbacks blocking `OpenProcess`/kill on the agent is powerful and legitimate in
principle (this is exactly what Windows PPL *is* — a kernel-enforced "you cannot
terminate this, but it is still fully visible in Task Manager" guarantee, not
concealment). It is high-privilege, high-risk to get wrong, and explicitly the
kernel-floor milestone's job (#39), not something to bolt on ad hoc from user mode.
Deferred, not rejected: the goal (prevent, don't just detect) is accepted; the
implementation waits for the milestone built to do it safely.

### 5. Hiding from enumeration (hooking, DKOM, unlinking from the process list, hidden
files, rootkit techniques) — **Reject**

Rejected outright, independent of effectiveness. A defensive agent must stay visible
and auditable to the machine owner: hiding from the operator is indistinguishable from
malware, breaks the trust the whole product depends on, trips other AV/EDR heuristics
(which correctly flag hiding behavior regardless of intent), and defeats incident
response — a responder who cannot see the agent cannot reason about the box it's
running on. Explicitly out of scope for the same reason: evasion of other security
products, detection-avoidance, or anything that makes the agent's presence deniable to
the machine owner. Every self-protection control shipped so far (#71, #103) makes a
tampering *attempt* loud and attributable; none of them make the *agent* harder to see.

## Consequences

- **What becomes easier:** the line is decidable per-technique going forward without
  relitigating first principles — "does this make an attack on the agent loud, or does
  it make the agent quiet" answers most future proposals. Persistence redundancy,
  process protection, and mutual-guarding are pre-approved patterns; anything that
  reduces the agent's visibility to its own operator is pre-rejected.
- **What becomes harder:** we accept a real ceiling — a same-privilege adversary can
  still momentarily kill or suspend the agent (the kill-both-fast race in
  `threat-model.md`), and we deliberately do not close that gap with concealment. The
  bet is that attribution + fleet visibility is the correct trade against a same-tier
  adversary, and that only ring-0 (#39, #91) legitimately closes the rest.
- **What we committed to:** every future self-protection proposal gets checked against
  this ADR before it ships, not just against "does it work." Concrete adopt items are
  linked here rather than re-surveyed: persistence redundancy and the watchdog
  mutual-guard (#216, #102), process/service protection and tamper resistance (#103),
  sensor-silence/protected-resource/kill-loudness (#71). Anti-tamper hooks stay tracked
  under the kernel-floor milestone (#39) rather than getting their own issue.

## Amendment 2026-10-01: the service's privilege model (#559)

Technique class 2 (process/service protection) names the hardened unit as adopted, but
the unit never said what the service is allowed to do. Starting the packaged unit on a
real host (Fedora 41, kernel 6.17.7, SELinux Enforcing) showed the gap: it ran the agent
as the unprivileged `synthaea` user with `NoNewPrivileges=true` and no capabilities, so
the eBPF sensor could not load and the audit fallback failed with `EPERM`.

**Decision: an unprivileged `synthaea` user plus an explicit ambient capability set, not
root with the hardening options kept.** The agent's own preflight already expects this
("capability-scoped deployment"), it keeps `NoNewPrivileges` and `ProtectSystem=strict`
meaningful, and it means a bug in a sensor or in event parsing is not a root bug. The
cost is that every privileged feature must be listed, which is the point: the list is
reviewable in one place, the unit.

The set is `AmbientCapabilities` equal to `CapabilityBoundingSet`, so nothing outside it
can be regained and the agent child the watchdog spawns inherits it across `exec`:

| Capability | Why | Status |
|---|---|---|
| `CAP_BPF`, `CAP_PERFMON` | load eBPF programs, attach tracepoints and the BPF-LSM hook | verified on a real host |
| `CAP_SYS_RESOURCE` | raise `RLIMIT_MEMLOCK` for the BPF maps | verified on a real host |
| `CAP_DAC_READ_SEARCH` | read `/proc/<pid>/*` and files owned by other users | verified on a real host |
| `CAP_NET_ADMIN` | conntrack netlink (network flows); without it the poll fails with `NLMSG_ERROR` | verified on a real host: no `NLMSG_ERROR` with it |
| `CAP_KILL` | signal other users' processes for the response action (off by default) | from the kernel's rule for `kill(2)`, not exercised on a host |

Not granted, on purpose: `CAP_SYS_PTRACE` (`/proc/<pid>/exe` of other users),
`CAP_CHOWN`/`CAP_FOWNER`/`CAP_DAC_OVERRIDE` (quarantining files the agent does not own)
and the audit capabilities (the audit fallback sensor). Each is added in its own change,
with the feature that needs it checked on a real host, so that the table above only ever
lists a capability with a reason. Until then the corresponding feature fails closed
(a logged, per-event failure), it does not silently run as root.

The sensor pins its tamper map under `/sys/fs/bpf/synthaea`; the directory is created
owned by `synthaea` through tmpfiles and made writable to the unit with
`ReadWritePaths`. The development-mode unit that `watchdog install` writes when no
package unit exists keeps `User=root`: it is a manual-install convenience, not the
shipped deployment, and the packaged unit is the one this decision binds.

This does not move the trust boundary: an adversary with root can still edit the unit.
What it changes is how much an adversary who only compromises the agent process obtains.

### Amendment (#594): the unit must see the host's `/tmp` and `/home`

Events carry host paths and the agent acts on them by path: YARA scans the file, the
enrich worker hashes it, quarantine moves it. The unit shipped with `PrivateTmp=true`
and `ProtectHome=true`, so the agent had its own empty `/tmp` and `/var/tmp` and no
`/home` at all. Measured under systemd as an unprivileged user holding
`CAP_DAC_READ_SEARCH`, reading a `0600` file written by another user:

| Sandbox | `/tmp`, `/var/tmp` | `/home` |
|---|---|---|
| `PrivateTmp=true`, `ProtectHome=true` (as shipped) | not found | not found |
| `PrivateTmp=false`, `ProtectHome=true` | read | not found |
| `PrivateTmp=false`, `ProtectHome=read-only` | read | read |

**Decision: `PrivateTmp=false` and `ProtectHome=read-only`.** Hashing and YARA are the
detection path, and for an EDR a payload dropped in `/tmp` or a home directory is the
common case, so being blind there is not an acceptable hardening trade. `ProtectSystem=strict`,
`NoNewPrivileges` and the capability set are unchanged: reading needs no capability beyond
`CAP_DAC_READ_SEARCH`, which is already granted.

Quarantine is a different case and stays opt-in. Moving a file out of another user's
directory needs `CAP_DAC_OVERRIDE` and `CAP_FOWNER` (without them the move fails even
with no sandbox at all) and a writable source directory, so `ReadWritePaths=/tmp
/var/tmp /home` and `ProtectHome=no`. Together that is close to running as root, which
is what the previous amendment avoided, for a feature that is off by default
(`--enable-quarantine`). The shipped unit therefore does not grant it; the drop-in that
does is documented in `docs/operations/response.md`, and measured with the same probe
(read and move both succeed with those capabilities and paths). Until a host opts in,
quarantine fails closed with a logged per-event failure.

What this gives up: the agent no longer has a private `/tmp`, so a local user can plant
or race files in the agent's own temporary directory. The agent keeps its state in
`/var/lib/synthaea` and `/run/synthaea` (both `ReadWritePaths`), not in `/tmp`.
