# ADR-0023: Process memory scanning: policy in `yara`, mechanism in a sensor, ptrace right opt-in

- **Status**: proposed
- **Date**: 2026-10-02

## Context

File scanning cannot see fileless tradecraft: a payload run from a `memfd`, reflectively
loaded shellcode, a hollowed process. #85 asks for YARA over process memory, "triggered,
budgeted like file scans, never a fleet-wide sweep". Two things make it different from a
file scan:

1. **Memory is attacker-controlled and unbounded.** A process can map gigabytes; a scan
   that is not bounded at every level is a denial-of-service on the endpoint.
2. **Reading another process's memory needs a privilege the agent does not have.**
   On Linux the mechanism is `/proc/<pid>/mem`, which is gated by `ptrace_may_access`
   (`PTRACE_MODE_ATTACH_FSCREDS`): same uid and dumpable, or `CAP_SYS_PTRACE`. The agent's
   capability set (`CAP_DAC_READ_SEARCH` among others, see ADR-0014) does not include it,
   and `CAP_DAC_READ_SEARCH` does not substitute: measured on 2026-10-02, an unprivileged
   read of `/proc/1/mem` fails with `EACCES`. `kernel.yama.ptrace_scope` can restrict it
   further. So without a new capability the agent can scan only processes of its own uid,
   which excludes exactly the root-run implants this is for.

`tools/check-deps.py` also forbids OS-specific code outside `crates/sensors/*`, and
detection crates never depend on a sensor.

## Decision

- **Policy and mechanism are split.** `crates/yara` owns *what* to read, *how much* and *how
  often* (`memory.rs`): a `MemorySource` trait, `MemoryBudget`, `scan_memory`, and a
  `MemoryScanQueue`. A Linux sensor crate implements `MemorySource` over `/proc` (a
  separate change); the agent wires the two. A `MemorySource` for Windows/macOS can follow
  without touching the policy.
- **What is read:** executable, readable regions that no file backs (anonymous, `memfd`,
  deleted-file mappings). Not file-backed mappings (the file scan owns those), not
  non-executable data, not `[stack]`/`[vdso]`. Order: writable-and-executable first (the
  strongest injection tell), then `memfd`/deleted, then plain executable anonymous memory.
- **Budgets, all hard caps and all counted:** per scan, 16 regions, 16 MiB per region,
  64 MiB in total (the file-scan cap); per process, one scan per `(pid, generation)` per
  5 minutes (a recycled pid is a new process, #590); globally, 6 scans started per minute
  and a queue of 16, with shed requests counted by reason (`queue_full`, `cooldown`,
  `rate`) and unreadable processes counted separately. A shed request never spends the
  cooldown.
- **Trigger, never a sweep:** a memory scan is requested by a detection about that
  process. First trigger: the `memfd` exec rule (T1620). Other injection signals join as
  their telemetry lands.
- **The ptrace right is opt-in, like quarantine's.** The shipped unit does not grant
  `CAP_SYS_PTRACE`: it lets the agent read and modify the memory of any process, which is
  close to root and a large step against ADR-0014's hardening for a feature that is new.
  Without it, a scan of a process the agent does not own fails closed (counted as
  `unreadable`, logged at debug) and a same-uid process is scanned normally. A host that
  wants full coverage adds the capability in a documented drop-in.

## Consequences

- The budget and trigger policy are unit-tested with a fake source on every platform and
  need no privilege; only the mechanism is OS-specific.
- On a default install, memory scanning covers only the agent's own uid until a host opts
  in, so the lab check "a marker payload present only in memory is detected" must run
  with the capability granted. **Decision for the owner:** whether to ship the capability
  in the default unit (full coverage, weaker hardening) or keep it opt-in (this ADR's
  choice, until the feature has a track record).
- `unreadable` makes the gap visible rather than silent: an operator can see how many
  triggered scans could not run for lack of the right.
- Not decided here: Windows (`ReadProcessMemory` needs PPL/driver work, #39) and macOS
  (`task_for_pid` via EndpointSecurity, #32); RWX-mapping and ptrace-write probes, which
  would add triggers.
