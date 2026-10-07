# YARA

File and memory scanning: engine choice (YARA-X), scan triggers, performance budget, and
how matches feed the correlator.

## Process-memory scanning (Linux)

File scans cannot see a payload that only ever exists in memory: a `memfd` exec, reflectively
loaded shellcode. A **memory scan** reads one process's executable, file-less memory regions
and runs the same `rules/yara` set over them (decision record: ADR-0023).

- **Trigger, never a sweep.** A scan is requested by a detection about that process. Today
  that is the memfd-exec rule (T1620); other injection signals join as their telemetry lands.
- **What is read.** Regions that are readable and executable and that no file backs: anonymous,
  `memfd`, and deleted-file mappings. Writable-and-executable memory first, then `memfd` and
  deleted mappings, then plain executable anonymous memory. File-backed mappings (the file scan
  owns those), data regions and `[stack]`/`[vdso]` are not read.
- **Budget** (hard caps, every skip counted): 16 regions, 16 MiB per region and 64 MiB per scan;
  one scan per process incarnation (`pid` + generation) per 5 minutes; 6 scans per minute across
  the host; a queue of 16. A request shed by any of these is counted by reason
  (`queue_full`, `cooldown`, `rate`) and never blocks the event path.
- **Output.** A match writes a `YARA-MEM` alert (`yara rule X matched in the memory of pid N`),
  is fused into the verdict of the process that was scanned (so it dedups against rule and Sigma
  findings and can escalate like a file match), and quarantines nothing: there is no file to move.

### The ptrace right

Reading another process's memory (`/proc/<pid>/mem`) needs `CAP_SYS_PTRACE`, or the target to be
the agent's own uid. The shipped unit does **not** grant it: it lets the agent read and write the
memory of any process, which is close to root (ADR-0014, ADR-0023). Without it the agent scans
only processes of its own uid, and a scan of any other process fails closed and is counted as
`unreadable`. A host that accepts the trade can opt in with a drop-in
(`systemctl edit synthaea-agent`):

```ini
[Service]
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE CAP_DAC_READ_SEARCH CAP_NET_ADMIN CAP_KILL CAP_SYS_PTRACE
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE CAP_DAC_READ_SEARCH CAP_NET_ADMIN CAP_KILL CAP_SYS_PTRACE
```

`kernel.yama.ptrace_scope` can restrict `/proc/<pid>/mem` further; `CAP_SYS_PTRACE` overrides it.
Windows and macOS have no memory scanner yet (they need a driver or `task_for_pid`, #39 and #32).
