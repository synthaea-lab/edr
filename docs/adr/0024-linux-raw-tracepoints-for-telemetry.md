# ADR-0024: Linux event collection uses raw tracepoints

- **Status**: accepted
- **Date**: 2026-10-02

## Context

Issue #643 reports that the Linux agent crash-loops on Debian when
`kernel.perf_event_paranoid=3`. Aya's regular tracepoint attachment uses the
perf-event API, which this setting denies to the service even when it has
`CAP_BPF` and `CAP_PERFMON`. Lowering the sysctl would change host-wide policy;
granting `CAP_SYS_ADMIN` would broaden the service's privilege substantially.

The primary Linux sensor currently collects scheduler lineage/exec events and
syscall events through regular tracepoints. Scheduler event records can vary by
kernel, and the syscall event handlers already depend on the regular
`sys_enter_*` record layout.

## Decision

- Attach the primary sensor's scheduler and syscall hooks as raw tracepoints.
  Keep one raw `sys_enter` dispatcher and one raw `sys_exit` dispatcher for the
  existing syscall handlers, instead of attaching a perf event for each syscall.
- Read scheduler fields (`task_struct.pid`, `task_struct.comm`, and
  `linux_binprm.filename`) and syscall argument register offsets from the
  running kernel's `/sys/kernel/btf/vmlinux`. Do not freeze kernel structure
  offsets in the eBPF object.
- Reconstruct the regular syscall tracepoint record in the raw syscall router
  and pass it to the existing event handlers, preserving their event parsing
  and filtering behavior.
- Keep the service's existing BPF capability model. This change removes the
  dependency on `perf_event_open` and does not lower `perf_event_paranoid`.

## Consequences

- The primary sensor can attach its scheduler and syscall telemetry while
  `perf_event_paranoid` remains at 3.
- A usable kernel BTF file with the required structure members is now required
  to load the primary sensor; startup reports an explicit error when those
  members cannot be read.
- The dispatcher must keep its syscall-ID table aligned with each supported
  Linux syscall ABI. Regression tests cover that table and the BTF parser.
- This decision covers the primary scheduler and syscall sensor. The separate
  optional uprobe sensor keeps its existing attachment path.
