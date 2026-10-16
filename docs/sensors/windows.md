# Windows Sensor

ETW providers used, session management, event normalization, and the path to a kernel
driver (inline prevention, PPL/ELAM).

**Status (issue #725, process incarnation):** `EventMeta::process_generation` and
`parent_process_generation` (#519) carry the kernel's process sequence number, unique
per process for the boot. Exec events take both from Kernel-Process `ProcessStart` v4+
(`ProcessSequenceNumber`, `ParentProcessSequenceNumber`), so the parent's stamp is the
one the kernel recorded at that creation, not whatever holds the ppid in the pid store
by then. Processes that predate the trace (the pid-store seed, and the live fallback for
a pid seen before its exec) are read with `NtQueryInformationProcess` class 92
(`PROCESS_QUERY_LIMITED_INFORMATION` suffices). Every other event reads its pid's and
its parent's stamp from the pid store. An older `ProcessStart` version, an unreadable
process, or a 0 value leaves the stamp `None`, which consumers treat as "cannot tell",
never as a new process. Unlike Linux, the value survives an agent restart. Lab-checked on
Windows 11 25H2 (PR #728): recycled pids get a new stamp, and the ETW parent field agrees
with the class-92 query. `listen_port` (the `sockets` snapshot) and the `eventlog` sensor
do not stamp yet.

## Minifilter event channel

The kernel minifilter reports successful file deletes and renames through its private
Filter Manager port. Protocol version 3 adds `dropped_capture_failed`, a cumulative
counter for successful operations whose source or destination name could not be captured.
The driver defers both capture-failure and queue-full accounting until post-op confirms
that the filesystem operation succeeded, so failed file operations do not inflate loss
counts. The packed event header is 72 bytes: v2 bytes 0–63 are unchanged,
`dropped_capture_failed` is a little-endian `u64` at offset 64, and UTF-16 path payloads
start at offset 72. The v3 decoder in the agent must preserve and export this counter.
