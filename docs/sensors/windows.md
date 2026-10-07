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
never as a new process. Unlike Linux, the value survives an agent restart. The lab check
(force a pid to repeat with a loop of short-lived processes and confirm the stamp
changes) is still open.
