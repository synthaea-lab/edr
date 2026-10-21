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

The kernel minifilter reports file **delete and rename requests that succeeded** through its
private Filter Manager port. A delete is reported when it is *requested and accepted*, not
when the file is finally removed: a disposition delete or a `FILE_DELETE_ON_CLOSE` open takes
effect at the last handle close, and a later `FileDispositionInformation(DeleteFile = FALSE)`
can still cancel it, or a delete of a non-empty directory can still fail at cleanup. The name
is the normalized name at the time of the request, which can differ from the final one. This
is the "intent that succeeded" level of Linux's `unlink(2)` tracepoint; reporting the actual
removal from cleanup is a possible follow-up. Renames are reported for `FileRenameInformation`
and `FileRenameInformationEx` and for their `...BypassAccessCheck` classes (kernel callers such
as the SMB server, so renames over a share are seen). Hard links (`FileLinkInformation*`) are
not reported: creating a name is neither a delete nor a rename.

A create that only redirects (`STATUS_REPARSE`, for example through a junction) is not an
operation: the re-issued create on the resolved path is the one that is reported.

Protocol version 3 adds `dropped_capture_failed`, a cumulative counter for successful
operations whose source or destination name could not be captured. The driver defers both
capture-failure and queue-full accounting until the post-op confirms that the operation
succeeded, so failed file operations do not inflate loss counts; nothing is counted while the
instance is draining or the driver is unloading, and an operation that completes after the
agent went away counts as `not_connected`. A set-information request that is not a delete or a
rename never moves a counter. A heartbeat the sender cannot send is not a loss: it moves no
counter and its sequence number is taken back, so the agent sees no gap. The packed event
header is 72 bytes: v2 bytes 0-63 are unchanged, `dropped_capture_failed` is a little-endian
`u64` at offset 64, and UTF-16 path payloads start at offset 72. The v3 decoder in the agent
(#853) must preserve this counter.

The driver and the agent client share the protocol version, and this change moves the client's
connection constant to 3 together with the driver, so it must land **before** the receive loop
(#853): until then the agent connects but does not read the events, the queue fills and the
loss is counted. The driver is not compiled by CI (no WDK on the runners): a change here is
checked by the author's WDK build and the lab run.

**Pool compatibility:** the driver uses `ExAllocatePoolZero` with the WDK's
`POOL_ZERO_DOWN_LEVEL_SUPPORT` path and initializes that path in `DriverEntry`. This avoids a
direct `ExAllocatePool2` import on Windows 10 before version 2004 and on Windows Server 2016/2019.
The WDK build checks the binary; actual loading and event delivery on those older systems still
need a VM run.
