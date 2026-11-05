# Windows Sensor

ETW providers used, session management, event normalization, and the path to a kernel
driver (inline prevention, PPL/ELAM).

## Containers (#371)

Windows containers come in three shapes, and each is covered from a different place:

| Shape | Kernel | Where the agent runs | What the host agent sees |
|---|---|---|---|
| Process-isolated (server silo) | the host's | on the host | every process in it, with `EventMeta::container` |
| Hyper-V-isolated | its own, in a utility VM | inside the container | the utility VM's host process only: the VM boundary is by design |
| WSL2, Docker Desktop's Linux engine | Linux, in a VM | the Linux agent inside the distribution | `vmmem`/`wslhost` and their network traffic, not the Linux processes |

Process isolation is not a server-only feature: Windows 10 1809 and later run
process-isolated containers too, when the image's build matches the host's.

**How a process is attributed** (`crates/sensors/windows/etw/src/silo.rs`):

1. At `ProcessStart` the sensor reads the process's `ServerSiloId`
   (`NtQueryInformationProcess`, `ProcessMembershipInformation`, documented in
   ntddk.h). 0 is the host. A process already gone by then (a one-command
   `cmd /c`) takes its parent's silo: a child is created in its parent's silo and
   cannot leave it.
2. The silo is named by the Host Compute Service: a background thread lists the
   containers (`HcsEnumerateComputeSystems`), reads each one's process list, and
   matches a listed process to the silo it runs in (checking its image name, so a
   Hyper-V container's own pids cannot claim a host process). The id is the HCS
   compute-system id, the same 64-hex id Docker and containerd use, as on Linux.
3. Until that answer arrives (the first processes of a starting container), the
   id is `silo:<n>`: the event still says "containerized". A silo created or torn
   down (Kernel-Process EIDs 23-26) forgets its mapping, since silo ids are reused.

Limits: `ProcessMembershipInformation` exists from Windows 11 22H2 / Server 2025;
on Server 2022 and older every process stays `None` (the query is tried once).
Only the ETW sensor attributes containers; the Event Log and socket snapshot
sensors keep `container: None`. `image` and `name` stay `None`, as on Linux, until
a runtime lookup lands. `computecore.dll` is loaded only once a process is seen in
a silo, from System32.

**Container-aware rules.** The Linux rule that keys on container context,
`check_proc_root_escape` (T1611: a containerized process opening
`/proc/<pid>/root`), has no Windows sibling, by assessment rather than omission:
there is no procfs, so the path never matches a Windows event, and the attribution
cannot make it fire. The Windows escape of record, Siloscape (Unit 42, 2021),
impersonates the container's `CExecSvc` and links the host volume into the
container's object namespace with `NtSetInformationSymbolicLink`. This sensor sees
neither the object-manager link nor which volume a container process's file
events land on. A sibling needs one of the two: the container's own volume per
silo (so a containerized write to a host volume is the signal), or
symbolic-link telemetry from the driver work (#136, #39).

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

Protocol version 3 added `dropped_capture_failed`, a cumulative counter for successful
operations whose file source/destination name or volume name could not be captured. The driver defers both
capture-failure and queue-full accounting until the post-op confirms that the operation
succeeded, so failed file operations do not inflate those two loss counts. `not_connected`
is different: while already disconnected, the pre-op counts a qualifying volume-open, delete, rename or timestamp-set
*attempt* before its result is known. Failed or reparsed attempts can therefore increase it;
each invocation of a re-issued create's pre-op may be counted. It is an upper bound on lost
events, not an exact number of successful operations. Nothing is counted while the instance is
draining or the driver is unloading; an operation that completes after the agent went away also
counts as `not_connected`. A set-information request that is not a delete, rename or explicit timestamp set never moves a
counter. A heartbeat the sender cannot send is not a loss: it moves no
counter and its sequence number is taken back, so the agent sees no gap. Protocol v4 extends
the legacy 72-byte header with four signed 64-bit requested `FILE_BASIC_INFORMATION` times at
offsets 72, 80, 88 and 96 (creation, last access, last write, change). The complete v4 header is
104 bytes and UTF-16 path payloads start there. The decoder rejects timestamp values on other
event kinds and rejects a set-time record with no requested time. Protocol v5 appends a 32-bit
requested `ACCESS_MASK` at bytes 104–107; the complete header is 108 bytes. Kind 4 reports a
successful mounted-volume open (`FO_VOLUME_OPEN`), with the kernel volume name in the old-path
slot and no new path or timestamp values. The mask is requested, not granted access. Physical
disk handles that bypass the filesystem are out of scope.

Queued records survive a client disconnect, subject to the 8,192-record and 16 MiB queue
limits. A reconnect can therefore receive older records: their timestamps were captured with
the file operation, while their sequence numbers are assigned only when sent on the new
connection. Consumers that use time windows must use the event timestamp, not the receive
time.

The driver and agent client share the protocol version, so protocol changes must update both
sides together. The driver is not compiled by CI (no WDK on the runners): a change here is
checked by the author's WDK build and a lab run.

**Pool compatibility:** the driver uses `ExAllocatePoolZero` with the WDK's
`POOL_ZERO_DOWN_LEVEL_SUPPORT` path and initializes that path in `DriverEntry`. This avoids a
direct `ExAllocatePool2` import on Windows 10 before version 2004 and on Windows Server 2016/2019.
The WDK build checks the binary; actual loading and event delivery on those older systems still
need a VM run.
