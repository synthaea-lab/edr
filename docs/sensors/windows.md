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
