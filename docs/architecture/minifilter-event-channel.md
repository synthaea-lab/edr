# Minifilter event channel (milestone 2c, #136)

Status: **draft for review**. Design of the first milestone where
`SynthaeaFilter` sends events to the agent. Builds on #508 (skeleton), #560
(port, agent-only) and #565 (user-mode client). The binding rules are
[ADR-0012](../adr/0012-windows-driver-framework-language-choice.md)'s
guardrails; this document says how 2c meets each one.

## Scope

**In:** file **deletes** and **renames**, the two events ETW doesn't give us
(audit F-6) and the earliest ransomware signal (#82: mass rename/delete
bursts). They map onto the existing `Event::FileDelete` / `Event::FileRename`
(#262), so **no schema change**: Windows starts filling variants Linux and
macOS already emit, and the cross-platform rules apply unchanged.

**Out, later milestones of #136:** ADS, timestomping (`SetInformation` on
`FileBasicInformation`), raw-volume access, named pipes. Also out: any
filtering or detection in the kernel (guardrail 1).

## Kernel side

### What is captured

| Operation | Callback | Emitted when |
|---|---|---|
| Delete via `FileDispositionInformation(Ex)` with `DeleteFile`/`FILE_DISPOSITION_DELETE` | `IRP_MJ_SET_INFORMATION` pre + post | post-op, `NT_SUCCESS` |
| Delete via `FILE_DELETE_ON_CLOSE` at open | `IRP_MJ_CREATE` post | post-op, `NT_SUCCESS` |
| Rename via `FileRenameInformation(Ex)` | `IRP_MJ_SET_INFORMATION` pre + post | post-op, `NT_SUCCESS` |

Semantics to state honestly in the event: a successful disposition or
delete-on-close means the delete was *requested and accepted*; the file goes
away at the last handle close, and another handle can still cancel it with a
later disposition. That is the same "intent that succeeded" level as Linux's
`unlink(2)` tracepoint, and what ransomware detection needs. Tracking the
actual removal (cleanup/close on the last handle) is a possible follow-up,
not 2c.

Skipped in the callbacks, before any work: paging I/O, operations without a
file object, and **the agent's own process** (recorded in the connect
callback; its spool and `events.jsonl` churn would otherwise feed back into
the stream).

### Names

`FltGetFileNameInformation(FLT_FILE_NAME_NORMALIZED |
FLT_FILE_NAME_QUERY_DEFAULT)` is only safe at `PASSIVE_LEVEL`/`APC_LEVEL`,
and post-op callbacks can run at `DISPATCH_LEVEL`. So:

- **pre-op** (passive): query the source name and, for a rename,
  `FltGetDestinationFileNameInformation` for the target. Allocate one
  non-paged record sized to those names (`ExAllocatePool2`), fill it with
  the paths, PID/TID and a `KeQuerySystemTimePrecise` timestamp, and pass it
  as the completion context;
- **post-op**: if the operation succeeded, the completion context *is* the
  queue record: link it into the queue as is. Otherwise free it. No name
  query, no copy and no allocation in the post-op.

Paths are UTF-16 and capped at **4,096 characters** each in the record; a
longer path is truncated and flagged, never dropped silently.

### Guardrail 6: the kernel never waits on user mode

I/O threads never call `FltSendMessage`. The post-op pushes a fixed-size
record into a **bounded in-kernel queue**; a **dedicated system thread**
drains it and sends.

- **Queue:** a spin-lock–protected list of those records, capped **both** at
  8,192 records **and** at 16 MiB of queued bytes. The byte cap is the one
  that matters: two maximal paths make a record of about 16 KiB, so a
  record cap alone would allow 128 MiB of non-paged pool. Typical records
  are a few hundred bytes. Push is O(1) at `DISPATCH_LEVEL`. Over either cap
  means **drop and count**: free the record, `InterlockedIncrement64` on a
  drop counter, no wait. The pre-op also checks the caps before allocating,
  so a saturated queue doesn't keep allocating records only to free them.
- **Sender thread:** waits on a queue event, pops a record, calls
  `FltSendMessage(…, Timeout = 100 ms)` with no reply buffer. On
  `STATUS_TIMEOUT` or any error the record is dropped and counted. The
  timeout bounds how long one stuck agent read can hold the *sender*; I/O is
  never involved.
- **No client connected:** the post-op checks a connected flag first and
  doesn't queue at all; those operations are counted in a separate
  "not connected" counter so the agent can tell "dropped under load" from
  "nobody was listening".

A hung, suspended or crashed agent therefore costs the queue filling up and
the counters climbing, never a stalled `DeleteFile` on the machine.

### `ClientPort` lifetime

#560 notes the bare global is only safe while nothing reads it outside the
connect/disconnect callbacks. In 2c the sender reads it, so:

- every `FltSendMessage` runs under `ExAcquireRundownProtection` on an
  `EX_RUNDOWN_REF` tied to the connection;
- `DisconnectNotify` clears the connected flag, calls
  `ExWaitForRundownProtectionRelease` (bounded by the 100 ms send timeout),
  closes the client port, then `ExReInitializeRundownProtection` for the
  next agent.

### Unload

`SynthaeaUnload`: close the server port, then signal the sender thread to
stop, `KeWaitForSingleObject` on it, free every queued record, delete the
lookaside lists, then `FltUnregisterFilter`. The #560 lab case "unload while
the agent holds the port" becomes "unload while the agent holds the port
**and** the queue is non-empty".

## Wire format

One message per record, all integers little-endian, packed, versioned by the
existing connection-context protocol version (2c bumps it to **2**; a v1
client is refused at connect, never fed a format it can't read).

| Field | Type | Notes |
|---|---|---|
| `kind` | u16 | 1 = delete, 2 = rename |
| `flags` | u16 | bit 0: delete-on-close (vs disposition); bit 1: old path truncated; bit 2: new path truncated |
| `seq` | u64 | per-connection sequence number, starts at 1 |
| `timestamp` | i64 | `KeQuerySystemTimePrecise`, 100 ns since 1601 |
| `pid`, `tid` | u64 ×2 | from the pre-op |
| `dropped_queue_full` | u64 | cumulative, since load |
| `dropped_send_failed` | u64 | cumulative, since load |
| `not_connected` | u64 | cumulative, since load |
| `old_path_len`, `new_path_len` | u16 ×2 | in UTF-16 code units; `new_path_len = 0` for a delete |
| paths | UTF-16 | `old_path` then `new_path`, not NUL-terminated |

Carrying the counters in **every** message means the agent always has the
current loss figures without a second request path (there is still no
`MessageNotify`: user mode never sends to the driver). A gap in `seq` plus a
counter increase tells the agent exactly how many events it lost and why.

**Idle heartbeat:** when the queue has been empty for 5 s, the sender emits a
`kind = 0` message (header only). It feeds the agent's silence monitor, so a
wedged driver or sender thread becomes a T1562 silence alert like every
other sensor (#71), instead of looking like a quiet machine.

## User-mode side (`sensor-windows-minifilter`)

- A receive thread: `FilterGetMessage` into a buffer sized for the largest
  record, `CancelIoEx`-based stop. One decode per message.
- **Guardrail 7:** the decoder treats driver bytes as hostile: bounds-checked
  reads, `kind`/length validation, UTF-16 decoded lossily. It gets a
  never-panic suite in `tests/` (every truncation, every length field at
  0/max/overflowing) and a `fuzz/` target, like the other byte parsers.
- Mapping: delete → `Event::FileDelete { path }`, rename →
  `Event::FileRename { old_path, new_path }`, with `EventMeta` from pid/tid
  and the timestamp converted to UNIX ns. Device paths
  (`\Device\HarddiskVolume3\…`) must reach rules in the same drive-letter
  form the ETW sensor produces (its `normalize_nt_path` over a
  `QueryDosDeviceW` volume map). Sensor crates can't depend on each other
  (`check-deps`), so that normalization either moves somewhere both can use
  or the minifilter asks for normalized names in a form that needs none;
  see open question 5.
- The crate then depends on `schema`, which the sensor rule of
  `tools/check-deps.py` allows (guardrail 8).
- **Agent wiring:** `agent::commands::windows` owns the connection:
  connect at start, reconnect with capped backoff after `NotLoaded` or a
  disconnect (driver reload), a `windows-minifilter` heartbeat registered in
  the silence monitor and pulsed by every message including idle ones, and
  the three counters exported in the health beacon next to `spool_dropped`
  and `enrich_dropped`.

## Test plan

- **Unit/robustness:** decoder never-panic suite + fuzz target; mapping
  tests with fixture messages.
- **Lab, under Driver Verifier `/standard`**, loaded binary hash-checked with
  `install-test-build.ps1`, agent identity via `run-as-agent.ps1`:
  - a burst of 10,000 renames (`x` → `x.locked`) and 10,000 deletes: every
    one arrives, `seq` contiguous, counters at 0;
  - **suspended agent** (`NtSuspendProcess` on the probe) during the same
    burst: the burst completes at normal speed (timed against a run with
    no filter loaded), `dropped_queue_full` climbs, nothing blocks;
  - agent killed mid-burst, then restarted: reconnects, `seq` restarts at
    1, counters carried over;
  - no agent connected: no queueing, `not_connected` climbs;
  - unload during the burst with the agent connected and the queue full;
  - no bugcheck, and `verifier /query` pool counters back to their pre-load
    values after unload (no leaked records or contexts).
- **CodeQL** `recommended.qls` and `/analyze`, as for #508/#560.

## Open questions for review

1. **Queue caps (8,192 records / 16 MiB):** too big for low-memory hosts,
   too small for a build server's delete storms? They could be registry
   values read at load, with hard ceilings.
2. **Delete semantics:** is "delete accepted" enough for #82, or do we want
   the actual removal at last-handle cleanup in 2c already?
3. **Protocol bump to v2 at connect time** vs a version field per message:
   refusing at connect is simpler and fails loudly; a per-message version
   would allow mixed rollouts of driver and agent.
4. **Overlap with ETW:** the ETW sensor already reports file creates/writes.
   2c only adds kinds ETW lacks, so there's no duplicate stream today; the
   question returns when the minifilter takes over writes.
5. **Where NT-path normalization lives** for two Windows sensors: a small
   shared module (in `schema`, or a new base-tier crate `check-deps` would
   have to allow), a copy in each sensor, or the driver resolving the volume
   to a DOS name itself (`FltGetVolumeName` + `IoVolumeDeviceToDosName`,
   which has its own IRQL and cost constraints).
