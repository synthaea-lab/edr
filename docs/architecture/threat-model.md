# Threat Model — EDR Self-Protection

How the agent and watchdog defend **themselves**: resisting termination, detecting when
they are blinded or frozen, protecting their own binaries/config/evidence, and making
every tampering attempt loud, attributable, and fleet-visible. This is the EDR-vs-EDR-
bypass problem — an adversary who cannot beat the detections tries to switch the sensor
off instead.

The governing principle, and the spine of this document: **an EDR that goes silent is
not the same as an endpoint that is safe. So silence is a detection.** Every path that
stops the agent, blinds a sensor, or cuts the server link ends in either an automatic
respawn or a gap that is itself alerted — locally by the watchdog/`tamper` heartbeat,
globally by the server's expected-cadence check. You cannot switch this agent off
without generating the record of having done so.

## Trust boundary and the adversary

The adversary we design for holds **administrator/root but not ring-0.** A kernel-mode
attacker defeats any user-mode EDR; that is the honest ceiling, named at each row it
touches and raised only by the kernel-floor milestones (#39 Windows driver/PPL/ELAM,
#91 Linux BPF-LSM, macOS System Extensions). Everything *above* the kernel is in scope,
and the design goal there is not "cannot be tampered with" — a same-privilege adversary
can always try — but **"cannot be tampered with silently."**

| Boundary | Trusted | Untrusted | Self-protection enforcement |
| --- | --- | --- | --- |
| Agent ↔ watchdog | mutual | — | two processes, each restores the other's role via the service manager; neither is a single point of failure |
| Runtime ↔ installed artifacts | signed `updater` manifest | live filesystem | `tamper` hash-verifies binaries + config against the manifest; only `updater` may change them |
| Agent ↔ its own resources | agent | every other process | protected-resource monitoring: any foreign writer to the agent's own files (binary, config, alerts/events/heartbeat) is a high-severity detection — `updater` never needs an exception, see PR #770 |
| Agent ↔ server | server PKI | transport | mTLS (ADR-0001); spool survives a severed link; the server flags a silent agent |

## The self-protection surface

Organized by MITRE **T1562 (Impair Defenses)** and **T1489 (Service Stop)**. Each row:
what the adversary does to the EDR, how the EDR notices, and the honest gap.

### 1. Terminating the agent or watchdog — T1489, T1562.001

| Attack on the EDR | How the EDR defends / detects | Gap |
| --- | --- | --- |
| `taskkill` / `kill -9` the agent | Watchdog respawns it (layer-1 supervision); death + respawn recorded; the kill itself is a process event attributable to the killer pid. | The kill succeeds momentarily; the defense is respawn + attribution, not prevention. Prevention needs PPL (#39). |
| Kill the watchdog | Service manager respawns it (layer 2): SCM `sc failure`, systemd `Restart=always`, launchd `KeepAlive`. | Kill both fast enough → a bounded gap, itself visible as a telemetry gap server-side. |
| Kill **both** in a tight loop | The gap is bounded by the restart interval; #101 (exponential backoff) keeps a crash-loop from becoming a self-DoS; #103 protects the on-disk artifacts a restart depends on. | A scripted race has a real window user-mode restart cannot fully close — a kernel watchdog / PPL closes it. |
| **Suspend** instead of kill (`NtSuspendProcess`) — agent alive but frozen, so no respawn fires | **Sensor-silence heartbeat** (this crate): each sensor advances a liveness counter every interval; a frozen agent stops advancing; the *watchdog*, not frozen, sees the stall and restarts (#102). | A suspend of both is the kill-both race again. |
| Crash-loop via malformed input forcing a panic | No `unwrap`/`expect` on the event path (CLAUDE.md); the crash is spooled; #101 backoff prevents the busy-spin. | A reproducible remote panic is a bug — standing mitigation is fuzzing the parsers (`schema`, `sigma`, `ml::forest`, wire crates). |

**Invariant:** neither process is a single point of failure; every termination path ends
in a respawn or a server-visible gap.

### 2. Blinding the sensors without touching the process — T1562.001, T1562.006

The subtler bypass: leave the agent *running* (no respawn, no missing-process alert) but
cut its vision. This is where the heartbeat earns its keep.

| Attack on the EDR | How the EDR defends / detects | Gap |
| --- | --- | --- |
| Stop the ETW session (`logman stop`, `NtTraceControl`) | **F-2 canary already ships:** the Windows sensor writes its own temp file every 2 s, which *must* produce a Kernel-File event; 30 s of silence despite the canary = the trace was stopped → loud sensor error → watchdog restart. Silence is deterministic even on an idle host. | Kernel-ETW stop needs admin and is loud; true kernel patching is ring-0, out of scope. |
| Detach/unload an eBPF program, or flood the ring buffer to force drops | Per-sensor heartbeat (same mechanism, generalized off Windows); ring-buffer drops are already counted (`store` eviction counters + the sensor drop counter). A detach stops the heartbeat. | Observing the *detach act* needs LSM (#91); until then we detect the *effect* (silence). |
| "ETW patching" — no-op `EtwEventWrite` inside a target to blind userland ETW consumers | We consume **kernel** ETW (Process/Network/File), not in-process provider callbacks, so in-process patching does not blind us. Patchable userland providers (AMSI/.NET, #21/#97) get a "provider went quiet" heartbeat. | Kernel ETW itself: see above. |
| **Unhook userland API hooks** (the classic commodity-EDR bypass) | We place **no userland hooks** — telemetry is kernel ETW/eBPF/ES, not inline hooks — so there is nothing to unhook. Architectural immunity, not a detection. | Trade-off: we also miss purely in-process calls that never reach the kernel; syscall sensors (#90 uprobes, #91 LSM) widen the view. |
| Direct/indirect syscalls to dodge userland instrumentation | Same immunity: kernel tracepoints fire on the syscall regardless of how userland reached it. | Real gaps here are eBPF ppid off the binding kernel (#53) and argv[0] spoofing (#111) — both tracked. |

**Invariant:** the vantage point is the kernel's own telemetry, so the whole
"unhook / patch userland ETW / direct syscall" family — the bulk of commodity EDR
evasion — is structurally weaker against this design than against a hook-based agent.
Where we *can* be blinded (stopping kernel ETW, detaching eBPF), the act produces
silence, and silence is wired to an alert. **This is the single most important
self-protection property, and the heartbeat is its enforcement.**

### 3. Tampering with integrity, persistence, config, evidence — T1562.001, T1112, T1070

| Attack on the EDR | How the EDR defends / detects | Gap |
| --- | --- | --- |
| Replace the agent/watchdog binary with a neutered build | `tamper` self-integrity: binaries + config hash-verified against the signed `updater` manifest; only `updater` may change them; a mismatch is high-severity, not a log. #103 hardens install artifacts. | The verify runs in user mode; a kernel adversary forges it. The manifest chain (updater #30) is the root of trust. |
| Modify config/policy to disable rules or lower thresholds | Policy is versioned and **signed** (`policy`, ADR-0003 trust domain); the agent rejects unsigned/tampered policy; protected-resource monitoring flags any foreign writer to the config path (`agent.toml`, watched since PR #770; the resolved path, so a relative `--config` is covered too). | Same user-mode caveat; the signature is the defense. |
| Delete the spool / alert log to erase evidence | The spool is append-only, `fsync`'d, and **drained to the server** — evidence that already left the host cannot be deleted from it; the two-phase ack (#108) makes at-least-once delivery the contract; protected-resource monitoring flags writers/deleters of the spool directory. | The spool-write→server-drain window; #108 minimizes it, transport (#24) closes it. Local-only deployments keep this risk. |
| Disable the service / uninstall (`sc delete`, `systemctl disable`) | Touches protected resources (service defs, unit files) → protected-resource detection; the resulting telemetry gap is server-visible. | A legitimate admin uninstall is byte-identical to a malicious one — disambiguated by *who/how/when* (recorded actor) + change-management context, not the act alone. |

### 4. Starving the server of evidence — T1562, T1071 (inverted)

| Attack on the EDR | How the EDR defends / detects | Gap |
| --- | --- | --- |
| Firewall the agent→server channel so cases never arrive | **The server treats a silent agent as suspicious, not healthy:** enrolled agents have an expected heartbeat cadence; a gap opens a fleet-level alert. Cutting comms is itself the signal. | Needs the enrollment/heartbeat spine (#24/#28); until then the agent is autonomous-and-quiet, the weaker posture. |
| MITM the transport | mTLS (ADR-0001); the agent PKI is a separate trust domain (ADR-0003) from server auth, so a stolen server credential is not an agent credential. | Standard TLS trust assumptions; cert pinning is the hardening lever. |
| Inject fake benign events to poison baselines or drown signal | Events are kernel-sourced, not accepted from arbitrary user-mode senders; the sink is not a network listener. Baseline capture is operator-gated on a clean host by procedure. | A kernel adversary forges kernel events — out of scope. Baseline poisoning is a procedure control today, not a technical one. |

## What we honestly cannot stop (and the milestone that changes it)

- **A kernel-mode adversary** defeats every user-mode control here. Mitigation: raise
  the floor to kernel (#39, #91, macOS System Extensions) and make the *transition to
  kernel* loud (driver load, LSM detach, unsigned module). Ring-0 is the honest ceiling.
- **The kill-both-fast race** has a bounded window user-mode restart cannot fully close;
  #101/#103 narrow it, a PPL-protected process + kernel watchdog close it.
- **Purely in-process activity that never reaches the kernel** is outside the no-hooks
  vantage point; #90/#91 widen it, never to 100%.
- **Local-only deployments** lose the server-side silence detection and the
  evidence-already-left-the-host guarantee — the fleet is half the self-protection story.

## Self-protection invariants (the load-bearing claims)

1. **Silence is a detection.** Every stop/blind/cut path yields a respawn or an alerted
   gap — locally (watchdog + `tamper` heartbeat), globally (server cadence check).
2. **Neither process is a single point of failure.** Agent ⇄ watchdog ⇄ service manager;
   killing any one restarts it.
3. **No userland hooks means nothing to unhook.** The commodity-EDR-evasion playbook is
   structurally weaker here; the cost is a narrower userland view, paid down by syscall
   sensors.
4. **Evidence leaves the host.** What reached the server cannot be deleted from the
   endpoint.
5. **We name the ring-0 ceiling.** Above the kernel is in scope and made loud; the
   kernel is the honest boundary, moved only by the driver/LSM milestones.

## Tracked work

#71 (`tamper`: integrity, sensor-silence, protected resources, kill-loudness — the
crate this document specifies), #101 (watchdog backoff), #102 (watchdog
liveness/hung-agent), #103 (artifact/binary protection), #104 (spike: self-protection
vs. hiding techniques — see ADR-0014 for the adopt/reject/defer verdicts), and the
kernel-floor milestones #39 and #91. Each detection row above is a conformance
target, validated the scenario-driven way the ransomware pack is
(`docs/detection/ransomware.md`): a benign lab tool performs the bypass, and the agent
must produce the alert within the interval.
