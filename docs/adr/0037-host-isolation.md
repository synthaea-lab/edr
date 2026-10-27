# ADR-0037: Host isolation: a persistent, agent-owned block with a pinned control-plane path

- **Status**: proposed
- **Date**: 2026-10-22

## Context

ADR-0010 lists `isolate` among the response actions a policy can enable, and #25 shipped
`kill` and `quarantine` but left isolation as follow-up scope. Isolation does not exist on
any platform today:

- `docs/operations/response.md` lists it under "Not built yet".
- `ipc` keeps it out of the control channel "once the authorization model they need
  (per-capability, policy-gated) is designed".

#138 adds Windows Filtering Platform (WFP) to the driver umbrella (#39) for two things:
network visibility and "the enforcement primitive for host isolation". The issue is marked
blocked on the kernel driver, because a WFP callout is a kernel component. Isolation does
not need a callout. WFP's management API (`FwpmEngineOpen0`, `FwpmSubLayerAdd0`,
`FwpmFilterAdd0`) adds permit and block filters from an elevated user-mode process through
the Base Filtering Engine, and those filters are enforced by the TCP/IP stack itself. Only
inspecting or rewriting traffic, as #373's TLS metadata does, needs a callout.

Five forces shape the design:

- **An isolated host must stay reachable by the control plane.** Without that path, nobody
  can lift the isolation, nobody can investigate, and the agent's own detections cannot
  reach the server. That is the point of isolating rather than unplugging.
- **The control plane can sit on shared addresses.** If it is hosted behind a CDN or a
  shared load balancer, "allow the server's IP" also allows every other site on that IP,
  for every process on the host. That would be an exfiltration path through the isolation.
- **An attacker who can stop the agent must not lift the isolation by doing so.**
  Otherwise, stopping the service is the escape.
- **An operator must always be able to recover a host**, including when the agent is broken
  and the control plane is unreachable.
- **Platform code placement** (CLAUDE.md): `response` is a leaf crate whose platform
  exceptions are narrow and named. The kill action already shows how to handle this:
  `response::kill_process` takes the OS call as an injected closure, and the binary supplies
  it (`agent/src/commands/linux.rs`).

## Decision

1. **The mechanism on Windows is user-mode WFP. No driver.** The agent owns:
   - a WFP provider and a sublayer, each with a fixed GUID;
   - in its sublayer, filters at the ALE authorization layers:
     `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` (outbound) and
     `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4/V6` (inbound).

   Isolation is one low-weight block-all filter per layer, plus higher-weight permits for the
   allowlist (decision 3). Lifting deletes the agent's filters by key. Nothing else on the
   host's WFP state is touched. Because the block sits in its own sublayer, a permit in
   another sublayer, such as Windows Firewall's, cannot override it: WFP lets a block in any
   sublayer win.

2. **Persistent filters, reconciled at start-up.**
   - The provider, the sublayer and the filters are added with the `*_FLAG_PERSISTENT` flags,
     so the Base Filtering Engine keeps them across a restart of the agent or of the host.
     Stopping or killing the agent therefore does not lift the isolation (the third force).
   - The agent also persists its intent in `isolation.json` in its state directory: isolated
     or not, the pinned endpoints, who asked and when. At start-up it reconciles WFP with
     that file:
     - intent "isolated": the filters are re-added if they are missing;
     - intent "not isolated": leftover filters in its sublayer are removed.

     A crash in the middle of applying or lifting cannot leave the host half-isolated across
     a restart. The file is written through a synced temporary file and a rename, and every
     command that reads or writes it (`cli`, the IPC handler, `agent isolation lift`, the
     reconciliation) holds an exclusive lock on a sibling `isolation.json.lock` first, so two
     of them cannot interleave.
   - The reconciliation is not policy-gated. The gate is on the request; an isolation already
     persisted stays enforced if the policy is turned off afterwards, and the way out is a
     lift (decision 5).
   - **Boot.** Persistent filters are enforced by the Base Filtering Engine as soon as it
     starts, not when the agent does, so the agent's own start-up adds no window. What
     remains is the window between the TCP/IP stack starting and BFE starting. Slice 2 closes
     it by adding the same block and permits as boot-time filters
     (`FWPM_FILTER_FLAG_BOOTTIME`, which the stack enforces until BFE takes over and which
     cannot also be persistent, hence a second set); whether that holds is checked in the
     lab before the operations doc promises it.
   - A WFP dynamic session was rejected: its filters vanish when the agent's process exits,
     which is exactly the escape described above.

3. **The allowlist is closed and computed by the agent, not configured as free text.** It
   holds:
   - **Loopback**, in both directions (`FWP_CONDITION_FLAG_IS_LOOPBACK`).
   - **The control plane, pinned and narrowed.**
     - The server URL from `agent.toml` is resolved once, when the isolation is applied.
     - The permit names those addresses and the server's port, **and the agent's own image
       as the application** (`FWPM_CONDITION_ALE_APP_ID`). Every other process stays
       blocked from those addresses, which closes the shared-address path from the second
       force.
     - Isolation does not allow DNS. DNS is a classic exfiltration channel, and on Windows
       queries leave from the DNS Client service, not from the agent, so it could not be
       limited to the agent anyway.
     - The consequence: a control plane that changes address while a host is isolated loses
       that host. The agent then stays isolated and keeps spooling, and recovery is
       decision 5.
   - **DHCP**: UDP 68→67 and 546→547. Without these, the lease expires and the host loses the
     address the control-plane path depends on.

   Nothing else is allowed in this first version. In particular, there are no
   operator-supplied exceptions (a management subnet, a jump host). They can be added later
   as a policy field with the same pinning rules, if an operator needs them.

4. **Who can isolate.**
   - **Policy gate.** Isolation is gated by a new `response.isolate_enabled` policy field,
     default `false`, alongside `kill_enabled` and `quarantine_enabled` (ADR-0010: deny by
     default until explicitly enabled). It applies to every trigger.
   - **Lifting is never gated.** It is the safe direction, and refusing it would turn a
     policy mistake into a host nobody can recover.
   - **First trigger: a local, elevated command.** `cli isolate` and `cli unisolate` go over
     the existing IPC control channel, which only accepts an elevated caller on Windows (or
     root on Unix). This is the per-capability, policy-gated model `ipc` asked for, applied
     to one capability.
   - **Not yet: the server, and automation.**
     - A server-initiated isolation needs analyst authentication on the server and a
       signed, per-agent, replay-protected command. The closest precedent is ADR-0035's
       posture overlay. It will be its own decision.
     - Automated isolation on a verdict tier is not in this ADR: isolating a host on a
       detection alone is a stronger act than killing one process, and nobody has asked
       for it yet.

5. **Recovery always has a local path.** Two commands lift the isolation from the console
   of the host, with an elevated prompt:
   - `cli unisolate`, which goes through the running agent;
   - `agent isolation lift`, which works with the agent stopped. It deletes the agent's
     filters by their known keys and records the lift in `isolation.json`.

   Neither needs the network. Both are documented in `docs/operations/response.md` before
   isolation can be enabled in a policy.

6. **The split between crates follows `kill`.**
   - **`response::isolation`** stays platform-neutral:
     - building and validating the plan: pinned endpoints, rejection of
       unspecified/multicast/broadcast addresses and of IPv6 link-local ones (a plan keeps no
       scope, so the permit would match on every interface), a cap on the number of entries.
       A plan read back from `isolation.json` goes through the same validation;
     - the policy gate;
     - the persisted intent and the reconciliation decision;
     - the outcome type an audit consumer reads.
   - **The WFP calls** live in the `agent` binary, behind a small trait `response` defines
     and the binary implements per platform (`agent/src/commands/windows.rs` and a module
     beside it).
   - So `response` gains no platform branch, and CLAUDE.md's list of platform exceptions
     does not change.
   - Linux (nftables, its own table) and macOS (a `pf` anchor) implement the same trait in
     later slices. The plan, the policy and the persisted intent are shared.

7. **Every change is audited and reported.**
   - Applying and lifting emit `HOST-ISOLATE` and `HOST-UNISOLATE` to the alert log and the
     detection spool, so the server learns about them over the pinned path. Each entry
     carries the trigger and the pinned endpoints.
   - A reconciliation that finds WFP state different from the intent emits
     `HOST-ISOLATION-DRIFT`. Filters missing while the host should be isolated are a
     tampering signal.
   - A reconciliation that fails (unreadable intent, unreadable WFP state, a refused re-apply
     or removal) also emits `HOST-ISOLATION-DRIFT`, with the error. It leaves WFP as it found
     it: persistent filters stay, so a host whose intent is unreadable and that was isolated
     stays isolated until a local lift.

## Consequences

- Isolation exists on Windows without the kernel driver. #138's inline-block half is no
  longer blocked on #39; only its visibility half (callout-level inspection) and #373 still
  are.
- An isolated host keeps sending telemetry and detections over a path that only the agent
  can use, toward addresses resolved before the isolation.
- A control plane that changes address during an isolation strands its isolated hosts.
  Recovery is then local (decision 5). This is accepted in exchange for not allowing DNS.
- A local administrator who wants out can always delete the agent's WFP filters. Isolation
  contains malware and an attacker without administrative rights. Against an administrator
  it is a detection (`HOST-ISOLATION-DRIFT` on the next reconciliation), not a guarantee. The
  driver (#39, ELAM/PPL) is what would change that.
- Whether filters added at the ALE layers also cut connections that were already open when
  the isolation started (ALE reauthorization) has to be checked in the lab before the
  operations doc promises it. If they do not, the Windows slice also adds blocks at the
  transport layers.
- The policy document gains `response.isolate_enabled`. It is serialized only when `true`, so
  the canonical bytes of every existing policy document are unchanged.

## Alternatives considered

- **Wait for the WFP callout driver (#39).** The driver adds nothing for a block or permit
  decision on addresses, ports and applications, and it is a long-term item. Waiting would
  keep isolation unbuilt for no gain in enforcement.
- **`netsh advfirewall` / Windows Firewall rules.** Rules live in the user-visible firewall
  policy, so a Group Policy refresh can rewrite them and an administrator can change them
  without a trace. The firewall also has to be on, which is not true on every host. A
  sublayer the agent owns depends on none of that.
- **A WFP dynamic session.** Rejected in decision 2: killing the agent would lift the
  isolation.
- **Allowlisting the control plane for every process.** Rejected because of shared
  addresses: on a CDN-hosted control plane, it would reopen the Internet to any process on
  those addresses.
- **Allowing DNS to the configured resolvers.** It keeps a moving control plane reachable,
  but it reopens a channel that DNS-tunnelling tools use, from every process, because the
  queries leave from a shared service.

## Slices

1. This ADR, `response::isolation` (plan, policy gate, persisted intent, reconciliation),
   and `response.isolate_enabled` in `policy`.
2. Windows: the WFP implementation in the agent, start-up reconciliation, the IPC
   `IsolateHost`/`LiftIsolation` requests, `cli isolate|unisolate`, `agent isolation lift`,
   and a lab scenario that measures what is cut (including already-open connections) and
   what still reaches the control plane.
3. Linux and macOS implementations of the same trait.
4. Server-initiated isolation (its own ADR: analyst authentication, the signed per-agent
   command) and the isolation state in the console.

## References

- #138 (WFP network telemetry and inline block), #25 (response), #39 (driver umbrella), #373.
- ADR-0010 (shared policy model), ADR-0021 (the quarantine platform exception), ADR-0035
  (the signed per-agent pull channel this ADR's server slice will follow).
