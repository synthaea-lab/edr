# ADR-0028: The kill gate refuses a system service's main process

- **Status**: proposed
- **Date**: 2026-10-06

## Context

`--enable-kill` terminates the process behind a correlator `BAYES` crossing (#25,
`crosses_kill_gate` in `agent/src/sink.rs`). The gate reads only that crossing, by design:
severity and rule alerts must not widen what the agent kills (#131).

On a stock Fedora 44 host (#652), `NetworkManager` crossed `BAYES` (log_odds 3.08, P=96%)
with a single source and no rule or YARA hit, and was killed; `chronyd` raised a High
escalation in the same run. systemd restarted the service, but on a fleet this drops host
connectivity and with it the agent's path to the control plane. The calibration is the
cause, not a regression of the gate. Three options were put on the issue:

1. Gate the exclusion on provenance (`policy::name_exclusion_applies` and the like).
2. Require corroboration (BAYES plus a rule, Sigma or YARA hit) before a kill.
3. Never kill systemd-managed units.

Option 2 does not hold: the lab implant is killed on `BAYES` alone by design
(`lab/scenarios/response.yaml`; the YARA hit lands on the payload its shell wrote, not on
its pid), so a per-pid corroboration rule would break `EXPECT=enforce` and the in-process
kill tests. Option 3 as worded would also protect a shell spawned by a compromised service
(it lives in the unit's cgroup), which is the `nginx` webshell case of #478. What separates
the implant from `NetworkManager` is provenance, not the amount of evidence.

## Decision

1. **A system service's main process is never terminated on a `BAYES` crossing.** The
   correlator records, at the `ExecEvent`, that a pid is a *service main process*: its image
   is under a trusted system path, outside `/opt/` and `/usr/local/`, not a shell or
   interpreter, and has no `..` path component (`policy::service_main_path_is_trusted` —
   stricter than the name-exclusion masquerade check `policy::name_exclusion_applies`
   reviewed PRs reuse, see its own doc comment for why: review of #755, Sollykhan
   2026-10-19, reproduced that `/usr/bin/python3`, `/usr/local/bin/kworkerd` and `/opt/x/x`
   all passed the broader check, each making every payload run under them permanently
   immune to the kill gate) **and** its parent is init (`ppid == 1`). The sink reads that
   verdict for the pid and generation (`CorrelationEngine::is_service_main_process`) when
   the gate fires. An exec that stops qualifying clears any prior entry for that pid (same
   review): `service_mains` used to be insert-only, so a service main that was later
   compromised and `exec`'d something else kept the refusal on its new image forever.
2. **The refusal is a `KillOutcome::Refused`**, audited as `RESPONSE-KILL` like the existing
   refusals, in observe mode too (the audit line says "refused", not "would have been
   killed"). The `BAYES` alert and the `RESPONSE-ESCALATE` it feeds are unchanged: the
   verdict is still raised, only the kill is withheld.
3. **Children are not protected.** A shell or tool spawned by the service has a different
   parent, so it stays killable (the compromised-daemon case).
4. **Unknown is not trusted.** An exec with an empty image path, or a pid whose exec the
   agent never saw, is not a service main process. A sensor limitation is not a reason to
   withhold a kill.
5. **Corroboration does not lift the refusal.** The rule is about what the process is, not
   how much evidence exists; a service that is compromised is dealt with by escalation and
   the responder, not by an automatic `SIGKILL` of a unit systemd would restart.
6. **Only the correlator's `BAYES` gate is covered.** The ransomware reflex (#82: the
   burst rule fires and the process touches a canary) is a separate trigger that rests on
   its own evidence, not on a calibrated belief score, and it keeps killing as before. This
   was a choice made when this branch was rebased over #82: whether a service's main process
   that trips the reflex should also be spared is open and is the reviewers' call.

## Consequences

- `NetworkManager`, `chronyd`, `sshd` and every other package-owned daemon started by init
  are escalated, not killed, whatever their belief score. The lab implant (exec'd from
  `/tmp`, child of a shell) is killed as before; the regression tests pin both sides.
- A compromised service's own main process is no longer auto-killed. The accepted
  trade-off: killing it restarts it, and the fleet-wide outage a false positive causes
  outweighs it. The compromised service's children remain killable.
- The check is path-and-parent provenance, a heuristic: a binary a root attacker replaces
  under `/usr/sbin` is not detected by it (the same limit `policy` documents for name
  exclusions; the durable answer is signature and package verification).
- **Limits.** Only services started directly by pid 1 qualify. User-session services
  (`systemd --user`) and container processes (parent is a container shim) are outside the
  rule and stay killable; whether they should be protected is open. The pid-1 test assumes
  the sensor reports the real parent, as the Linux eBPF sensor does. Non-systemd init
  (OpenRC's `start-stop-daemon`, forking daemons in general) never gives their main process
  `ppid == 1`, so they are not protected either — the safe direction, same #652 false-kill
  risk just stays open there. A subreaper or a pid namespace also breaks the `ppid == 1`
  assumption; not evaluated.
- `lab/validate-652.sh` ran on Fedora 41 (2026-10-07, 8/8, before the #82 rebase) and again
  on Fedora 43 (2026-10-16, 7/8: scenario A's `BAYES` crossing missed this run's timing
  window on that VM, unrelated to this guard). Scenarios B and C — the guard itself, in
  enforce and observe mode — passed both times.
- The refusal is visible only locally (the `RESPONSE-KILL` audit line in `alerts.ndjson`);
  nothing distinguishes a withheld kill from an ordinary refusal over the transport, so the
  control plane cannot yet tell a fleet operator "a service main was spared" versus any
  other reason a kill didn't happen.
- The ADR changes the kill contract, so it needs the correlator calibration owner's review.
