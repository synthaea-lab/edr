# Automated response

What the agent does to the endpoint on its own, how to turn it on, what it writes
down, and how to undo it. Linux only today: on Windows and macOS `run` accepts the
flags and ignores them (nothing acts, nothing reports). Issue #25.

## Off by default

`agent run` is observe-only. Nothing is killed or moved until the operator opts
in per action:

| Flag | Action | Triggered by |
| --- | --- | --- |
| `--enable-kill` | `SIGKILL` the process | a high-confidence correlated verdict for that pid (today: the Bayesian belief crossing, `BAYES`, the only `Critical` detection) |
| `--enable-quarantine` | move the file aside | a YARA rule confirmed a match on a file being written |

With a flag off, the same trigger still produces an audit line saying what
**would** have happened, so a policy can be trialled in observe-only before it
acts. `policy::ResponsePolicy::default()` is both off, pinned by a test.

## What is audited

Every outcome lands in the agent's alert log (`--alerts`, default
`alerts.ndjson`) as a `RESPONSE-*` entry, acted or not:

| Technique | Message says |
| --- | --- |
| `RESPONSE-KILL` | `killed pid N …`, `pid N would have been killed … (observe-only)`, `failed to kill pid N …: <error>`, or `refused to kill pid N …: <reason>`. The reason after `on` names the trigger: `a high-confidence correlated verdict` (the correlator's `BAYES` crossing) or `a corroborated ransomware signal (burst rule + canary touch)` (below) |
| `RESPONSE-QUARANTINE` | `quarantined <path> (<sha256>) to <dir> …`, `<path> would have been quarantined … (observe-only)`, or `failed to quarantine <path> …: <error>` |
| `RESPONSE-UNQUARANTINE` | `restored <path> (<sha256>) from quarantine …` or `failed to restore <sha256> …: <error>` |
| `RESPONSE-ESCALATE` | `escalated <ppid>:<comm> at <severity> severity across N source(s): <techniques>`: the entity's fused verdict (rules, Sigma, YARA, correlator) reached High or Critical. Raised once per new verdict snapshot, not per finding. Non-destructive: it kills and quarantines nothing and does not depend on `--enable-kill` or `--enable-quarantine`, so it appears with both off. It is a prompt to triage; the kill gate still reads only the correlator's own `BAYES` crossing |

## Safety rails

- **Protected pids are never signalled**, whatever the policy: pid 0 and any pid
  that does not fit a signed `pid_t` (both would address a process group), pid 1,
  and the agent's own pid. The refusal is audited as `refused to kill`, also with
  `--enable-kill` off, so the log never claims something "would have been killed"
  that could not be. The pid comes from telemetry and the kill is a root `SIGKILL`
  by number, so a wrong number has to fail closed.
- **The kill's trigger is a belief, not a signature.** It fires when the correlator's
  Bayesian score for a process crosses its threshold, and that score is built from
  behaviour (a fast connection after exec, repeated connections, destination, path) plus
  the co-occurrence rules. Through the real correlator with no learned scorer, a
  short-lived process that execs and then connects out repeatedly crossed it whatever its
  image path was, `/usr/bin/nc` included, so an ordinary tool with that shape is a
  candidate. Trial `--enable-kill` observe-only first, read the
  `RESPONSE-KILL ... (observe-only)` lines it would have acted on, and enable it only for
  hosts where those are all things you would have wanted killed. The name exclusions
  (`wget`, `chronyd`) and the ignored-comm list reduce this and were not part of that
  measurement.
- **Quarantine never re-quarantines itself.** A file already under the quarantine
  directory is left alone (writing it there is itself a file event the sensor sees).
- **A kill is a `SIGKILL`**, not `SIGTERM`: a process judged compromised gets no
  chance to catch the signal. The pid is the one on the event that raised the
  verdict; a pid recycled between the event and the signal is a known, narrow window.

## What the agent reads on other users' behalf

With the packaged unit the agent can read any file on the host (`CAP_DAC_READ_SEARCH`,
`ProtectHome=read-only`), and hashes or scans paths that processes of other users touch,
including under `/home` and `/root`. Two consequences for a deployment with data-handling
constraints:

- A YARA scan is done only when the user whose process named the path could read the file
  themselves, so one user cannot make the agent read another user's files.
- The *result* of a scan or a hash (a rule name, a SHA-256) and the path leave the host
  with the detection, for files in users' home directories too. If hashes of user files
  must stay on the host, keep `ProtectHome=true` in a drop-in; payloads dropped in
  `/home` are then not scanned.

## Quarantine from the packaged unit

The packaged systemd unit lets the agent read and hash anything on the host, including
`/tmp`, `/var/tmp` and `/home` (read-only), but it deliberately cannot move a file out of
another user's directory: that needs `CAP_DAC_OVERRIDE`, `CAP_FOWNER` and writable
source directories, which is close to running as root (ADR-0014, amendment for #594).
With `--enable-quarantine` and the shipped unit, quarantine therefore fails with a logged
`failed to quarantine ...` for such files, and the payload is left in place.

A host that accepts that trade can opt in with a drop-in
(`systemctl edit synthaea-agent`):

```ini
[Service]
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE CAP_DAC_READ_SEARCH CAP_NET_ADMIN CAP_KILL CAP_DAC_OVERRIDE CAP_FOWNER
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE CAP_DAC_READ_SEARCH CAP_NET_ADMIN CAP_KILL CAP_DAC_OVERRIDE CAP_FOWNER
ProtectHome=no
ReadWritePaths=/tmp /var/tmp /home
```

## Quarantine layout and reversal

The quarantine directory is `quarantine/` next to the alert log (`--alerts`), no
separate flag. A payload is moved there, renamed to its own SHA-256, marked
read-only, with a `<sha256>.origin` sidecar holding its original path.

```
agent quarantine --alerts /var/lib/synthaea/alerts.ndjson list
agent quarantine --alerts /var/lib/synthaea/alerts.ndjson restore <sha256>
```

Pass the same `--alerts` the running agent was given. `list` prints
`<sha256>  <original path>`. `restore` puts the file back and audits it. It refuses,
changing nothing, when:

- the digest is not a lowercase 64-character SHA-256 (it names a file under the
  quarantine directory, so it must not be able to name anything else);
- the stored file no longer hashes to its name (altered since quarantine);
- something now exists at the original path. A restore never overwrites.

The restored file stays read-only: whoever restores a payload for investigation
should decide explicitly that it is safe to make writable or executable again.

A restore that fails before the file is back changes nothing, including when the
quarantine directory is on another filesystem and the payload has to be copied: a
half-written destination is removed, so a retry is not blocked by it. Once the file is
back at its original path the restore has succeeded, and removing the quarantined copy
and its sidecar is cleanup. If the quarantine directory refuses that (read-only or
busy), `restore` still succeeds, prints a warning, and records the leftover in the
`RESPONSE-UNQUARANTINE` audit line; the payload then stays listed until it is removed by
hand, and a second `restore` refuses because the original path is occupied.

## Silencing a noisy finding

The agent fuses every engine's findings into one verdict per entity (`<ppid>:<comm>`).
When one technique keeps firing on an entity you have judged benign, drop it from that
fused view without touching the rules:

```
cli suppress <ppid> <comm> <technique>     # e.g. cli suppress 1 cron T1059.004
cli unsuppress <ppid> <comm> <technique>
cli status                                  # lists every active suppression
```

- It is runtime state in the agent, not configuration: a restart clears it.
- The alert log still records every finding. A suppression only keeps the finding out
  of the fused verdict (and so out of escalation); it never feeds the kill gate, which
  reads the correlator's own `BAYES` crossing.
- Each change is audited as `VERDICT-SUPPRESS` / `VERDICT-UNSUPPRESS`. Repeating a
  command that changes nothing says so and writes no audit line.
- The list holds at most 1024 marks; past that `suppress` is refused until one is lifted.
- Like every control channel request it needs root (Unix) or an elevated prompt (Windows).

## Not built yet

- **Host isolation** and the analyst-driven half (`response::live`): blocked on
  server-side analyst auth.
- **A lab run of the whole chain** ("Done when": the beacon scenario with response
  enabled kills the process and quarantines the payload, both audited).
  `lab/scenarios/response.sh` (with `response.yaml` and `response-marker.yar`) is that
  scenario and has not been run on a VM. The same stream through the real detection path
  (correlator, YARA queue, filesystem; only the kernel `terminate` call is a recorder) is
  covered in-process in `agent/src/sink.rs`, with response on and with it off. What only
  a VM can show is that the eBPF sensor delivers the stream and that the real `SIGKILL`
  lands. Note that `beacon.sh` itself cannot show a kill: four `nc` connections two
  seconds apart from four separate pids do not reach the `BAYES` verdict the kill is
  gated on, while one process reconnecting every second does (measured without a learned
  scorer; a deployed agent adds the ML contribution, so the crossing point on a real
  install can differ).
- **Windows and macOS actions.** The pieces in `crates/response` are platform-neutral;
  the kill call is injected per platform and only Linux injects one.
- **Non-Linux `quarantine list|restore`** works everywhere (plain file operations)
  but has nothing to list there yet.

## Ransomware reflex

A second, separate kill trigger (issue #82). A process incarnation that raises the ransomware
burst rule (T1486) **and** touches a planted canary (`docs/operations/deception.md`) within 60
seconds of event time is killed, in either order. Neither signal kills alone: a burst alone is a
backup, an export or an archiver, and a canary touch alone is an indexer nobody listed. It
follows the same policy as every automated kill: with `--enable-kill` off the audit line says
`pid N would have been killed on a corroborated ransomware signal ... (observe-only)` and
nothing is signalled, and the pids `response` never signals (init, the agent) are refused. The
detection is recorded before the kill. It needs `[deception] canary_dirs`: without canaries the
reflex has nothing to corroborate and never fires. It kills the process only; killing the tree
and quarantining its binary are not built.
