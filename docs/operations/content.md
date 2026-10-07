# Content delivery on an agent

`agent apply-content-manifest` fetches the signed content manifest for the
agent's ring, downloads what is missing or stale, verifies it, writes it under
the content directory and tells a running agent to reload (ADR-0016).

## Exit status

| Status | Meaning |
|---|---|
| 0 | Applied, or already up to date. |
| 1 | Failed: control plane unreachable, a rejected request (any 4xx other than 423, any 5xx), a manifest or artifact that does not verify, a disk error. |
| 75 | The control plane **halted the ring** (`423 Locked`). |

A halt is an intended, temporary state: the control plane serves nothing for
that ring until it is lifted. The command prints the server's reason, for example

    ring canary_0: content delivery is halted by the control plane (Content delivery is halted for ring 'canary_0' at release 3); nothing was changed, the current content stays active

and, when the halt arrives before any artifact is applied, leaves the state
file and content directory untouched. The rules the agent already loaded keep
running. The halt can also land between the manifest and an artifact download;
it is reported the same way, and entries already written stay recorded for the
next run. The release is not marked applied until every artifact has landed.

## Running it from a timer

Status 75 is `EX_TEMPFAIL`. So that a halt does not show as a failed unit,
declare it a success in the service:

```ini
[Service]
Type=oneshot
ExecStart=/usr/bin/agent apply-content-manifest
SuccessExitStatus=75
```

Anything else non-zero is a real failure and should stay one.

`check-content-manifest` is different on purpose: it is a read-only check run by a
person, not a timer, and it exits 1 on a `423` (it still prints the reason). A check
that returned 75 would show a halted ring as an accepted outcome in the one place an
operator looks for it. Do not add `SuccessExitStatus=75` to a unit that runs it.

A ring that stays halted for weeks is silent from the timer's side once 75 counts as
success; the agent does not count consecutive halts or put them in the health beacon
(a new beacon field is a schema change for a state the control plane already knows).
Watch the halt where it is set, on the control plane, or run `apply-content-manifest`
by hand and read the reason it prints.
