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

## Withdrawing a rule that an agent already applied

An agent that has applied release N does not go back to an older release (anti-rollback,
ADR-0016: `up to date (release 4, server offers 2)`). To take a bad rule off such an agent,
publish a newer release that no longer lists it. After the new entries have landed, the agent
deletes every file it had applied that the manifest no longer lists, and says how many
(`applied release 5 (0 entries fetched, 2 removed)`); `check-content-manifest` lists them as
`remove <path>`. Only files recorded in the agent's content state are removed, never anything
outside the content directory, and never through a symlink. If the download of the new release
fails, nothing is removed and the rules the agent runs today stay.

Three guards worth knowing. A manifest that lists nothing while the agent has applied content is
refused (`the manifest lists no content but N applied file(s) would be removed`), and the server
refuses to build one: an empty or mis-globbed release must not be able to wipe a ring. A file
that cannot be removed (a directory at its path, a symlink on the way, a permission error) is
reported (`could not be removed ... retries them`) and kept in the state; the rest of the release
still applies and the next run tries again, so one stuck file does not stop new rules. A path
that is the same file as a listed one under another case (`Foo.yml` against `foo.yml` on
Windows or macOS) is not deleted. An offer of the *same* release number is applied again when
the files on disk do not match it, which is what repairs a ring after the agent was pointed at
another ring and back; an *older* offer is still ignored (see #665).

## A rollback does not reach an agent that already applied the release

Rolling a ring back (`POST /api/content/rollback`) makes the control plane offer the earlier
release again. An agent that has **not** applied the rolled-back release takes it. An agent that
**has** stays where it is: it never applies a lower release number (anti-rollback), and says so:

    ring canary_0: the server offers release 2, OLDER than release 4, which this agent has applied. An older offer is never applied (anti-rollback), so this agent stays on release 4. ...

To bring those agents back, publish a **corrective release** that carries the earlier content
(ADR-0032). Its number is exactly the next one the control plane assigns, one above the highest
release of the ring (rolled-back ones included); the rollback response names it. Built and signed
offline, from the earlier release's **archived, signed manifest** (the tool verifies its signature
and refuses one that does not verify or lists nothing):

    release-tool roll-forward --from release-2.json --current release-4.json \
        --release-version 5 --released-at 2026-10-12T09:30:00Z --out release-5.json
    release-tool sign --kind content --key-file release.key release-5.json --out release-5-signed.json

`--current` (the manifest being withdrawn) is optional but worth giving: it lists what agents will
remove, and the paths whose bytes differ between the two releases, for the operator's own
information. **The artifact store is keyed by content hash** (`storage/artifacts/<sha256>`,
#804), not by path, so nothing needs restoring: the earlier release's bytes are still sitting
under their own hash, wherever they were first uploaded, whatever a later release did at that
path. Publishing the corrective release needs only the manifest itself.

Then publish with `POST /api/content/release`. The control plane refuses (422) a release whose
manifest is not the one named, lists nothing, is for another ring, carries another number than the
one it will assign, or lists an artifact that is missing from the store or does not hash to its
value, so none of this shows up later as a failure for every agent of the ring. Agents fetch what
differs and remove what it no longer lists (see above).

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

`apply-content-manifest` also checks which key it would verify against (ADR-0027) before any
network or disk work, and refuses in two cases that look like a failing unit: a packaged
build embeds no content key until the production keys are committed
(`crates/updater/keys/`), and a lab build with the `test-key` feature verifies against the
public test key only when started with `--allow-test-key`. For a lab unit that means
`ExecStart=/usr/bin/agent apply-content-manifest --allow-test-key`; do not add that flag to
a production unit.

`check-content-manifest` is different on purpose: it is a read-only check run by a
person, not a timer, and it exits 1 on a `423` (it still prints the reason). A check
that returned 75 would show a halted ring as an accepted outcome in the one place an
operator looks for it. Do not add `SuccessExitStatus=75` to a unit that runs it.

A ring that stays halted for weeks is silent from the timer's side once 75 counts as
success; the agent does not count consecutive halts or put them in the health beacon
(a new beacon field is a schema change for a state the control plane already knows).
Watch the halt where it is set, on the control plane, or run `apply-content-manifest`
by hand and read the reason it prints.
