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

(`--key-file` accepts only the public test keys, ADR-0027; a production key signs with
`--pkcs11`.)

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

## Staging an artifact in the store

The artifact store is keyed by content hash, not by path (`storage/artifacts/<sha256>`, #804).
To publish a release that adds or changes a file, put its bytes there under the hash of its own
content before calling `POST /api/content/release` — the manifest's `sha256` for that entry must
match:

    sha=$(sha256sum rules/new.sigma | cut -d' ' -f1)
    cp rules/new.sigma storage/artifacts/$sha

An unchanged file needs nothing staged: its bytes are already under their hash from whichever
release first uploaded them, and the store never prunes a hash that any release (active,
rolled-back, or historical) still references (retention for hashes nothing references any more
is #834). A publish that lists a hash not present in the store is refused (422, "not in the
store"), naming the missing path.

## Publishing an IOC feed (#60, ADR-0038)

An IOC feed is content of type `ioc`: `ioc/<feed>.txt` (and an optional `ioc/VERSION`), loaded by the
agent on startup and on a content reload. `POST /api/content/ioc-feed` (owner or admin) builds the feed
from a source and stages it in the store, so the `cp` step above is done for you:

    curl -X POST .../api/content/ioc-feed -H 'content-type: application/json' -d '{
      "feed": "abuse-ch", "version": "2026-10-28",
      "source": { "format": "csv", "csv": "<the file>", "valueColumn": "indicator", "typeColumn": "type" }
    }'

`source` is `{ "format": "plain", "text": ... }` (`kind:value` lines, `defaultKind` for bare values) or
`{ "format": "csv", "csv": ..., "valueColumn", "typeColumn"?, "defaultKind"?, "hasHeader"? }` (columns by
header name, or by index with `hasHeader: false`). The feed is built with the device's own rules and the
public-suffix check; a line the device would skip is **dropped and counted**, not published, and the answer
reports how many and which (`report.rejected`, `report.rejectedTotal`): read it, a column mapped wrong shows
up as a long list. The answer also carries the manifest `entries` to paste into the unsigned content
manifest (`type: "ioc"`, the path, `sha256`, `size`), which is then signed and published as above.

Two refusals to know. A source that leaves **no** indicator is refused (422): an empty feed in a release
unloads the set on every agent of the ring, and a mis-mapped column or an error page saved as the source
gives exactly that; `"allowEmpty": true` says it is the intent. And at publish, an `ioc/` path that is not
an `ioc` entry, or a feed with a line the device would skip, is refused like any bad release (422).

To take a feed off agents, publish a corrective release that no longer lists it (above): the file is
removed and the set unloads at the next reload.

Staging writes the artifact to the store and nothing else: it does not create a release, and a feed
staged and never listed is unreferenced until retention (#834) prunes it. `prune-artifacts` keeps an
unreferenced file for 24 hours after its last write (`DEFAULT_MIN_AGE_MS`, by mtime), so that is the time
between staging and publishing the signed release; staging the same bytes again resets it.

The request body is capped at 32 MiB (413 above), in the handler and in nginx (`location =
/api/content/ioc-feed` in `server/nginx.conf`, `client_max_body_size 32m`; the default 1 MiB would refuse a
feed of about 15,000 hashes). Raise both together (`MAX_STAGE_BODY_BYTES` in `server/lib/ioc-stage.ts`).

## Upgrading a server from the old, path-keyed store (#804)

Before #804, `storage/artifacts/` held one file per manifest path
(`storage/artifacts/rules/beacon.sigma`), **overwritten on every release that changed that
path** — the old layout never kept more than the current bytes. The routes now read and write
only `storage/artifacts/<sha256>`. A server upgraded without a migration step serves every agent
a 404 on its next fetch — a new enrollment, an agent moved back to its ring, or the same-release
repair above. Before deploying past this change, copy each existing file to its hash-named
sibling (the old path-keyed files are no longer read and can be removed once every active
release's artifacts have a hash-named copy):

    find storage/artifacts -type f ! -regex '.*/[0-9a-f]\{64\}$' | while IFS= read -r f; do
        sha=$(sha256sum "$f" | cut -d' ' -f1)
        cp "$f" "storage/artifacts/$sha"
    done

Safe to re-run (a hash-named destination that already exists is overwritten with the same
bytes), but re-running does **not** verify completeness or re-heal a hash-named file that is
already missing or corrupt — it only ever reads path-named files, which the `! -regex` exclusion
skips once they have a hash-named copy. Verify after running: for every release still referenced
(active, rolled-back, or historical — same scope as the retention note above), its manifest's
every `sha256` must resolve with `test -f storage/artifacts/$sha`.

**This migration cannot recover a path's *overwritten* versions — only what is on disk right
now.** Because the old layout kept one file per path, a release that changed `rules/x.yml`
discarded whatever bytes were there before; by the time this migration runs, only the
*current* release's bytes survive at that path, and only those get a hash-named copy. A
corrective release naming an *earlier* release's hash for `rules/x.yml` (ADR-0032) is refused
(422, "not in the store") exactly as if it had never been uploaded, because for this migration's
purposes it never was: that hash's bytes were already gone before #804 shipped. Re-stage them
under their own hash from the original release's build artifacts (the `dist/` directory
`release-tool manifest` built that release from, not the live server) before publishing a
corrective release that reaches back past the most recent change to a path.

**`sha256` is schema-validated on every load, not only on publish** (`ContentEntry.sha256`,
`/^[a-f0-9]{64}$/`, since #835): `loadActiveManifest` runs the same `ContentManifest.safeParse`
the publish route does, on every agent fetch of every still-active release's stored manifest
file. A manifest that predates the regex, or was otherwise stored with a non-conforming hash
before this change shipped, now makes every agent of that release's ring get a 502 ("Manifest
does not match the expected schema") on every fetch, not just the next publish. Before deploying
this change, check every currently-active release's stored manifest against the regex (a quick
`jq '.entries[].sha256' storage/manifests/*.json | grep -vE '^"[a-f0-9]{64}"$'` over the active
ones is enough) and re-sign a corrected manifest for any that fail, same as the #804 migration
above is itself a pre-deploy step, not something the running server does for you.

## Halting or rolling back a ring from the console

`/console/ops` shows each ring's rollout state, and an organization **owner or admin** also gets two
buttons on it (#898, #863 item 4). They call the same admin routes as before (`POST /api/content/halt`
and `/rollback`), which check the role again, make the change and write the audit row
(`content.release.halt`, `content.release.rollback`, with the ring, the versions, the reason and the
user): the console adds no authority of its own.

| Ring state | Buttons | What it does |
|---|---|---|
| serving | Halt, Roll back (Roll back only when an earlier release exists) | Halt: agents of the ring stop being offered content until a new release is published or the ring is rolled back; what an agent already applied stays applied. Roll back: see below |
| halted | Roll back, only when an earlier release exists | The earlier release is offered again |
| rolled back, or no release | none | Nothing to halt or roll back |

A ring with a single release is never offered a rollback (the route would answer 404 with no release to go back to). The confirmation stays open when the call fails, with the reason and the typed ring name kept, and closes only on success.

A click opens a confirmation, it does not act. The confirmation says what the action does and does not
do, takes an optional reason (kept in the audit row) and, for a rollback, asks for the ring's name. A
rollback does not reach an agent that has already applied the rolled-back release (see above): the
answer names the number a corrective release must carry, and the page shows it. **Publishing a release
(or the corrective one) stays an API call**: there is no one-click release, because who may publish is
not decided.

**A member who is not an owner or admin** sees the same rollout state and agent counts, no buttons, and
the line "Only an organization owner or admin can halt or roll back a ring." The routes answer them
`403` in any case. A session that has ended is reported as such ("sign in again, then retry") instead of
as a failure.

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
