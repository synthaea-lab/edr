# ADR-0032: Content is withdrawn by a corrective release, not by a lower number

- **Status**: accepted
- **Date**: 2026-10-12

## Context

A content release can be wrong: a rule that produces false positives, or one that is itself
wrong. ADR-0016 gives the operator two tools. A **halt** stops delivery of the newest release
(`423`), which protects the agents that do not have it yet. A **rollback** marks the newest
release `rolled_back` and serves the previous one, which again only helps agents that have not
applied the rolled-back release: an agent applies a release only if its `release_version` is
strictly above the one it applied for that ring (the anti-replay check, ADR-0016 section 3).
The lab run of #73 (2026-10-05) showed the consequence: the server offered release 2 to an agent
that had applied release 4, the agent said `up to date (release 4, server offers 2)` and stayed
on release 4, where the rolled-back rule kept firing. With the agent never removing content a
later release stopped listing (#666, fixed in #778) there was no supported way to take a rule
off an agent that had received it (#665).

Two ways to withdraw content from such an agent were on the table: a **signed rollback marker**
that lets the agent accept a lower number, or a **corrective roll-forward**, a newer release that
carries the earlier content.

## Decision

1. **The agent never applies a lower `release_version`.** The anti-replay rule of ADR-0016 is
   unchanged, and no rollback marker, exception or new signed message type is added. A signed
   manifest that is replayed later is refused exactly as before.
2. **Content already applied is withdrawn by a corrective release**: a release numbered above
   every release of the ring so far (rolled-back ones included), carrying the earlier content
   again. Because the control plane numbers a release highest + 1 and refuses a manifest whose
   own `release_version` differs from its row's, the number is exactly highest + 1. The agent fetches what
   differs and removes what the new manifest no longer lists (#778), so it converges on the
   earlier content whatever it had applied.
3. **The corrective release is built and signed offline**, like every release: `release-tool
   roll-forward` rebuilds an earlier content manifest under a new number, `release-tool sign
   --kind content` signs it, and it is published through `POST /api/content/release`. The control
   plane does not hold the key and does not mint releases. `roll-forward` **verifies the earlier
   manifest's signature first** (against the key the tool embeds) and refuses an empty one: the
   offline step is the trust boundary, and a manifest taken from a store the control plane holds
   must not come out of it validly signed with edited entries.
3a. **The artifact store keeps one file per path, shared by every release.** A corrective release
   can therefore withdraw content a later release *added* (its files are simply no longer listed),
   but for content a later release *modified* the earlier bytes must be put back in
   `storage/artifacts` first: the manifest lists the earlier hash, the store holds the later bytes,
   and every agent would get a 502 on that fetch. `release-tool roll-forward --current <manifest
   being withdrawn>` lists those paths, and **`POST /api/content/release` now refuses (422) a
   release whose manifest is not the one named, lists nothing, is for another ring, carries a
   number other than the one it will assign, or lists an artifact that is missing from the store
   or does not hash to its value**, instead of failing for the whole ring when it is served.
   Storing artifacts by hash would remove the restoring step and is the larger change this does
   not make.
4. **The rollback endpoint keeps its job, and says what it does not do.** It still reactivates
   the earlier release for agents that have not applied the rolled-back one. Its response and its
   audit entry now name the corrective release that is needed (the number to use, the release to
   restore).
5. **The agent says what it is looking at.** An offer older than the applied release is reported
   as such (`the server offers release N, OLDER than release M ... stays on release M`) and logged
   as a warning, no longer as "up to date". The exit status is unchanged: a timer unit must not
   fail because an operator rolled a release back.

## Consequences

- A corrective release over a modified path is a two-step operation (restore the bytes, then
  publish); the tool says which paths and the server refuses a publish that skips it.
- Known and not changed here: after an agent was pointed at another ring the "stays on release N"
  message can be wrong, because the agent's applied-entries state is one map for all rings (#666).
  (The release, rollback and halt routes checking a session and a tenant but not an administrator
  role, noted here as predating this ADR, is fixed by #803/#831: all three now require an `owner`
  or `admin` member of the tenant.)
- No new trust primitive, no change to what an attacker who can replay old manifests can do, and
  no new thing to verify, rotate or revoke.
- Withdrawing content takes a signing step. With the custody of the production keys still open
  (#753) that is the same bottleneck as any release; the lab uses the test key.
- Withdrawal is not instant for an agent that is offline: it converges on the corrective release
  at its next apply. A halt on the ring in the meantime still stops delivery.
- Applying the corrective release depends on the agent removing unlisted files (#778) and on its
  guards: it refuses a manifest that lists nothing while content is applied, so the corrective
  release must carry at least one entry. Withdrawing **everything** is not possible this way, by
  design; it needs its own decision.
- The binary updater (ADR-0015) is unchanged: its rollback is the ban list and the previous
  version directory, and `apply-release` still prints "up to date" for an older offer. Not part
  of this decision.
