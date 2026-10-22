# ADR-0027: Production signing keys for releases and content: a trust set, custody, and a recovery path

- **Status**: accepted 2026-10-21 as a design, with "Owner's decisions, 2026-10-21"; the holders, the approvers and the accounts are not decided, and no key is generated until they are
- **Date**: 2026-10-06 (accepted 2026-10-21)

ADR-0033 adds a fourth key to this trust set, `snapshot`, with one job: signing the per-tenant
common-set snapshot manifest, held in a signing-only key service rather than in offline custody.
ADR-0035 adds a fifth, `posture`, on the same terms. Neither changes the three keys decided here.

## Implementation status

Decision items 3 and 4 are implemented (#753): `crates/updater/keys/{release,content,recovery}.pub`
(`unprovisioned` until the ceremony), the `test-key` feature on `updater`, `agent` and
`release-tool` (default on for development and the lab), `SYNTHAEA_UPDATER_TEST_KEY` derived from
it, `--allow-test-key` only in a `test-key` build and now also required by
`apply-content-manifest`, a build without the feature or a key refusing with a clear error, and
`tools/check-no-test-key.sh` in CI. `release-tool` signs from a PKCS#11 token (#944:
`--pkcs11 <module> --pkcs11-token --pkcs11-key`, the PIN from an environment variable or a
0600 file, a `Signer` trait, a signature that does not verify under the signer's own public key
refused), tested against a software token only: no real token or HSM has been exercised.
`--key-file` accepts only the public test keys (a key file holding any other seed is refused, and
a build without the `test-key` feature takes no key file at all), as the decision below says. The
key-rotation release is implemented (#753, #961, tested with the public test `recovery` key and a
software token only): `updater::rotation`
(`KeyRotationManifest`, verified against the embedded `recovery` key and nothing else, bound to the
key state it starts from, with a `release_version` and a validity window), `release-tool rotation`
to build it and `sign --kind rotation` to sign it, and a golden fixture
(`crates/updater/tests/fixtures/key-rotation-golden.json`). **The agent applies a rotation**
(this change, stacked on #961): `agent apply-key-rotation` fetches it (or reads `--file`), verifies
it and records it under `storage.state_dir` (`key-rotations.json`); `apply-release`,
`apply-content-manifest`, `check-content-manifest` and the self-integrity check verify against the
keys in force; releases share the rotation's `release_version` counter. How the record relates to
the embedded keys is in "How an install holds the rotated keys". Not implemented: the control
plane offering a rotation (`GET /api/release/key-rotation` is the agent's contract, nothing serves
it yet), a cloud-KMS backend, the holder and approver decisions below, the runbook and the lab
drills. Windows and macOS got the same
`--no-default-features` treatment in #855: the MSI build command in `packaging/windows/README.md`,
a scan of `agent.exe` and `watchdog.exe` in `packaging/windows/build.ps1` (not run by any CI job,
it needs WiX), a `tools/assert-no-test-key.sh` step in the two static-agent workflows, and
`tools/check-no-test-key.sh` checking that those flags leave `updater/test-key` off for both
targets. macOS has no package script yet, so its check covers the CI build only.

## Context

Every build today verifies releases and content against one Ed25519 public key derived from a
seed that is checked into the repository (`crates/updater/src/key.rs`, `TEST_KEY_SEED`).
ADR-0015 shipped it that way on purpose and named what must happen before it can stay:

- While `SYNTHAEA_UPDATER_TEST_KEY` is `true`, anyone who can serve `/api/release/*` can sign
  a release that `apply-release` promotes and restarts onto: **root code execution from a
  public key**. The only thing in the way is that the command is manual and refuses to run
  without `--allow-test-key`. The constant must flip, with a real key embedded, **before
  `apply-release` is scheduled, packaged as a timer or documented for operators**.
- The content path (`apply-content-manifest`, ADR-0016) verifies against the same key and has
  no guard. A forged content release cannot run code, but it can weaken detection.
- Rotating *away from a compromised key* is not covered: a compromised key can sign a release
  that says "trust this new key" too. ADR-0015 asks for an out-of-band revocation path (a
  second, offline-held key, or a ban list shipped by the package) and defers it.

The offline `release-tool` (#597) already signs release and content manifests from a key
file of 64 hex characters. It makes no decision about where the real key lives, who may use
it, or how it rotates. ADR-0016 says the production key is HSM-backed and signed by CI/CD or
a release manager, and that is the whole of the plan. This ADR proposes the rest, for the
owner to accept, change or reject; the holders of the keys and the custody technology are the
owner's decisions and are marked as such.

## Decision

1. **An embedded trust set of three Ed25519 public keys, each with one job.**
   - **`release`**: signs binary release manifests. Forging it is root code execution on
     every agent, so it is the most protected key that is used routinely.
   - **`content`**: signs content manifests (rules, models). A different key from `release`
     because the damage of a forgery differs by an order: a stolen content key weakens
     detection, a stolen release key runs code. ADR-0016's "same key" is a development
     shortcut, not a production design.
   - **`recovery`**: held offline, never used for a routine release. It signs only a **key
     rotation release**: a manifest that names a replacement `release` and/or `content` key
     and the keys it retires. A manifest signed by `release` or `content` cannot change the
     trust set. This is the out-of-band path ADR-0015 asked for: a compromised `release` key is
     replaced by a recovery-signed release without touching the endpoints by hand.
   Routine rotation (the planned, uncompromised case) stays as ADR-0015 Decision 4: a release
   signed by the current key names the next one.
2. **Custody.** No private key lives in the repository, on the control plane, or on an
   endpoint (the server never holds one and does not verify signatures; every agent does).
   - `release` and `content`: non-exportable, on a hardware token or a managed key service
     that only signs, used by a release job that needs a second person's approval. *Owner's
     decision: which technology (a PIV token per release manager, a cloud KMS or an HSM), and
     who the approvers are.*
   - `recovery`: generated on an air-gapped machine in a documented ceremony, split between
     named holders (for example 2 of 3) and stored in separate places. Its public half is
     committed; the shares are never online. *Owner's decision: the holders and the places.*
3. **Embedding.** The three public keys are files under `crates/updater/keys/` (hex),
   included at compile time. `SYNTHAEA_UPDATER_TEST_KEY` is derived (`true` only when the
   embedded set is the test set), not a hand-flipped constant. The test seed is compiled in
   only under a `test-key` cargo feature or `cfg(test)`; a build without either has no test
   key, so a release build cannot ship it by omission. A CI job builds the packaged
   binaries and fails if the test key is present.
4. **The guard goes away in the same change.** `--allow-test-key` exists only in a
   `test-key` build. The content path gets the same refusal.
5. **The timer waits.** A periodic `apply-release` and `apply-content-manifest` timer is not
   written, packaged or documented until 1 to 4 are merged and a release signed with the real
   `release` key has been applied on a lab host.
6. **Rotation and compromise are drilled, not assumed.** The runbook includes a rotation of
   `release` (signed by the old key) and a recovery rotation (signed by `recovery`) on a lab
   fleet before the first production release.

## Consequences

- The key-rotation release is a new shape of signed manifest, a sibling type of
  `ReleaseManifest` with its own schema version. That is a change to a signed envelope, so it got
  its own PR and golden fixtures; the format is below ("The key-rotation release").
- `release-tool` has to sign without a key file: the custody choice in 2 decides whether it
  grows a token or KMS backend. #944 added the PKCS#11 one; `--key-file` is restricted to the
  public test keys.
- The residual risk is named: losing or compromising **`recovery`** is not recoverable by an
  update and needs a package reinstall of every endpoint. It is the one key whose compromise
  the update channel cannot repair, which is why it is offline and split.
- Content and binary releases now need two signing identities and two approvals. That is
  the cost of the blast-radius split.
- `docs/operations/` gains a release-signing runbook (ceremony, approvals, rotation, what to
  do on suspected exposure), written with the first real key and not before.

## The key-rotation release

Written with the rotation payload, as owner's decision 5 requires. The type is
`updater::rotation::KeyRotationManifest`; it is verification only, like the content and snapshot
manifests.

**Shape.** One signed JSON document, canonical form as for the other manifests (2-space indent,
alphabetical fields, `signature` forced to `""`, unknown fields refused), signed by `recovery`:
`schema_version`, `release_version`, `issued_at`, `expires_at`, `reason` (audit text, at most 256
bytes), and for each role it changes a pair `new_<role>_key` / `retired_<role>_key` (64 lowercase hex
characters; `null` when the role is not rotated). `<role>` is `release` or `content`: **`recovery`
is never rotated** and a rotation that makes `release` or `content` equal to it is refused.

**Rules, in the order an agent applies them** (`KeyRotationManifest::verify`):

1. A known `schema_version`, and a manifest that is well formed: at least one role rotated, both
   halves of each pair, keys in canonical form and not all zeros, no key replaced by itself, not
   the same new key for both roles (the split of Decision 1 is not undone by a rotation), a
   non-empty reason, and a window of at most 30 days (`MAX_VALIDITY_SECS`, provisional).
2. The Ed25519 signature verifies under the embedded `recovery` key. A `release` or `content`
   signature does not, so **a manifest signed by `release` or `content` cannot change the trust
   set** (Decision 1); a build with no `recovery` key refuses with `SigningKeyUnprovisioned`.
3. The window: not past `expires_at`, and not issued further ahead than 15 minutes of clock skew.
4. `release_version` is strictly greater than the highest release or rotation the agent applied
   (ADR-0015 decision 2, owner's decision 5). A rotation takes a number from the same counter as a
   binary release, so the next release has to go above it.
5. Each retired key **is the key the agent trusts now** for that role. This is what makes a
   rotation apply once and to one state: a replay finds its retired key gone, and a manifest
   written for hosts on an older key does not apply to a host that has moved on. `recovery` signs
   one manifest per key state it needs to move.

**Why `recovery` signs and the new key does not.** The new key is a public half only, so a mistyped
key would leave nobody able to sign releases. That is repairable by the same means as any rotation
(a second one, from `recovery`, retiring the mistyped key), which is why `recovery` is the one key a
rotation cannot touch, and `release-tool rotation` prints what it is about to install.

### How an install holds the rotated keys

The embedded keys are compile-time statics, so a rotation cannot change them. An install records
**the signed rotation manifests themselves** in `<state_dir>/key-rotations.json` (written
atomically, at most 64 entries). Every load replays that record from the embedded keys and
re-verifies each manifest under the embedded `recovery` key, so the record cannot introduce a key
`recovery` did not sign. The keys in force are "embedded, then each recorded rotation, in order";
for each role a rotation changes:

- the key in force is the one the rotation retires: apply it;
- the key in force is already the one it installs, or one a later rotation installs (a newer
  build embeds keys the record is behind): skip it, the embedded key is ahead;
- anything else: the record does not lead from these keys, and the load fails.

| The record is | What happens |
|---|---|
| **absent** | A fresh install: the embedded keys. |
| **older than the embedded keys** (a package upgrade embedded a key the record is behind) | The embedded key stays in force, the record's highest `release_version` still counts. A role never moves backward: the key in force is always the embedded one or one `recovery` signed after it. |
| **newer than the embedded keys** (an older build over a rotated install) | The record moves the roles forward to the keys it recorded. |
| **corrupt** (does not parse, a manifest fails verification, versions not increasing, built for other embedded keys, roles collapsed) | **Refused, never a fallback**: `apply-release`, `apply-content-manifest` and `check-content-manifest` stop before the network, and the integrity check raises a tamper event. A file that exists proves a rotation happened, and the embedded keys may be ones that were rotated away from. The operator removes the file on purpose, knowing what that re-trusts. |

**Residual risk, named.** Deleting the file on an install that rotated puts the embedded (possibly
retired) keys back in force. That needs write access to the state directory, which is root's, the
same boundary as the ban list and the content state (an attacker with it can already replace the
agent). A package that re-embeds the rotated keys closes it for that fleet.

Other rules the wiring settles:

- **One counter.** The highest recorded rotation's `release_version` is a floor for releases:
  `apply-release` treats a release numbered at or below it as not newer.
- **The window is checked when a rotation is applied, not when the record is replayed**: a
  rotation applied while valid stays applied after it expires.
- **Self-integrity accepts every `release` key the install has trusted** when it re-checks the
  manifest of an already promoted release, because that manifest was signed by the key in force
  when it was promoted. It is a re-check of a file on disk, never an approval of anything new;
  a manifest signed by a key the install never trusted is still a tamper event.
- **A test-key build that rotated a role away from the public test key** no longer needs
  `--allow-test-key` for that role. `apply-key-rotation` itself needs it while `recovery` is the
  public test key, like the other commands.
- **Content keeps its own counter** (per ring); only binary releases share the rotation's.

### Comparison with TUF's threshold and expiry rules

TUF (the specification's root metadata) rotates keys with a signed `root` role: each role lists
`keyids` and a `threshold`; a new root must be signed by a threshold of the keys in the **current**
root and also by a threshold of the keys in the **new** root; its `version` must be exactly one
above the current one, so a client walks every root in sequence; every metadata file has an
`expires` date and a client refuses expired metadata. What this ADR does with each:

| | TUF | This rotation | Consequence |
|---|---|---|---|
| Threshold | `m` of `n` keys, enforced by the client, each signature attributable | The agent checks **one** Ed25519 signature under one `recovery` key. "2 of 3" (decision 3) is how the key is *held*, split between holders and rebuilt for the ceremony | Compromising two holders or the ceremony machine compromises `recovery`, and the fleet cannot tell one signer from three. TUF would let a holder be removed by a root rotation without touching the other two; here a changed holder means a new `recovery` key and so a reinstall (decision 3's accepted risk). Kept because the trust set has one key per role and `recovery.pub` is one file |
| Signature by the new key | The new root must also be signed by the new keys (proof of possession) | Not required | A mistyped new key is possible; repaired by a second rotation (above) |
| Version rule | Exactly `current + 1` for `root`: no root can be skipped | Strictly greater than the highest applied, gaps allowed | A rotation shares the release counter, which moves on binary releases between rotations, so "exactly one above" cannot hold. The retired-key rule (5) gives the "no skipping a state" property TUF's chain gives: a rotation only applies to the state it was written for |
| Expiry | Every file expires; a client refuses an expired one. Forces the signers to re-sign periodically | Each rotation has `expires_at`, at most 30 days after `issued_at`; the root of trust itself does not expire | Without an expiry, an old rotation `K1 → K2` could be served years later to a host still on `K1` (offline, or held back by an attacker) after `K2` was compromised and rotated away: the host would move to the compromised `K2`. The window closes that for rotations. It does **not** make `recovery` sign routinely, which TUF's root expiry does and which would defeat keeping it offline |
| Roles and delegation | `root`, `targets`, `snapshot`, `timestamp`, delegations | Roles by key: `release`, `content`, with `snapshot` and `posture` outside the rotation | Smaller than TUF by design |

What remains open and is accepted: within its window a rotation held back by an attacker can still
be applied late; an offline fleet that outlives a window needs a new manifest from `recovery` for its
key state, or a reinstall; the lab drill (decision 6) must calibrate 30 days.

**When to revisit TUF** (owner's decision 5): the rotation format grows beyond one signed payload;
or the holders want signatures the fleet can attribute and count (a trust set with several
`recovery` keys and a threshold the agent enforces); or `recovery` itself has to rotate.

## Alternatives considered

- **One key in a managed key service, no recovery key.** The simplest, and acceptable to an
  owner who accepts that a compromise means a reinstall. It leaves exactly the gap ADR-0015
  deferred, and on a fleet that reinstall is the incident.
- **The Update Framework (TUF).** What this proposes is a small subset of it (a root of trust
  that can rotate the signing keys, with roles by key). Adopting TUF's metadata, its
  expiry and threshold rules and its tooling would avoid inventing the rotation format, at
  the cost of a larger envelope than ADR-0015's and a dependency on its client logic. Worth
  evaluating before the rotation payload is designed; this ADR does not exclude it. Owner's
  decision 5 (2026-10-21): not adopted now.
- **Threshold signatures (for example FROST) for `release`.** Removes the single signer
  without a second key, at the cost of cryptography the workspace does not use today and
  tooling that is young. Not proposed now.
- **Keyless signing (Sigstore-style).** Trusts an online identity provider and transparency
  log at verification time; an agent that must verify offline against embedded keys does not
  fit it.
- **Keep one embedded key for both release and content.** Smallest change, and the reason this
  ADR splits them: it makes the lowest-value forgery as dangerous as the highest.

## Owner's decisions, 2026-10-21

Taken by the owner, who delegated the design choices to the author of this change; the reviewers
of this change can contest them. They decide the design only. **They do not name a person, an
account or a device, and no key may be generated before the open points below are settled.**

1. **The trust set is the three keys of Decision 1, unchanged.** `snapshot` (ADR-0033) and
   `posture` (ADR-0035) are **separate keys that only sign**, never shared with `release`,
   `content` or `recovery` and never with each other.
2. **Technology for `release` and `content`: `release-tool` grows a PKCS#11 backend first.** It
   covers a PIV token and an HSM, keeps the tool offline (#597), and needs no cloud account. A
   cloud-KMS backend is added only if the organisation has such an account; `--key-file` stays
   reserved to the test key. The backend is built and tested against a software token before any
   real key exists.
3. **`recovery` is generated and held as Decision 2 says, split 2 of 3,** with its public half
   committed. The holders and the places are not decided here.
4. **A signing-only service for `snapshot` and `posture` is accepted** (ADR-0033 decision 1,
   ADR-0035 owner's decision 1), under three constraints: the set of documents it may sign is
   fixed in its code (a snapshot manifest, a posture overlay), it applies a per-tenant rate
   limit, and every signature is audited. It reuses the signer abstraction of point 2. The
   `snapshot` loop stays gated on tenant binding (ADR-0033 decision 3). If this point is
   refused, the fallback of both ADRs applies: no automatic overlays, only analyst-approved ones
   signed offline.
5. **TUF is not adopted now.** The rotation release keeps the shape of Decision 1 (a subset of
   TUF: roles by key, a root of trust that can rotate them). The change that designs the rotation
   payload must carry a written comparison with TUF's threshold and expiry rules, and a rotation
   release carries a `release_version` like any release (anti-rollback, ADR-0015). TUF is
   revisited if the rotation format grows beyond one signed payload.

**Still open, and not decidable by design** (they are facts about people and accounts): who the
release managers and the approvers are, and how many approvals a release needs; who holds a
`recovery` share and in which places; whether a cloud account or an HSM exists; who owns the
signing service's policy. Until then there is no real key, no runbook (this ADR says it is
written with the first real key) and no lab drill, and #754 stays unwritten (Decision 5).

What this unblocks, without any key: the key-rotation release against a test recovery key (with
golden fixtures), and the `release-tool` PKCS#11 backend against a software token.

## Follow-up issues (to open if this is accepted)

1. Key ceremony and custody setup for the three keys (owner, holders, technology).
2. (Done, #761 and #855.) Embedded trust set, the `test-key` feature, derived
   `SYNTHAEA_UPDATER_TEST_KEY`, the CI check that a packaged build has no test key, and removal of
   the guard for production builds.
3. (Done in #753, this change: the format, the verification, the golden fixture, `release-tool`
   building and signing it. Not done: the agent applying it, see Implementation status.) The
   key-rotation release: manifest shape, verification rules (which key may change which),
   golden fixtures, anti-rollback interaction (a rotation has a `release_version` like any
   release).
4. `release-tool` signing backends: the PKCS#11 backend first, a cloud-KMS one only if an account
   exists.
5. The release-signing runbook and the lab rotation drill.
6. The periodic timer units, after the above.

## References

- ADR-0015 (Decision 4 and Deferred), ADR-0016 (content signing workflow), ADR-0010 (the
  signed-document pattern); `crates/updater/src/key.rs`; `release-tool` (#597); #30.
