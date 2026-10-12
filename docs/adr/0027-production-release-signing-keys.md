# ADR-0027: Production signing keys for releases and content: a trust set, custody, and a recovery path

- **Status**: proposed
- **Date**: 2026-10-06

## Implementation status

Decision items 3 and 4 are implemented (#753): `crates/updater/keys/{release,content,recovery}.pub`
(`unprovisioned` until the ceremony), the `test-key` feature on `updater`, `agent` and
`release-tool` (default on for development and the lab), `SYNTHAEA_UPDATER_TEST_KEY` derived from
it, `--allow-test-key` only in a `test-key` build and now also required by
`apply-content-manifest`, a build without the feature or a key refusing with a clear error, and
`tools/check-no-test-key.sh` in CI. Not implemented: the `recovery` verification and the rotation
release (a separate PR with golden fixtures), `release-tool` custody backends, the custody and
holder decisions below, the runbook and the lab drills. Windows and macOS packaging still build
with the default features, so they carry the test set until they get the same `--no-default-features`
treatment.

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

- The key-rotation release is a new shape of signed manifest: `ReleaseManifest` gains a
  rotation payload (or a sibling type) and the schema version moves. That is a change to a
  signed envelope, so it gets its own PR and golden fixtures; this ADR does not specify the
  bytes.
- `release-tool` has to sign without a key file: the custody choice in 2 decides whether it
  grows a token or KMS backend. Until then it keeps `--key-file` for the test key only.
- The residual risk is named: losing or compromising **`recovery`** is not recoverable by an
  update and needs a package reinstall of every endpoint. It is the one key whose compromise
  the update channel cannot repair, which is why it is offline and split.
- Content and binary releases now need two signing identities and two approvals. That is
  the cost of the blast-radius split.
- `docs/operations/` gains a release-signing runbook (ceremony, approvals, rotation, what to
  do on suspected exposure), written with the first real key and not before.

## Alternatives considered

- **One key in a managed key service, no recovery key.** The simplest, and acceptable to an
  owner who accepts that a compromise means a reinstall. It leaves exactly the gap ADR-0015
  deferred, and on a fleet that reinstall is the incident.
- **The Update Framework (TUF).** What this proposes is a small subset of it (a root of trust
  that can rotate the signing keys, with roles by key). Adopting TUF's metadata, its
  expiry and threshold rules and its tooling would avoid inventing the rotation format, at
  the cost of a larger envelope than ADR-0015's and a dependency on its client logic. Worth
  evaluating before the rotation payload is designed; this ADR does not exclude it.
- **Threshold signatures (for example FROST) for `release`.** Removes the single signer
  without a second key, at the cost of cryptography the workspace does not use today and
  tooling that is young. Not proposed now.
- **Keyless signing (Sigstore-style).** Trusts an online identity provider and transparency
  log at verification time; an agent that must verify offline against embedded keys does not
  fit it.
- **Keep one embedded key for both release and content.** Smallest change, and the reason this
  ADR splits them: it makes the lowest-value forgery as dangerous as the highest.

## Follow-up issues (to open if this is accepted)

1. Key ceremony and custody setup for the three keys (owner, holders, technology).
2. Embedded trust set, the `test-key` feature, derived `SYNTHAEA_UPDATER_TEST_KEY`, the CI
   check that a packaged build has no test key, and removal of the guard for production builds.
3. The key-rotation release: manifest shape, verification rules (which key may change which),
   golden fixtures, anti-rollback interaction (a rotation has a `release_version` like any
   release).
4. `release-tool` signing backends for the chosen custody.
5. The release-signing runbook and the lab rotation drill.
6. The periodic timer units, after the above.

## References

- ADR-0015 (Decision 4 and Deferred), ADR-0016 (content signing workflow), ADR-0010 (the
  signed-document pattern); `crates/updater/src/key.rs`; `release-tool` (#597); #30.
