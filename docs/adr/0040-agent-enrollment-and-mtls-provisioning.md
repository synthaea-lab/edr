# ADR-0040: Agent enrollment and mTLS certificate provisioning

- **Status**: proposed
- **Date**: 2026-10-29

## Context

Every agent-to-server connection is already authenticated by mTLS, and the server side of
that is fully built: nginx terminates TLS and forwards `X-Client-Cert-Verified`/
`X-Client-Cert-Subject`; `server/lib/agent-auth.ts`'s `authenticateAgent` reads an
`enrollmentId` out of the certificate's CN (`extractEnrollmentId`) and looks it up against
`Agent.enrollmentId` (`@unique`, `server/prisma/schema.prisma:46`). `docs/architecture/
control-plane.md`'s heartbeat contract is explicit that this is the *only* identity that
counts: `agent_id` in a request body is `null` today and is "never trusted" — correctly,
since trusting a self-reported field over the verified certificate would be the actual
vulnerability. None of that is in question here.

What is missing is everything upstream of a certificate existing. Today, per
`docs/operations/binary-releases.md`'s description of `agent run`'s upload path:
`server.mtls_cert`/`server.mtls_key` are config fields the agent loads from disk — present
or absent, valid or not. Nothing in this codebase issues one, stores one anywhere durable,
or rotates one before it expires. An operator must place a cert/key pair on a host by hand,
through whatever deployment tooling they already use, before that host's telemetry reaches
the control plane at all. `docs/architecture/control-plane.md`'s own header promises an
"enrollment/PKI" section "recorded here once made" — it is still a stub. Issue #314 named
this gap in September; two of its three original bullets turned out to already be resolved
by the design above (see the issue's own 2026-10-29 reconciliation comment), leaving this one.

This is a bootstrap-trust problem in the same family as ADR-0015's Decision 7 ("day 0, the
installer's job"), but not the same shape: ADR-0015's day-0 trust is about binaries already
sitting on local disk, verified once by whoever ran the installer. Enrollment is about a
host establishing trust with a server **over the network**, for the first time, with nothing
local to anchor to yet except whatever an operator chooses to hand it. The two problems
share a root concern (what does the very first trusted thing rest on) but need their own
answer.

**Self-hosting constrains the answer** (ADR-0001: "self-hosting stays a docker-compose,
matching the self-hosting goal"). Whatever issues agent certificates has to be something a
customer's own deployment owns and runs — not a certificate authority Synthaea-the-company
operates centrally, which would make every self-hosted customer's fleet depend on an
external service neither they nor this ADR controls.

**This is not the same key-custody problem ADR-0027 already solved.** ADR-0027's `release`/
`content`/`recovery` keys sign manifests entirely offline (`release-tool`, run by a human with
an HSM or a PKCS#11 token) — the private key never needs to be reachable by the running
server, because signing happens out of band before a manifest is ever published, and the
server only ever serves bytes it did not sign. An enrollment CA cannot work that way: it has
to sign a certificate synchronously, in response to a live HTTP request, while the server is
up — "the signing key is never on the control plane" is not an available answer here the way
it was for ADR-0027. The threat model differs accordingly: a compromised `release` key is root
code execution on every agent; a compromised enrollment CA key lets an attacker mint a
certificate that impersonates a *new* agent to *this one tenant's* server — serious, but not
the same order of damage, and already bounded by the fact that a self-hosted deployment's
server process is already trusted with that tenant's database, cases, and every detection in
it. Holding the CA key at the same trust level as the server process it runs inside of is a
narrower ask than ADR-0027's, not a weaker version of the same one.

## Decision

1. **Scope**: how a freshly-installed agent, with no certificate yet, obtains one; how it
   renews one before expiry; and who signs it. Does not cover: the release/content signing
   keys (ADR-0027, unaffected), the better-auth/tenant/organization model (#821/#829, reused
   as-is), or transport's existing upload/heartbeat/fetch mechanics (unaffected — this ADR
   only adds how the certificate those already use gets onto the host).

2. **A per-deployment CA, generated once, self-hosted with everything else.** Each
   self-hosted instance generates its own root CA keypair at first setup (a `docker-compose`
   init step or an explicit `synthaea-ctl init-ca`-style one-shot command — naming the exact
   mechanism is implementation detail, not decided here) and stores the private key the same
   place the deployment already keeps its other server-side secrets (the database connection
   string, better-auth's own secret — whatever that convention already is, reused rather than
   inventing a second one). This key is held by the running server process, deliberately
   unlike ADR-0027's keys, for the reason in Context: enrollment has to sign on demand. The
   CA's public certificate is what nginx is configured to trust for client-certificate
   verification — the same trust anchor documented today in `docs/operations/binary-
   releases.md` for the *agent's* side (`server.ca_cert`), generated by this deployment
   instead of handed to an operator to produce by some unspecified means.

3. **Enrollment: a shared, time-boxed, usage-capped token; the agent generates its own
   keypair.** An admin (an authenticated console session, same tenant/org model as #829)
   creates an enrollment token scoped to their tenant: a random secret, an expiry, and a
   usage cap (more than 1 — a fleet deployed from one golden image or one deployment script
   enrolls many hosts with the same token in a short window; unlimited reuse forever would
   make the token a long-lived shared secret, which defeats the point). How the token
   physically reaches the new host is the operator's existing deployment tooling's problem,
   exactly as it already is for today's manual certificate file — this ADR does not change
   who is responsible for that step, only what the host does once the token is there.
   A new one-shot agent subcommand, `agent enroll --token <token> --server <url>` (matching
   the existing one-shot style of `apply-release`/`apply-content-manifest`, ADR-0015's
   amendment), generates a local keypair (the private key is created on the host and never
   transmitted anywhere), builds a CSR naming a server-chosen, random `enrollmentId` — a
   UUID, never the hostname: a hostname can collide, change, or be attacker-influenced, and
   `Agent.enrollmentId` is already `@unique`, so a collision is a hard failure this ADR does
   not want to make possible by picking a weaker identifier — and POSTs the CSR plus the
   token to a new `/api/v1/enroll` endpoint (reachable over plain TLS, not mTLS: there is no
   client certificate yet, by construction; the token is the credential for this one call).
   The server validates the token (not expired, under its usage cap), creates the `Agent` row
   with the CSR's `enrollmentId`, signs the CSR with the deployment's CA (Decision 2),
   decrements the token's remaining uses, and returns the signed certificate. `agent enroll`
   writes it, and the private key it already generated, to the paths `server.mtls_cert`/
   `server.mtls_key` already name — `agent run` needs no change at all; it already loads
   whatever is at those paths.

4. **Renewal authenticates with the certificate being renewed, not a new token.** Before
   expiry, `agent enroll --renew` (or a periodic trigger — #754's own timer work, applicable
   here too, once it ships) connects **with its current, still-valid mTLS certificate** to a
   renewal endpoint and receives a freshly-signed certificate for the same `enrollmentId`,
   same key or a freshly rotated one. No token is involved: the existing certificate is
   already proof of enrollment. If the certificate has already expired — a host offline past
   its renewal window — there is nothing valid left to authenticate a renewal with, and the
   host falls back to needing a fresh enrollment token, an operator action, same as a first
   install. This is not a new failure mode: `docs/operations/binary-releases.md` already
   documents `offline_fallback` (default `true`) for exactly "a host without certificates" —
   a host with an expired one degrades into that same, already-designed path (local
   detection continues, `UPLOAD-DISABLED` is logged) rather than needing new behavior here.

5. **A token is revocable; a certificate is not, yet.** An admin can delete an unused or
   still-valid enrollment token from the console at any time (it is a server-side row with a
   usage count and an expiry — nothing more). Revoking an already-issued *certificate* before
   its natural expiry (a decommissioned host, a suspected-compromised one) is a real,
   needed capability this ADR does not design: it needs either short-lived certificates with
   frequent forced renewal (cheap to build, but makes every renewal-endpoint outage a
   fleet-wide near-term authentication failure) or a revocation list nginx's mTLS verification
   checks on every connection (a new piece of infrastructure, and a performance question at
   fleet scale) — a real design decision with real trade-offs, not a detail to wave through
   here. Deferred, with the consequence spelled out below.

## Consequences

- `server/app/api/v1/enroll/route.ts` (new): the one unauthenticated-by-certificate endpoint
  in the ingest/release family, by necessity — token-authenticated instead. Needs the same
  care `/api/ingest/*`'s existing proxy-secret check already takes about what is and is not
  spoofable ahead of the nginx boundary.
- A new `EnrollmentToken` model (tenant-scoped, expiry, usage cap/count) and the console UI
  to create and list them — the only new piece of UI this ADR requires; everything else is
  agent-side or a one-shot endpoint.
- `agent enroll`/`agent enroll --renew`: new one-shot subcommands, `updater`-adjacent in style
  but not in that crate (no manifest, no signature, no rollback — a CSR and a cert, nothing
  staged) — probably its own small module, named here as `enroll` for discussion, not fixed.
- The CA private key moves the server process's own trust boundary slightly wider than
  ADR-0027's keys ever did (Context) — this is a deliberate, scoped exception to "no private
  key lives on the control plane," not a precedent for weakening that rule elsewhere. Any
  future key this project adds should default to ADR-0027's offline posture unless it has
  the same "must sign online, synchronously" requirement this one does.
- `docs/architecture/control-plane.md` gains the "enrollment/PKI" section its header has
  promised since before this ADR existed.
- Issue #314 narrows to exactly this ADR once accepted; its other two bullets are already
  closed by existing code, per its 2026-10-29 reconciliation comment.

## Deferred

- **Certificate revocation before natural expiry** (Decision 5) — a real gap this ADR
  knowingly leaves open: a decommissioned or compromised host's certificate stays valid
  until it expires. The practical mitigation until this is designed is keeping certificate
  lifetimes short enough that this window is tolerable, which is itself a decision (how
  short, traded against how much load frequent renewal puts on the enrollment path) not
  made here.
- **The CA private key's own custody mechanics** (Decision 2) — "store it the way the
  deployment already stores its other secrets" names a posture, not an implementation; which
  secret-storage convention that actually is depends on how `docker-compose`/self-hosting
  config already works, which this ADR does not re-derive.
- **CA rotation** — if the deployment's own CA key is ever rotated (suspected compromise, a
  long-lived deployment's routine hygiene), every already-issued agent certificate needs a
  story for staying trusted or being re-issued against the new CA. Not designed here; the
  new CA endpoint and `--renew` give a mechanism a future design could build on, but the
  actual rotation procedure is not this ADR's job.
- **Multi-server / high-availability deployments** — this ADR assumes the CA key is held by
  "the server process," singular. A deployment running more than one server instance behind
  a load balancer needs the signing capability (and the key) reachable from whichever
  instance handles a given enrollment request; not addressed, since the project's current
  self-hosting story (ADR-0001) is one deployable.

## References

- Issue #314 — the issue this ADR narrows and (once accepted) resolves.
- ADR-0015 — Updater: staged self-update, manifest signing, and rollback — Decision 7's
  "day 0, the installer's job" is the bootstrap-trust problem this ADR's own bootstrap
  problem is related to but distinct from (Context).
- ADR-0027 — Production signing keys for releases and content — the key-custody model this
  ADR deliberately does not reuse for the CA key, and why (Context).
- ADR-0001 — Server stack (Next.js + PostgreSQL) — the self-hosting goal that rules out a
  centrally-operated CA (Context).
- `server/lib/agent-auth.ts`, `server/lib/tenant.ts` — the existing, unaffected
  certificate-verification path this ADR provisions a certificate *for*.
- `docs/operations/binary-releases.md` — today's manual certificate loading and the
  `offline_fallback` degrade path Decision 4's expired-certificate case reuses as-is.
- `docs/architecture/control-plane.md` — the heartbeat/ingest contract doc this ADR's
  "enrollment/PKI" section (once written) belongs in.
