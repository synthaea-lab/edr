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

2. **A per-deployment CA, generated once, self-hosted with everything else, scoped to one
   job only: signing agent client certificates.** Each self-hosted instance generates its
   own root CA keypair at first setup (a `docker-compose` init step or an explicit
   `synthaea-ctl init-ca`-style one-shot command — naming the exact mechanism is
   implementation detail, not decided here) and stores the private key the same place the
   deployment already keeps its other server-side secrets (the database connection string,
   better-auth's own secret — whatever that convention already is, reused rather than
   inventing a second one). This key is held by the running server process, deliberately
   unlike ADR-0027's keys, for the reason in Context: enrollment has to sign on demand.
   The CA's public certificate becomes nginx's `ssl_client_certificate`
   (`server/nginx.conf:29`, today a pre-placed `ca.crt`) — the CA nginx trusts to verify an
   *incoming agent's* client certificate. **It is not, and must not become, what an agent
   trusts to verify the *server*.** That is `server.ca_cert`
   (`docs/operations/binary-releases.md`), which verifies nginx's own listener certificate
   (`ssl_certificate`/`server.crt`, `nginx.conf:25`) — a separate credential, provisioned
   however this deployment's public-facing TLS already is (a real domain's ACME
   certificate, or an operator-supplied one; orthogonal to this ADR, unchanged by it).
   Collapsing these two into one CA was an earlier draft's mistake (review of #314's ADR):
   a leaked enrollment-CA key would then also mint a certificate that *agents* accept as
   *the server*, turning "impersonate one new agent" into "run a MITM every already-enrolled
   agent trusts" — a materially larger blast radius than Context's "bounded" claim allows
   for. Keeping them separate is what makes that claim true. The CA this ADR creates issues
   nothing but agent client certificates, is constrained to that at signing time (Decision
   3), and every certificate it issues is logged (`AuditLog`, same table and shape as every
   other privileged action) — "bounded by the server's existing trust" holds only because
   of those constraints, not merely because the key lives at the same privilege level as the
   server process.

3. **Enrollment: a shared, time-boxed, usage-capped token; the agent generates its own
   keypair; the server, never the agent, picks the identity.** An admin (an authenticated
   console session, same tenant/org model as #829) creates an enrollment token scoped to
   their tenant: a random secret, an expiry, and a usage cap (more than 1 — a fleet deployed
   from one golden image or one deployment script enrolls many hosts with the same token in
   a short window; unlimited reuse forever would make the token a long-lived shared secret,
   which defeats the point). How the token physically reaches the new host is the operator's
   existing deployment tooling's problem, exactly as it already is for today's manual
   certificate file — this ADR does not change who is responsible for that step, only what
   the host does once the token is there.

   A new one-shot agent subcommand, `agent enroll --token <token> --server <url>` (matching
   the existing one-shot style of `apply-release`/`apply-content-manifest`, ADR-0015's
   amendment), generates a local keypair — the private key is created on the host and never
   transmitted anywhere — and builds a CSR carrying that public key. The CSR's requested
   subject is not trusted and is not the identity mechanism: **the server generates the
   random `enrollmentId` UUID itself**, on successful token validation, and signs the
   certificate with that server-chosen CN regardless of what the CSR asked for (any
   requested subject or SAN is discarded at signing, not merely ignored by convention — the
   signing step itself overwrites it). An earlier draft of this ADR had the agent choose the
   `enrollmentId` and the server merely accept it, which is self-defeating: a token holder
   could request a colliding or spoofed identity (`Agent.enrollmentId` is `@unique`, so a
   collision is a live hard-failure, not a theoretical one) and the server nevertheless
   trusted the request. The agent learns its own `enrollmentId` only from the certificate it
   gets back (parsed from the returned CN), the same way it already learns nothing about its
   own identity ahead of time today.

   The call target is `POST /api/v1/enroll`, reachable without a client certificate — there
   isn't one yet, by construction — but **not reachable without verifying the server**:
   `agent enroll` uses the exact same `server.ca_cert`/`--ca-cert` mechanism `apply-release`
   and `apply-content-manifest` already use today (`docs/operations/binary-releases.md`) to
   verify the TLS certificate `/api/v1/enroll` presents, before it ever sends the token. This
   is not a new mechanism to design: the operator already has to hand a new host its
   `server.ca_cert` bundle for every other one-shot command to work at all (it's a required
   `[server]` config field already), so handing it over alongside the enrollment token costs
   nothing new and closes the "agent trusts whatever answers" gap a bare, unauthenticated TLS
   connection would otherwise leave open. `--token` also accepts `--token-file <path>` or `-`
   (read from stdin) as alternatives to the bare argument, so an operator's deployment script
   is not forced to leave the secret sitting in `ps` output and shell history — `--token`
   itself stays available for interactive use, where that risk is already the operator's to
   manage.

   Server-side, one request does, in a single database transaction: validates the token
   (hashed lookup — tokens are stored hashed, never in plaintext, same posture as any other
   bearer secret this project stores) and atomically decrements its remaining-uses counter in
   the same statement that checks it is still positive and unexpired (a conditional
   `UPDATE ... WHERE uses_remaining > 0 AND expires_at > now() RETURNING ...`, not a
   check-then-decrement in two steps) — so two concurrent enrollments against a
   one-remaining-use token cannot both succeed, regardless of request ordering; generates the
   `enrollmentId`; creates the `Agent` row; signs the CSR with the deployment's CA, with the
   signing call itself constrained to this CA's one job (Decision 2) — client-auth key usage
   only, no `CA:TRUE`, a capped certificate lifetime (Decision 4); and writes one `AuditLog`
   row for the issuance. A signing failure after a successful decrement burns that use rather
   than leaking an extra one past the cap — an accepted, bounded cost, not a correctness gap.
   `/api/v1/enroll` is rate-limited per source address (nginx's existing `limit_req_zone`
   mechanism, `nginx.conf:14`'s `cron` zone is the precedent to mirror), since it is, by
   necessity, the one agent-facing endpoint with no certificate to key a cost on. The server
   returns the signed certificate; `agent enroll` writes it, and the private key it already
   generated, to the paths `server.mtls_cert`/`server.mtls_key` already name — `agent run`
   needs no change at all; it already loads whatever is at those paths.

4. **Concrete lifetime, renewal window, and a cheap revocation check on both.** A signed
   certificate is valid 30 days; `agent enroll --renew` (or a periodic trigger — #754's own
   timer work, applicable here too, once it ships) is expected to run by day 20, a 10-day
   lead — generous enough that a control-plane outage has to run longer than ten days before
   any agent is actually at risk of hitting its hard expiry, and staggered fleet renewal
   times mean a shorter outage affects none of them. These are config defaults, not
   hardcoded forever, but they are *stated*: Decision 5's original text left both unset and
   called the trade-off a future decision, which left this ADR's own renewal design
   unimplementable (review of #314's ADR) — a number has to exist for "the server was down
   longer than the cert lifetime" to even be a question with an answer.

   `agent enroll --renew` connects **with its current, still-valid mTLS certificate** to a
   renewal endpoint and receives a freshly-signed certificate for the same `enrollmentId`,
   same key or a freshly rotated one. No token is involved: the existing certificate is
   already proof of enrollment — **but only if the `Agent` row behind it is not revoked.**
   Both the renewal endpoint and `authenticateAgent` (the single existing chokepoint every
   agent-facing route already calls, per Context) check a new `Agent.revoked` boolean before
   accepting the certificate for anything. This makes revocation genuinely cheap to add: no
   new DB round trip (the row is already fetched by `enrollmentId` on every authenticated
   call), no CRL, no short-lived-certificate scheme — an admin flips one flag from the
   console, and the next request *of any kind* from that host, renewal included, is refused.
   It is not TLS-layer revocation: nginx's mTLS handshake itself has no opinion on
   `Agent.revoked` and completes normally for a revoked certificate right up to the
   application layer, where every route that matters already stops it. That boundary — and
   the fact that it depends on every agent-facing route actually going through
   `authenticateAgent`, which Context already establishes as true today — is the honest
   shape of this mitigation, not a CRL's or a short-lived-certificate scheme's, and it
   substantially narrows what Decision 5 below still has to leave open.

   If the certificate has already expired — a host offline past its renewal window — there
   is nothing valid left to authenticate a renewal with, and the host needs a fresh
   enrollment token, an operator action, same as a first install. `docs/operations/
   binary-releases.md`'s `offline_fallback` (default `true`) already covers "a host without
   certificates" this way; a host with an expired one degrades into the same path. Stated
   fully rather than just by its `UPLOAD-DISABLED` log line: that fallback stops *every*
   server interaction this ADR's design depends on, not only upload — content-manifest and
   release fetches stop too, so a long-offline host also stops receiving new detection
   content and agent updates until it is re-enrolled, not only losing its own telemetry
   upload. A fresh enrollment after expiry does not have to mean a fresh identity, either: an
   enrollment token can optionally be scoped to a specific, already-known `Agent` (an
   operator picks "reissue for this host" in the console rather than "new enrollment" when
   creating the token) — the server then rotates that existing row's `enrollmentId` to the
   newly-minted one instead of inserting a new row. Every relation that matters
   (`AgentHealth`, `Detection`, cases, decoy tokens) already keys off `Agent.id`, the stable
   row identity, never `enrollmentId` — so this preserves a host's full history across
   re-enrollment, and a token *not* scoped to an existing agent still creates a fresh row,
   exactly as a genuine first install should.

5. **A token is revocable outright; a certificate is revocable at the application layer, not
   the TLS layer.** An admin can delete an unused or still-valid enrollment token from the
   console at any time (it is a server-side row with a usage count and an expiry — nothing
   more). For an already-issued *certificate*, Decision 4's `Agent.revoked` flag is this
   ADR's actual answer for a decommissioned or suspected-compromised host: every request that
   matters is refused the moment it's set, with no wait for expiry. What is still, genuinely,
   not designed here is TLS-layer revocation — nginx completing a nominally-successful mTLS
   handshake with a revoked certificate before the application layer ever sees the request.
   Closing that needs either a revocation list nginx's own mTLS verification checks on every
   connection (new infrastructure, and a performance question at fleet scale) or short enough
   certificate lifetimes that the handshake succeeding is cheap to tolerate — Decision 4's
   30-day default is sized for availability against a control-plane outage, not tuned as a
   revocation-latency bound, and nothing here claims it is one. That gap — a revoked host can
   still complete a TLS handshake it can do nothing useful with — is what's deferred, not the
   whole of "can revocation happen before expiry," which Decision 4 already answers.

## Consequences

- `server/app/api/v1/enroll/route.ts` (new): the one agent-facing endpoint with no client
  certificate at all, by necessity. Concretely, not just "needs the same care": a new
  `location /api/v1/enroll` block in `server/nginx.conf`, alongside the existing
  `/api/v1/ingest/` one, that does *not* add the `if ($ssl_client_verify != "SUCCESS")`
  check those neighboring blocks have (`nginx.conf:59-68`) — everything else about it is
  unchanged from the pattern already there: `proxy_set_header X-Client-Cert-Verified
  $ssl_client_verify` still runs server-block-wide (`nginx.conf:33`) and always carries
  nginx's own computed value, never a client-suppliable one, so the backend correctly sees
  "no cert" with no special-casing needed; `X-Proxy-Secret` (`nginx.conf:45`) is still
  attached the same as every other route. A new `limit_req_zone`
  (`nginx.conf:14`'s `cron` zone is the existing precedent) bounds it per source address.
  `server/middleware.ts` gets one more exact-path exemption
  (`req.nextUrl.pathname === "/api/v1/enroll"`, alongside `/api/release/manifest` and its
  siblings, `middleware.ts:20-23`) so it bypasses the browser-session check the same way —
  `stripIdentityHeaders` still runs on that branch, so a client-supplied identity header is
  dropped here exactly as it already is on every other public path.
- A new `EnrollmentToken` model (tenant-scoped, expiry, usage cap/count, hashed secret, and
  an optional `agentId` for a token scoped to re-enrolling a specific host rather than
  minting a new one — Decision 4) and the console UI to create and list them — the only new
  piece of UI this ADR requires; everything else is agent-side or a one-shot endpoint.
- `Agent.revoked: Boolean` (default `false`) and `revokedAt`, checked by `authenticateAgent`
  and the renewal endpoint (Decision 4) — console gets a "revoke" action alongside each
  agent, the cheap partial answer to certificate revocation this ADR actually ships.
- `agent enroll`/`agent enroll --renew`: new one-shot subcommands, `updater`-adjacent in style
  but not in that crate (no manifest, no signature, no rollback — a CSR and a cert, nothing
  staged) — probably its own small module, named here as `enroll` for discussion, not fixed.
  `--token` accepts a bare argument, `--token-file <path>`, or `-` for stdin.
- The CA private key moves the server process's own trust boundary slightly wider than
  ADR-0027's keys ever did (Context) — this is a deliberate, scoped exception to "no private
  key lives on the control plane," not a precedent for weakening that rule elsewhere. Any
  future key this project adds should default to ADR-0027's offline posture unless it has
  the same "must sign online, synchronously" requirement this one does. Its blast radius
  depends on the CA doing only one job — client-auth certificates, nothing else, every
  issuance audited — not on the key's storage location alone (Decision 2).
- `docs/architecture/control-plane.md` gains the "enrollment/PKI" section its header has
  promised since before this ADR existed.
- Issue #314 narrows to exactly this ADR once accepted; its other two bullets are already
  closed by existing code, per its 2026-10-29 reconciliation comment.

## Deferred

- **TLS-layer certificate revocation** (Decision 5) — `Agent.revoked` closes revocation at
  the application layer (every route that matters refuses a revoked host immediately), but
  nginx's own mTLS handshake still completes for a revoked certificate; closing that needs
  a revocation list nginx checks per connection, or certificate lifetimes short enough that
  a successful-but-useless handshake is cheap to tolerate. Not designed here.
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
  certificate-verification path this ADR provisions a certificate *for*, and the
  `authenticateAgent` chokepoint Decision 4's `Agent.revoked` check reuses.
- `server/nginx.conf` — the existing `ssl_verify_client optional` posture, the per-location
  `$ssl_client_verify` checks `/api/v1/enroll`'s new location block deliberately omits, and
  the `cron` rate-limit zone (`limit_req_zone`) Decision 3's enrollment rate limit mirrors.
- `server/middleware.ts` — the exact-path public-route exemption list `/api/v1/enroll` joins
  (Consequences), and `stripIdentityHeaders`'s existing defense (#468) that still applies to
  it.
- `docs/operations/binary-releases.md` — today's manual certificate loading, the
  `server.ca_cert`/`--ca-cert` mechanism `agent enroll` reuses to verify the server
  (Decision 3), and the `offline_fallback` degrade path Decision 4's expired-certificate case
  reuses as-is.
- `docs/architecture/control-plane.md` — the heartbeat/ingest contract doc this ADR's
  "enrollment/PKI" section (once written) belongs in.
