# ADR-0040: Agent enrollment and mTLS certificate provisioning

- **Status**: proposed
- **Date**: 2026-10-29

## Context

Every agent-to-server connection is already authenticated by mTLS, and the server side of
that is fully built: nginx terminates TLS and forwards `X-Client-Cert-Verified`/
`X-Client-Cert-Subject`; `server/lib/agent-auth.ts`'s `authenticateAgent` reads an
`enrollmentId` out of the certificate's CN (`extractEnrollmentId`) and looks it up against
`Agent.enrollmentId` (`@unique`, `server/prisma/schema.prisma`'s `Agent` model).
`docs/architecture/ control-plane.md`'s heartbeat contract is explicit that this is the
*only* identity that counts: `agent_id` in a request body is `null` today and is "never
trusted" — correctly, since trusting a self-reported field over the verified certificate
would be the actual vulnerability. None of that is in question here.

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
it was for ADR-0027. The threat model differs accordingly. A compromised `release` key is root
code execution on every agent. A compromised enrollment CA key is not bounded to one tenant:
there is one CA per deployment behind one nginx `ssl_client_certificate`, and the identity is
just a UUID in the CN, so a leaked key mints a certificate for *any* `enrollmentId` in *any*
tenant of that deployment — impersonating any existing agent to the server (injecting or
suppressing its telemetry, heartbeats, detections and decoy hits) and pulling content and
releases as it. That is serious. What bounds it is not tenancy but where the key lives: it
sits inside the server process, and an attacker able to read it from there can already write
any tenant's rows directly (the server holds the database connection string). The key being
online adds no capability over a server compromise *while it lasts*; what it adds is
persistence — a copied key outlives the cleanup of the server it was copied from, which is
why CA rotation (Deferred) is the incident-response half of this design, not an optional
extra. It reaches agents' *inputs* only through the server (content and releases stay signed
by ADR-0027's offline keys, which this key cannot forge), so it never becomes code execution
on an agent. Holding the CA key at the server process's own trust level is a narrower ask
than ADR-0027's, not a weaker version of the same one.

## Decision

1. **Scope**: how a freshly-installed agent, with no certificate yet, obtains one; how it
   renews one before expiry; and who signs it. Does not cover: the release/content signing
   keys (ADR-0027, unaffected), the better-auth/tenant/organization model (#821/#829, reused
   as-is), or transport's existing upload/heartbeat/fetch mechanics (unaffected — this ADR
   only adds how the certificate those already use gets onto the host).

2. **A per-deployment CA, generated once, self-hosted with everything else, scoped to one
   job only: signing agent client certificates.** Each self-hosted instance generates its
   own CA keypair once, in a one-shot setup step run **before** `docker compose up` (not by
   the running server): it writes the public certificate next to nginx's existing
   certificates in `./certs`, and the private key **outside** `./certs` — the `proxy`
   container mounts that whole directory, and nginx has no business holding the key. The
   `server` container's other secrets (`DATABASE_URL`, `BETTER_AUTH_SECRET`) arrive as
   environment variables in `docker-compose.yml`; a PEM key is a file, so it gets a
   read-only mount into `server` only, from a path `server/.gitignore` covers so a
   development checkout cannot commit it. This key is then held by the running
   server process, deliberately unlike ADR-0027's keys, for the reason in Context:
   enrollment has to sign on demand.

   nginx is a separate container that reads its client-CA file once, at startup, from the
   `./certs` mount (`ssl_client_certificate` in `server/nginx.conf`, today a pre-placed
   `ca.crt`). The setup step therefore writes a **bundle** — the existing, operator-managed
   `ca.crt` followed by the new enrollment CA's certificate — and `ssl_client_certificate`
   points at that bundle. Two consequences, both intended: hosts already running with
   certificates an operator signed by hand against `ca.crt` keep working unchanged (nothing
   forces a flag day), and because the CA exists before nginx starts, no runtime reload is
   needed. Dropping the legacy CA from the bundle is an operator decision once every host has
   enrolled, not something this ADR schedules.

   This CA is what nginx trusts to verify an *incoming agent's* client certificate. **It is
   not, and must not become, what an agent trusts to verify the *server*.** That is
   `server.ca_cert` (`docs/operations/binary-releases.md`), which verifies nginx's own
   listener certificate (`ssl_certificate`) — a separate credential, provisioned however
   this deployment's public-facing TLS already is (a real domain's ACME certificate, or an
   operator-supplied one; orthogonal to this ADR, unchanged by it). Collapsing these two into
   one CA was an earlier draft's mistake (review of #314's ADR): a leaked enrollment-CA key
   would then also mint a certificate that agents accept as *the server* — a MITM of every
   enrolled agent, on top of Context's already-serious impersonation.

   The CA is constrained in its own certificate and in every certificate it issues, so the
   key can do exactly one thing: the CA certificate carries `basicConstraints CA:TRUE,
   pathlen:0` (it can sign leaves, nothing it signs can sign further); every issued
   certificate carries `CA:FALSE`, `keyUsage digitalSignature`, `extendedKeyUsage
   clientAuth` only, and the capped lifetime of Decision 4. No name constraint is claimed:
   the identity is a random UUID in the CN, not a DNS name or an address, so there is no
   name space for a constraint to narrow. Every issuance is logged
   (`AuditLog`, same table and shape as every other privileged action).

3. **Enrollment: a shared, time-boxed, usage-capped token; the agent generates its own
   keypair; the server, never the agent, picks the identity.** An admin (an authenticated
   console session, same tenant/org model as #829) creates an enrollment token scoped to
   their tenant: a random secret, an expiry, and a usage cap (more than 1 — a fleet deployed
   from one golden image or one deployment script enrolls many hosts with the same token in
   a short window; unlimited reuse forever would make the token a long-lived shared secret,
   which defeats the point). The server generates the token, never the operator: the
   presented form is `<token id>.<secret>`, the secret 256 bits from the OS CSPRNG, so
   guessing is not an attack worth rate-limiting against and the id lets the server count
   failures against one token without ever storing the secret in plaintext. How the token
   physically reaches the new host is the operator's existing deployment tooling's problem,
   exactly as it already is for today's manual certificate file — this ADR does not change
   who is responsible for that step, only what the host does once the token is there.

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
   `agent enroll` verifies the TLS certificate `/api/v1/enroll` presents with the exact same
   trust anchor `apply-release` and `apply-content-manifest` already use
   (`docs/operations/binary-releases.md`): `server.ca_cert`/`--ca-cert` when set, otherwise
   the platform's built-in roots (`server.ca_cert` is optional — absent means the built-in
   roots, `crates/config`'s `an_absent_ca_cert_means_the_builtin_roots`). A deployment
   whose listener certificate chains to a public root needs nothing extra; one with a
   private listener CA already has to ship that file to every host for the other one-shot
   commands, and ships it alongside the enrollment token the same way. Either way the agent
   never sends the token to a server it has not verified.

   **`agent enroll` never presents a client certificate**, even when `server.mtls_cert`/
   `server.mtls_key` already exist on disk. That matters because of how nginx is set up:
   `ssl_verify_client optional` lets a client that presents *no* certificate through, but a
   client that presents one that does not verify (expired, or signed by a CA no longer in
   the bundle) is rejected before any route runs. A host re-enrolling after its certificate
   expired would hit exactly that if `enroll` loaded the configured identity, so its TLS
   client is built with no client identity at all. `--token` also accepts `--token-file
   <path>` or `-` (read from stdin) as alternatives to the bare argument, so an operator's
   deployment script is not forced to leave the secret sitting in `ps` output and shell
   history — `--token` itself stays available for interactive use, where that risk is
   already the operator's to manage.

   Server-side, the request first checks the CSR, outside any transaction, and refuses it
   with `400` before touching the token if it fails: the CSR's self-signature verifies
   (proof the requester holds the private key), and the key is ECDSA P-256 or RSA of at least
   3072 bits — anything else is refused, not upgraded. Then **one database transaction**
   holds everything that must happen together, and the certificate is returned only after it
   commits:

   1. the token is consumed by a single conditional `UPDATE ... SET uses_remaining =
      uses_remaining - 1 WHERE id = $1 AND secret_hash = $2 AND uses_remaining > 0 AND
      expires_at > now() AND NOT locked RETURNING ...` — tokens are stored hashed, never in
      plaintext, and two concurrent enrollments against a one-remaining-use token cannot
      both succeed, regardless of ordering;
   2. the server generates the `enrollmentId` and inserts the `Agent` row (or, for a
      reissue token, updates the existing one — Decision 4);
   3. it signs the certificate in-process with the CA key — no network call, so holding the
      transaction across it costs milliseconds;
   4. it writes the `AuditLog` issuance row;
   5. it commits, and only then returns the certificate.

   Any failure before the commit — signing included — rolls back all of it: the use is not
   consumed, no `Agent` row exists, nothing is audited, and the agent gets a `5xx` it may
   retry with the same token. A failure *at* commit leaves a signed certificate that was
   never returned and names an `enrollmentId` with no `Agent` row, which `authenticateAgent`
   already refuses. There is no state in which a use is consumed without a matching `Agent`
   and `AuditLog` row, or the reverse.

   Abuse is bounded per token, not per address. A presented token whose id exists but whose
   secret does not match increments that token's failure count, outside the rolled-back
   transaction, and the token locks after a small number of failures (an admin can unlock or
   reissue it); an unknown id is a plain `401`. The usage cap bounds how many identities one
   leaked token can mint, and the expiry bounds for how long. nginx also gets a
   `limit_req_zone` for `/api/v1/enroll`, with the existing `cron` zone as the precedent, but
   only as a coarse flood guard: its burst is sized so a golden-image fleet enrolling behind
   one NAT address is not refused, and it is not what stops a distributed attacker — the
   token's entropy, lock, cap and expiry are.

   The server returns the signed certificate; `agent enroll` writes it, and the private key
   it already generated, to the paths `server.mtls_cert`/`server.mtls_key` already name —
   `agent run` needs no change at all; it already loads whatever is at those paths.

4. **Concrete lifetime, renewal window, and a cheap revocation check on both.** A signed
   certificate is valid 30 days, and renewal starts with at least a 10-day lead — generous
   enough that a control-plane outage has to run longer than ten days before any agent is at
   risk of hitting its hard expiry. These are config defaults, not hardcoded forever, but they
   are *stated*: a number has to exist for "the server was down longer than the cert
   lifetime" to even be a question with an answer.

   **The renewal trigger ships with enrollment, not after it.** It does not wait for #754's
   periodic update timer, which is still open: if enrollment shipped first, every host
   enrolled through it would reach hard expiry with nothing to renew it, and hosts enrolled
   together from one golden image would all expire together, taking upload, content and
   release fetches down fleet-wide at once. So `agent run` owns the trigger itself: it reads
   its own certificate's `notAfter` at startup and on a daily tick, and renews in-process once
   inside the renewal window — the same code path `agent enroll --renew` runs by hand. Each
   agent picks its renewal point at random between 15 and 10 days before expiry, so a batch
   enrolled the same hour spreads its renewals over five days instead of arriving at once;
   a failed attempt retries on the next tick, inside the same window. It writes the new pair
   to the same `server.mtls_cert`/`server.mtls_key` paths with the ownership and mode the old
   pair had, each atomically (temp file and rename), and only switches the in-memory
   identity once both are on disk.

   Renewal is its own route, `POST /api/v1/enroll/renew`, the reverse of `/api/v1/enroll`
   in every respect that matters: it **requires** the current, still-valid client
   certificate (no token is involved — the certificate is the proof of enrollment), so its
   own exact-match nginx block keeps the `$ssl_client_verify` check `/api/v1/enroll` drops,
   and its handler goes through `authenticateAgent` like any other agent route. Its
   middleware exemption is the same exact-path kind the agent's release and content routes
   already have (`/api/v1/enroll/renew`, not a prefix, so nothing else under `/api/v1/enroll`
   inherits it). It re-signs for the same `enrollmentId`, with a fresh keypair the agent
   generated for the purpose, under the same CSR checks as Decision 3.

   **Revocation is a flag every agent route checks.** A new `Agent.revoked` boolean is read by
   `authenticateAgent`, and a revoked agent is refused with `403` and a body that names
   revocation, so it reads as revocation in the agent's logs rather than a generic auth
   failure. Today that check would not be enough on its own, because `authenticateAgent` is
   *not* the single chokepoint an earlier draft of this ADR said it was: on `main`,
   `ingest/events`, the `content/*`, `release/*` and `snapshot/*` routes go through it, but
   `ingest/heartbeat`, `ingest/detection`, `ingest/decoy` and `corpus/submit` call
   `extractEnrollmentId` and `verifyProxyAuth` directly and look the agent up themselves. As
   part of this change those four move onto `authenticateAgent` (heartbeat's `lastSeen`
   update then keys on the returned `Agent.id`), and `revoked` joins its `select`, so a
   revoked host's heartbeats, detections, decoy hits and corpus submissions are refused along
   with everything else, renewal included. No CRL and no new database round trip: the row is
   already fetched on every authenticated call.

   For the agent, a revocation `403` is final, not a transient failure: transport already
   treats `403` as non-retryable, so uploads stop being accepted and fetches stop
   succeeding, while the agent keeps detecting and responding locally — revocation cuts a
   host off from the control plane, it does not disarm it. That is a different state from
   `server.offline_fallback`, which only covers a certificate missing or unreadable at
   startup; a revoked host still has a valid certificate and is told, on every request, that
   it no longer counts. It is not TLS-layer revocation: nginx's handshake has no opinion on
   `Agent.revoked` and completes normally right up to the application layer (Decision 5).

   If the certificate has already expired — a host offline past its renewal window — there
   is nothing valid left to authenticate a renewal with, and the host needs a fresh
   enrollment token, an operator action, same as a first install. Such a host does *not*
   land in `server.offline_fallback` (`docs/operations/binary-releases.md`): that path is
   for a certificate or key that is missing or unreadable, which stops `run` from setting
   upload up at all. An expired certificate is still readable, so upload is set up and every
   request then fails at nginx, which refuses a presented certificate that does not verify
   before any route runs. The end state is the same — the host keeps detecting locally, but
   uploads nothing and fetches no content or releases until it is re-enrolled — and
   `agent run`'s own expiry check (above) says so in the journal, so the operator reads
   "certificate expired, re-enroll this host" rather than a stream of `400`s to interpret.

   A fresh enrollment after expiry does not have to mean a fresh identity: an enrollment
   token can be scoped to a specific, already-known `Agent` (an operator picks "reissue for
   this host" in the console rather than "new enrollment"), and redeeming it rotates that
   row's `enrollmentId` to the newly minted one instead of inserting a row. Every relation
   that matters (`AgentHealth`, `Detection`, cases, decoy tokens) keys off `Agent.id`, the
   stable row identity, never `enrollmentId`, so the host keeps its history. A reissue
   token follows three rules:

   - **Same tenant, checked twice.** The token can only be created for an `Agent` in the
     admin's own tenant, and redemption re-checks that the token's tenant and the `Agent`'s
     tenant are still the same, inside the same transaction as Decision 3's.
   - **It never un-revokes.** A reissue token cannot be created for a revoked `Agent`, and
     redeeming one against an `Agent` revoked since fails like an exhausted token.
     Un-revoking is its own console action, audited on its own, so bringing a revoked host
     back is always a deliberate step and never a side effect of reissuing it.
   - **Rotation is the kill switch for the old certificate, on purpose.** Once
     `enrollmentId` rotates, the previous certificate names an `enrollmentId` no `Agent` row
     carries, and `authenticateAgent` refuses it from the next request, for the up to 30
     days it would otherwise have stayed valid. That is the point of reissuing a host whose
     old key may have leaked or whose disk was lost. The audit row records both the old and
     the new `enrollmentId`.

   A token *not* scoped to an existing agent still creates a fresh row, exactly as a genuine
   first install should.

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
  certificate at all, by necessity. In `server/nginx.conf`, a new exact-match `location =
  /api/v1/enroll` block beside the existing `/api/v1/ingest/` one, without the `if
  ($ssl_client_verify != "SUCCESS")` check that block has, and with its own `limit_req_zone`
  (the `cron` zone is the precedent; Decision 3 says why it is only a flood guard).
  Everything else follows the pattern already there: the server-block-wide `proxy_set_header
  X-Client-Cert-Verified $ssl_client_verify` always carries nginx's own computed value,
  never a client-suppliable one, so the backend correctly sees "no cert" with no
  special-casing; `X-Proxy-Secret` is attached as on every other route.
  `server/middleware.ts` gets one more exact-path entry in its public-route list
  (`req.nextUrl.pathname === "/api/v1/enroll"`, beside the `/api/release/manifest` group) so
  it bypasses the browser-session check; `stripIdentityHeaders` still runs on that branch.
- `server/app/api/v1/enroll/renew/route.ts` (new): a `location = /api/v1/enroll/renew` block
  that *keeps* the `$ssl_client_verify` check, a handler that goes through
  `authenticateAgent`, and its own exact-path middleware entry (Decision 4). Being exact
  matches, neither nginx block nor either middleware entry covers any other path.
- `ingest/heartbeat`, `ingest/detection`, `ingest/decoy` and `corpus/submit` move onto
  `authenticateAgent` (Decision 4), so revocation reaches every agent route — a refactor of
  existing routes that ships with this change, not after it.
- A one-shot CA setup step, run before `docker compose up`: generates the CA keypair, puts
  the key outside `./certs` where only the `server` container reads it, and writes the
  client-CA bundle (existing `ca.crt` plus the new CA) that `ssl_client_certificate` now
  points at (Decision 2). `docker-compose.yml` gains the key mount for `server`.
- A new `EnrollmentToken` model (tenant-scoped; id plus hashed 256-bit secret; expiry; usage
  cap and count; failure count and `locked`; optional `agentId` for a reissue token) and the
  console UI to create, list, unlock and delete them.
- `Agent.revoked: Boolean` (default `false`) and `revokedAt`, read by `authenticateAgent`;
  console "revoke" and "un-revoke" actions, each audited.
- `agent enroll` (token, never presents a client certificate) and `agent enroll --renew`
  (current certificate), plus the renewal check inside `agent run` (Decision 4) —
  `updater`-adjacent in style but not in that crate (no manifest, no signature, no rollback
  — a CSR and a certificate, nothing staged), probably its own small module. `--token`
  accepts a bare argument, `--token-file <path>`, or `-` for stdin.
- The CA private key moves the server process's own trust boundary slightly wider than
  ADR-0027's keys ever did (Context) — this is a deliberate, scoped exception to "no private
  key lives on the control plane," not a precedent for weakening that rule elsewhere. Any
  future key this project adds should default to ADR-0027's offline posture unless it has
  the same "must sign online, synchronously" requirement this one does. Its blast radius is
  every agent identity in the deployment, across tenants (Context); the constraints of
  Decision 2 keep it from being anything *more* than that, and CA rotation (Deferred) is
  what ends it after a leak.
- `docs/architecture/control-plane.md` gains the "enrollment/PKI" section its header has
  promised since before this ADR existed.
- Issue #314 narrows to exactly this ADR once accepted; its other two bullets are already
  closed by existing code, per its 2026-10-29 reconciliation comment.

## Deferred

- **TLS-layer certificate revocation** (Decision 5) — `Agent.revoked` closes revocation at
  the application layer (every route that matters refuses a revoked host immediately), but
  nginx's own mTLS handshake still completes for a revoked certificate; closing that needs a
  revocation list nginx checks per connection, or certificate lifetimes short enough that a
  successful-but-useless handshake is cheap to tolerate. Not designed here.
- **Hardening the CA key's storage beyond a mounted file** (Decision 2) — a read-only file
  mounted only into the `server` container is the posture decided here. Moving it into an
  HSM or a KMS the server signs through is a later option for deployments that need it;
  nothing in this design depends on the key being a plain file.
- **CA rotation** — the incident response to a leaked CA key (Context), and routine hygiene
  for a long-lived deployment: every already-issued agent certificate needs a story for
  staying trusted or being re-issued against the new CA. Not designed here, but the pieces
  this ADR ships are what one would use: nginx already reads a CA *bundle* (Decision 2), so
  old and new CA can be trusted side by side while `--renew` moves the fleet over, then the
  old one dropped. Until that procedure exists, a leaked key's only remedy is re-enrolling
  every host against a fresh CA.
- **Per-tenant CAs** — one CA per tenant, with the backend checking the certificate's issuer
  against the `Agent`'s tenant, would narrow a leaked key to one tenant's agents. Not done:
  every tenant's key would still sit in the same server process, so it narrows a leak of one
  key file, not a server compromise, and it needs nginx to forward the issuer DN. Worth
  revisiting if a deployment ever hosts mutually distrusting tenants.
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
  (Decision 3), and `server.offline_fallback`, which covers a missing certificate but not
  an expired or revoked one (Decision 4).
- `docs/architecture/control-plane.md` — the heartbeat/ingest contract doc this ADR's
  "enrollment/PKI" section (once written) belongs in.
