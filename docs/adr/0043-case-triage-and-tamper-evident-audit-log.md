# ADR-0043: Case Triage and Tamper-Evident Audit Log

- **Status**: proposed
- **Date**: 2026-10-29

## Context

Issue #135 splits two pieces out of the #28 server scaffold: a case triage workflow
(assign, status, severity, notes, close, link related cases) and a tamper-evident audit
log of privileged actions. Both are marked as depending on #89 (RBAC + multi-tenancy,
ADR-0003), which is still **open** with every "done when" box unchecked. That checklist
understates how much already exists; it needs separating from what's genuinely missing
before proposing anything new.

**Already built:**
- better-auth is wired with the organization plugin, organization = tenant
  (`server/lib/auth.ts`). Membership is the `Member` model, keyed by `organizationId`
  (which *is* the tenant id) and `userId`, with a free-form `role` string.
- Every relevant table is already tenant-scoped (`tenantId` first-class on `Case` and
  `AuditLog`, among others) — ADR-0003's "tenant id first-class from the first migration"
  box is done.
- Session-derived identity already reaches route handlers safely: `server/middleware.ts`
  resolves the session, then `buildIdentityHeaders` (`server/lib/tenant.ts`) sets
  `x-tenant-id`/`x-user-id` from it — deleting any client-supplied copy first (the fix for
  #468's spoofing bug) — and `getTenantId`/`getUserId` are what route handlers call. The
  audit log's attribution is therefore server-derived, not client-asserted.
- **A role gate already exists, for one role tier.** `server/lib/admin-auth.ts`'s
  `requireTenantAdmin` (#803) looks up `Member` by `organizationId = tenantId` and
  `userId`, splits `role` on `,` (better-auth stores several roles as one comma-separated
  string), and allows only `owner`/`admin`. It is **deny by default**: no membership row,
  an unknown role string, or a session with no active organization (401) all fail closed.
  Ten routes already call it (content release/halt/rollback, agent ring, corpus finalize,
  notification channels, release, admin tenants). An earlier draft of this ADR said "no
  RBAC enforcement anywhere"; that was wrong (review of #135's ADR).
- The roles actually stored today are better-auth's organization defaults: `owner`,
  `admin`, `member` (`admin-auth.ts`'s doc comment; tenant provisioning creates the first
  member as `owner`). ADR-0003's four roles (analyst / responder / admin / read-only) are an
  intention — no code creates or reads `analyst`, `responder` or `read-only`.
- `Case` already has `title`/`description`/`severity`/`status`, with `status` one of
  `open`/`investigating`/`resolved`/`false_positive` (a string, by convention).
  `GET /api/cases/[id]` already serves a rich read view: detections, the AI-generated
  narrative (`CaseNarrative`) with staleness, fleet prevalence (#76), and the ransomware
  damage manifest (#82).
- `AuditLog` already exists, tenant-scoped, with `userId`/`action`/`resource`/`details`/
  `timestamp`, and rows in it today. `userId` is a plain string with **no** foreign key,
  and system actors already use it: the ring-health cron writes `userId: "system"`.
  `AuditLog` cascades on `Tenant` deletion (`onDelete: Cascade`); no production code
  deletes a tenant, only test helpers do.

**Not built:**
- **No role gate below admin.** Nothing distinguishes "may triage a case" from "may read
  it": every non-admin route is session-only.
- **No case mutation surface at all.** `/api/cases/[id]/route.ts` exports `GET` only — no
  `PATCH`, no assign, no close, no notes, no related-case link.
- **`AuditLog` has no tamper-evidence.** It is a plain mutable Postgres table: no chain,
  no append-only constraint, no integrity check of any kind.
- **SSO/OIDC** (#89's fourth checklist box) is unverified, and is a separable piece this
  issue does not need.

## Decision

Narrow #89 to what #135 actually needs — a role gate for triage — and treat SSO/OIDC and
ADR-0003's full role set as #89's own remaining items, not blockers here.

1. **`requireRole`, generalized from `requireTenantAdmin`, deny by default.** A new
   `server/lib/rbac.ts` exports `requireRole(req, allowed: readonly Role[])`, and
   `requireTenantAdmin` becomes `requireRole(req, ["owner", "admin"])` so there is one
   lookup, not two that can drift. The lookup is exactly the existing one:
   `Member` where `organizationId = tenantId` and `userId`, both from the session-derived
   headers; `role` split on `,` and trimmed. `Role` is a closed TypeScript union of the
   role names that exist today — `"owner" | "admin" | "member"` — and the check is an
   explicit allowlist: a caller passes if **any** of its roles is in `allowed`, and fails
   with `403` in every other case — no membership row, an empty role, a role string not in
   the union (a typo, a future `read-only`, anything else). No active organization is
   `401`, as `requireTenantAdmin` already does. There is no "everyone except" rule
   anywhere.

   Triage writes are allowed to `owner`, `admin` and `member`. That is coarse on purpose:
   `member` is today's only non-admin role, so the gate adds no restriction a deployment
   currently relies on, but it does make "may write a case" an explicit, tested decision
   rather than "has a session". When #89 introduces ADR-0003's `read-only` (or `analyst`/
   `responder`), it is added to the `Role` union and *not* to the triage allowlist unless
   someone decides it should be — deny-by-default means a new role starts with nothing.
   The finer per-action matrix (e.g. only `responder`/`admin` may close) stays deferred.

2. **Case triage mutation surface.** Every route calls `requireRole` first, loads the case
   with `where: { id, tenantId }` (a case from another tenant is `404`, never `403`, so
   existence does not leak across tenants), and commits its change and its `AuditLog` row
   in **one** transaction (Decision 3's chain append runs inside it).
   - `PATCH /api/cases/[id]` — `severity`, `assignedToUserId`, and `status` between the
     two **open** states only (`open` ↔ `investigating`). A terminal status (`resolved`,
     `false_positive`) in a `PATCH` body is `400`: closing has exactly one route, so it
     can never be recorded as a `case.update`. Audit action `case.update`, with the
     changed fields' before/after in `details`.
     - **Assignee is tenant-checked.** `Case.assignedToUserId` (new, nullable) references
       `User`, which is the global auth table — tenancy lives in `Member`. A non-null
       assignee is accepted only if a `Member` row exists with `organizationId = tenantId`
       and that `userId`, checked inside the transaction; otherwise `400`. A user removed
       from the tenant later stays as the historical assignee (the audit trail records
       who it was) but cannot be newly assigned.
   - `POST /api/cases/[id]/close` — body `{ resolution: "resolved" | "false_positive" }`,
     which becomes `status`. Refused with `409` if the case is already in a terminal
     status. Audit action `case.close`.
   - `POST /api/cases/[id]/reopen` — terminal → `open`, `409` if the case is not
     terminal. Same allowlist as the other triage routes; audit action `case.reopen`.
     Reopening is allowed because a `false_positive` call that turns out wrong must be
     correctable without editing the database, and a separate route keeps it visible in
     the audit trail as its own action.
   - `POST /api/cases/[id]/notes` — a new `CaseNote` model (tenantId, caseId, userId,
     body, createdAt). Deliberately separate from `CaseNarrative`: the narrative is the
     AI-generated case summary (`api/cases/[id]/narrative/regenerate`), a note is an
     operator's own words; conflating them would make an analyst's note vanish on the
     next narrative regeneration. Notes are append-only (no edit or delete route).
     Audit action `case.note`.
   - `POST /api/cases/[id]/links` and `DELETE /api/cases/[id]/links/[otherId]` — a new
     `CaseLink` model storing an **unordered** pair canonically: `(tenantId, caseLowId,
     caseHighId)` with `caseLowId < caseHighId` (string order), `@@unique` on the three,
     and a check constraint `caseLowId <> caseHighId`. So A→B and B→A are the same row,
     a duplicate link is a `409` from the unique constraint rather than a second row, and
     a self-link is `400`. The other case must exist **in the same tenant**, checked in
     the transaction (`404` otherwise, same no-leak rule). Readers query both columns.
     Audit actions `case.link` / `case.unlink`.

3. **Tamper-evident audit log: a per-tenant hash chain with an explicit order, a canonical
   encoding, and a stored head.**

   - **Order and concurrency.** Each tenant gets one `AuditChainHead` row (`tenantId` as
     primary key, `seq`, `headHash`). Appending an audit row, inside the transaction of the
     write it records: `SELECT ... FROM audit_chain_heads WHERE tenant_id = $1 FOR UPDATE`;
     the new row gets `seq = head.seq + 1` and `prevHash = head.headHash`; insert it;
     update the head to the new `seq`/`rowHash`. The row lock serializes appends per
     tenant, so two concurrent privileged writes cannot both read the same tail — the
     second waits for the first to commit and chains onto it. `AuditLog` gains
     `@@unique([tenantId, seq])` as a backstop: a fork would be a constraint violation,
     not a silently branched chain. **The chain's order is `seq`, never `timestamp`.**
     Different tenants never contend.
   - **Canonical hash input.** `rowHash = SHA-256(encoding)`, where the encoding is the
     concatenation of these fields in this order, each as a 4-byte big-endian length
     followed by its UTF-8 bytes (so no two different field splits produce the same
     input): a format tag `synthaea-audit-v1`, `tenantId`, `seq` (decimal), `id`,
     `userId`, `action`, `resource`, `timestamp` (UTC, RFC 3339 with milliseconds),
     `details` as RFC 8785 (JCS) canonical JSON or the empty string when null, and
     `prevHash` (lowercase hex). The application sets `id` and `timestamp` explicitly
     before hashing instead of leaving them to database defaults, so what is hashed is
     exactly what is stored. A golden test pins the encoding to a fixed vector so a
     refactor cannot change it silently.
   - **Existing rows: a genesis row, not a backfill.** The migration adds `seq`/`prevHash`/
     `rowHash` as nullable; existing rows keep them null and are **outside** the chain —
     a backfill would be computed by the same unprotected process that could have
     altered them, and would claim more than it proves. Instead, the migration writes one
     row per tenant, `action = "audit.chain.genesis"`, `seq = 1`, `prevHash` = 64 zeros,
     whose `details` record how many pre-chain rows the tenant had and a SHA-256 over
     their canonical encodings (same format, ordered by `timestamp, id`). That snapshot
     makes later edits to old rows detectable relative to the migration moment, while
     saying honestly that nothing vouches for them before it.
   - **System actors.** `userId` stays a free string without a foreign key, as today.
     `"system"` is the reserved actor for scheduled jobs (the ring-health cron already
     uses it); any other non-human writer names itself the same way
     (`"system:<job name>"`). No fake user id is needed.
   - **Truncation and deletion.** `verify-audit-chain` walks a tenant's rows by `seq` from
     genesis and checks each `prevHash`/`rowHash`, **and** that the last row's `seq` and
     `rowHash` equal the stored head — so deleting the newest rows is a reported break,
     not a shorter valid chain. A Postgres trigger rejects `UPDATE` and `DELETE` on
     `audit_logs` outright (the application never does either), and `AuditLog`'s relation
     to `Tenant` becomes `onDelete: Restrict`: no production path deletes a tenant today,
     and one that does in future must decide what happens to its audit trail explicitly,
     not lose it through a cascade. Test helpers that wipe the database switch to
     `TRUNCATE`, which does not fire row-level triggers.
   - **What this is.** Tamper-*detecting* for an actor who changes audit rows without
     going through the application, including by deleting them. Not proof against an
     actor with full database control: such an actor can drop the trigger, rewrite rows
     from some point, recompute every hash from there, and update the head — nothing in
     the chain is outside the database's reach. External anchoring of the head (or
     signing it with a key the server does not hold) is what closes that, and is
     deferred.

4. **SSO/OIDC** stays #89's own remaining item; closing it is not part of this ADR.

## Consequences

**New**: `server/lib/rbac.ts` (`requireRole`, with `requireTenantAdmin` reimplemented on
it); `Case.assignedToUserId`; `CaseNote`, `CaseLink`, `AuditChainHead` models;
`AuditLog.seq`/`prevHash`/`rowHash` and `@@unique([tenantId, seq])`; the `PATCH`,
`close`, `reopen`, `notes` and `links` routes; one shared append helper every
`auditLog.create` call site moves onto (fourteen today, across thirteen files, plus the
new routes) so no route writes an unchained row; the canonical-encoding golden test; the `UPDATE`/`DELETE`
trigger; `AuditLog → Tenant` as `onDelete: Restrict`; the genesis migration; a
`verify-audit-chain` script.

**Closes**, as a side effect: #89's "RBAC enforced on one privileged path end to end with
audit" checklist box.

**Still not delivered**: the console UI that turns this API into a clickable triage
workflow; SSO/OIDC; ADR-0003's `analyst`/`responder`/`read-only` roles and a per-action
role matrix; a tamper-evidence guarantee that survives a database-level attacker.

## Deferred

- SSO/OIDC verification (#89's own remaining scope).
- ADR-0003's four roles as stored roles, and the fine-grained role-to-action matrix.
- External anchoring or signing of the audit chain head, for a guarantee that survives a
  database-level attacker.
- Revoking the application's own database role's `UPDATE`/`DELETE` grant on
  `audit_logs`: the server runs `prisma db push` with the same role it serves with
  (`docker-compose.yml`), so this needs a separate migration role first. The trigger is
  the interim control.
- A tenant-deletion procedure that exports or archives the audit trail first.
- The console triage UI itself.

## References

- #135 (this issue), #28 (server scaffold, closed), #89 (RBAC/tenancy, open, narrowed by
  this ADR), ADR-0003 (better-auth console decision), #803 (`requireTenantAdmin`)
- #76 (fleet prevalence), #82 (ransomware damage manifest) — already consumed by the
  existing read-only case-detail view this ADR builds mutation on top of
- RFC 8785 (JSON Canonicalization Scheme) — the `details` encoding
- `server/lib/{auth,tenant,admin-auth,session-lookup}.ts`, `server/middleware.ts`,
  `server/prisma/schema.prisma` (`Case`, `AuditLog`, `Member`),
  `server/app/api/cases/[id]/route.ts`
