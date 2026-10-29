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

**Already built (ADR-0003's decision, partially landed):**
- better-auth is wired with the organization plugin, organization = tenant
  (`server/lib/auth.ts`). `Member.role` (`prisma/schema.prisma:575`) exists per the
  org/tenant membership.
- Every relevant table is already tenant-scoped (`tenantId` first-class, e.g.
  `prisma/schema.prisma:181` on `Case`, `:269` on `AuditLog`) — ADR-0003's "tenant id
  first-class from the first migration" box is done.
- Session-derived identity already reaches route handlers safely:
  `server/middleware.ts` resolves the session, then `buildIdentityHeaders`
  (`server/lib/tenant.ts:32`) sets `x-tenant-id`/`x-user-id` from it — deleting any
  client-supplied copy first (the fix for #468's spoofing bug) — and `getTenantId`/
  `getUserId` (`tenant.ts:50,64`) are what route handlers call. This already satisfies
  the audit log's attribution half: `userId` on a privileged action is server-derived,
  not client-asserted.
- `Case` (`prisma/schema.prisma:179`) already has `title`/`description`/`severity`/
  `status`. `GET /api/cases/[id]` (`server/app/api/cases/[id]/route.ts`) already serves a
  rich read view: detections, the AI-generated narrative (`CaseNarrative`) with staleness,
  fleet prevalence (#76), and the ransomware damage manifest (#82).
- `AuditLog` (`prisma/schema.prisma:265`) already exists, tenant-scoped, with
  `userId`/`action`/`resource`/`details`/`timestamp`.

**Not built, confirmed by absence, not by the stale checklist:**
- **No RBAC enforcement anywhere.** `grep` across `server/lib` for a role-check turns up
  nothing. ADR-0003's four roles (analyst / responder / admin / read-only, per tenant) are
  modeled in data (`Member.role`) but checked by no code.
- **No case mutation surface at all.** `/api/cases/[id]/route.ts` exports `GET` only — no
  `PATCH`, no assign, no close, no notes, no related-case link. The triage workflow issue
  #135 asks for is entirely unbuilt, not partially built.
- **`AuditLog` has no tamper-evidence.** It is a plain mutable Postgres table: no hash
  chaining, no append-only constraint, no integrity check of any kind. This is the one
  bullet of #135 with zero existing infrastructure to build on.
- **SSO/OIDC** (#89's fourth checklist box) is unverified, and is a separable piece this
  issue does not need.

## Decision

Narrow #89 to what #135 actually needs — RBAC enforcement — and treat SSO/OIDC as #89's
own remaining, separate item, not a blocker here.

1. **Minimal RBAC gate.** One helper, `requireRole(tenantId, userId, allowed: Role[])` in
   a new `server/lib/rbac.ts`, reading `Member.role` for the pair `getTenantId`/
   `getUserId` already resolve. Enforces ADR-0003's four roles. Every new privileged
   route below calls it first. This *is* #89's "RBAC enforced on one privileged path end
   to end, with audit" checklist item, satisfied as a consequence of building triage
   rather than as separate pre-work. Coarse split to start: `read-only` never writes;
   every other role can triage/note/link; a finer per-action matrix (e.g. only
   `responder`/`admin` may close) is explicitly deferred, not designed here.

2. **Case triage mutation surface**, each call gated by `requireRole` and each write
   committed in the same Prisma transaction as its `AuditLog` row (no separate job, so a
   crash between "the case changed" and "it's in the log" cannot happen silently):
   - `PATCH /api/cases/[id]` — status/severity/assignee. Adds `Case.assignedToUserId`
     (nullable FK to `User`).
   - `POST /api/cases/[id]/notes` — a new `CaseNote` model (tenantId, caseId, userId,
     body, createdAt). Deliberately separate from `CaseNarrative`: the narrative is
     AI-generated case summary (`#api/cases/[id]/narrative/regenerate`), a note is an
     operator's own words; conflating them would make an analyst's note vanish on the
     next narrative regeneration.
   - `POST /api/cases/[id]/close` — a status transition with its own route rather than
     folded into the generic `PATCH`, so audit `action` reads `case.close` and not an
     ambiguous `case.update`.
   - `POST /api/cases/[id]/link` — a new `CaseLink` model (tenantId, caseId, linkedCaseId,
     createdAt), symmetric (creating one direction is enough; the UI reads both).

3. **Tamper-evident audit log**: hash-chain `AuditLog` rather than add a new subsystem.
   Each row gains `prevHash` (the prior row's `rowHash` for that tenant, or a fixed seed
   for the first) and `rowHash` (a SHA-256 over the row's own fields plus `prevHash`),
   computed server-side in the same transaction as the write it records. A
   `verify-audit-chain` script/job walks a tenant's chain and reports the first break.
   This is **integrity-checking, not non-repudiation**: nothing here stops a party with
   direct database access from rewriting history and recomputing a new, internally
   consistent chain from the tampering point forward — there is no external anchor and
   no key the application server itself doesn't hold. Call it what it is (tamper-*
   detecting*, within the threat model of "someone edited a row without going through
   the app") rather than oversell it as cryptographic proof against a DB-level attacker.
   A stronger guarantee — periodic external anchoring, or signing with a key outside the
   server's reach — is deferred.

4. **SSO/OIDC** stays #89's own remaining item; closing it is not part of this ADR.

## Consequences

**New**: `server/lib/rbac.ts` (`requireRole`); `Case.assignedToUserId`; `CaseNote` and
`CaseLink` models + their routes; `PATCH /api/cases/[id]`, `POST .../notes`, `.../close`,
`.../link`; `AuditLog.prevHash`/`rowHash` + a chain-verification script.

**Closes**, as a side effect: #89's "RBAC enforced on one privileged path end to end with
audit" checklist box.

**Still not delivered**: the console UI that turns this API into a clickable triage
workflow (a follow-on piece consuming what this ADR builds, same shape as the existing
read-only case-detail view); SSO/OIDC; a fine-grained per-action role matrix (ships
coarse: read-only vs. everyone else); a tamper-evidence guarantee stronger than hash-chain
integrity-detection.

## Deferred

- SSO/OIDC verification (#89's own remaining scope).
- External anchoring or signing of the audit hash chain, for a guarantee that survives a
  database-level attacker.
- The fine-grained role-to-action permission matrix.
- The console triage UI itself.

## References

- #135 (this issue), #28 (server scaffold, closed), #89 (RBAC/tenancy, open, narrowed by
  this ADR), ADR-0003 (better-auth console decision)
- #76 (fleet prevalence), #82 (ransomware damage manifest) — already consumed by the
  existing read-only case-detail view this ADR builds mutation on top of
- `server/lib/{auth,tenant,session-lookup}.ts`, `server/middleware.ts`,
  `server/prisma/schema.prisma`, `server/app/api/cases/[id]/route.ts`
