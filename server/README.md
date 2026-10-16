# server — Control Plane

One modern Next.js (App Router, TypeScript) + PostgreSQL application — see
[ADR-0001](../docs/adr/0001-server-stack-nextjs-postgres.md). Authentication and
tenancy build on better-auth ([ADR-0003](../docs/adr/0003-better-auth-console.md)):
organization = tenant, RBAC on member roles, tenant id first-class from the first
migration; agent identity stays the mTLS enrollment PKI — the two never mix.

| Path | Purpose |
| --- | --- |
| `ingest/` | Agent-facing endpoints — event/detection upload, heartbeats; mTLS terminated in front (proxy/sidecar) |
| `api/` | Management API — enrollment/PKI, policy distribution, fleet inventory, case queries, audit log |
| `console/` | Analyst console — case-centric triage UI, fleet health, content/model distribution |
| `ops/` | Fleet operations — agent health, observable-loss counters, ring rollout, ingest health |
| `integrations/` | SOAR/ticketing/paging — bidirectional case workflow (Jira, ServiceNow, PagerDuty, webhooks) |
| `datalake/` | Telemetry lake — full-fidelity raw events, columnar/partitioned; substrate for cloud detection, hunting, graph/prevalence rebuilds, ML corpora |
| `cloud-detection/` | Cloud-based detection: streaming on ingest, scheduled sweeps, and retrospective replay of new content over history |
| `hunt/` | Threat hunting — saved/scheduled hunts over fleet telemetry, graduation into detection content |
| `fleet/` | Cross-machine case correlation + adaptive posture (a detection on one host raises the alertness of related hosts) |
| `graph/` | Entity graph — fleet-wide entities/relations projection backing cases, fleet correlation, hunting, prevalence |
| `prevalence/` | Reputation/prevalence (Layer 5): fleet first-seen/rarity counters feeding detection and triage |
| `forensics/` | DFIR workbench — triage acquisitions (via live-response), case timeline, artifact parsing, chain of custody |
| `assistant/` | Analyst AI assistant — grounded narratives/navigation over cases and the graph; never scores |
| `disruption/` | Attack disruption — case-level playbooks: isolate device, suspend user, block indicators |
| (planned) `export/` | SIEM forwarding — vendor connectors (Splunk HEC, Sentinel, Elastic) shipping cases/detections fleet-wide; agents only ever emit neutral formats via `sinks` |

All three are facets of the single Next.js app until scale forces a split (the ADR
records the escape hatch). Postgres schema and migrations live here once scaffolded.

## Console authentication (#810)

better-auth reads and writes its tables (`auth_user`, `auth_session`, `auth_account`,
`auth_verification`, `auth_organization`, `auth_member`, `auth_invitation`) through the Prisma
client (`prismaAdapter` in `lib/auth.ts`), so `prisma db push` creates them with the rest of the
schema. Two constraints follow, both found by running a real login:

- **`middleware.ts` must not import `@/lib/auth`.** It runs in Next's Edge runtime, where Prisma
  cannot run; it asks the Node route `/api/auth/get-session` over the loopback
  (`lib/session-lookup.ts`, which fails closed). Server components and route handlers run on Node
  and call `auth.api.getSession({ headers: await headers() })`; better-auth refuses a call without
  the headers.
- **A session's `activeOrganizationId` is the tenant id**, so an organization's id must equal its
  tenant's. `lib/tenant-provisioning.ts`'s `provisionTenant` creates the pair (#821), called from
  `POST /api/admin/tenants` with `{ name }`; the caller becomes the tenant's owning member. The
  route is gated by `PLATFORM_OPERATOR_USER_IDS` (`lib/platform-operator.ts`), a comma-separated
  allow-list of `auth_user.id` values, not a session role — the caller has no tenant yet at this
  point, so a role *within* a tenant (`requireTenantAdmin`, #803) cannot gate it. To sign in
  against the new tenant afterward, call better-auth's own `POST /api/auth/organization/set-active`
  with `{ organizationId: <the returned tenant id> }`. Organization deletion is disabled
  (`disableOrganizationDeletion` in `lib/auth.ts`): better-auth's own delete API has no notion of
  the Tenant/Organization pairing and would orphan the Tenant row.

A better-auth upgrade can add fields to its tables: `tests/integration/console-auth.test.ts` fails
if a required one is missing from `prisma/schema.prisma`.
