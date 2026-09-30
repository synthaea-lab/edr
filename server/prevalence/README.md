# server/prevalence — Reputation & Prevalence (Layer 5)

How common is this hash / process name / parent-child pair / domain — on this fleet,
and globally? Rarity is one of the highest-value, cheapest detection signals, and it
is exactly the fleet-derived half of the thesis an attacker cannot reproduce offline.

Planned shape:
- Continuous counters from ingest: first-seen / last-seen / host-count per tenant for
  hashes (from enrich), image paths, parent→child transitions, and domains
- **Feeds detection**: per-site rarity flows into T0/T1 features via the adaptation
  loop (docs/detection/ml.md), and "first execution on the fleet" becomes a
  correlator evidence type
- **Feeds the console**: every hash/process in a case shows "seen on N hosts,
  first seen <date>" — the single most-used triage fact
- Global (cross-tenant) prevalence only ever as opt-in, aggregated, k-anonymous
  statistics — per-tenant data stays per-tenant

## Status (issue #76)

Slice 1 is in: counters, the ingest hook and the lookup API. The code lives with the
rest of the server (`lib/prevalence.ts`, `app/api/prevalence/route.ts`,
`PrevalenceSighting` in `prisma/schema.prisma`) rather than in this directory.

- **Storage:** one row per `(tenant, kind, key, agent)` with `first_seen`, `last_seen`
  and an event count. "Seen on N hosts, first <date>" is an aggregate over a key's rows,
  so the host count is exact without a separate distinct-set. Kinds: `sha256`,
  `image_path`, `transition` (`parent -> child`), `domain`.
- **Ordering:** `first_seen` only moves earlier and `last_seen` later (SQL `LEAST`/
  `GREATEST`), so a spool flushed after an outage cannot make something look newer.
- **Normalization:** Windows paths and domains are case-insensitive keys; POSIX paths are
  not. Keys are capped at 1024 characters.
- **Feed:** `POST /api/ingest/events` (the agent's `/api/v1/ingest/events`) records the
  observations of every uploaded event, aggregated per batch into one multi-row upsert,
  so counters see the fleet's full event stream and not just what alerted.
  `POST /api/ingest/detection` also records its event's observations. A counter failure
  never rejects the request. See `docs/architecture/control-plane.md` for the contract.
- **Read:** `GET /api/prevalence?kind=&key=` (session, tenant-scoped) returns
  `seen: false` for an unknown key.

**Known limits:** the bias of the first slice (counters fed only by detections) is
gone for agents that upload events, but two things remain. Every event is
counted, so the table grows with the fleet's distinct paths/hashes/domains (keys are
capped in length, not in number; no retention or eviction yet). And the raw events
are not kept anywhere: the lake (`server/datalake`) doesn't exist, so prevalence
cannot be rebuilt from history if the counting rules change.

Not done yet: the console triage line, the "first seen on fleet" correlator evidence,
the rarity feature into per-site recalibration, and opt-in k-anonymous global statistics.
