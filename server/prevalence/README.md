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

Built: the counters, the ingest hook and the lookup API, the console triage line, the
retention job, and the server half of the common-set snapshot (format and builder, below).
Not built: publishing the snapshot to agents. The code lives with the rest of the server
(`lib/prevalence.ts`, `lib/common-set-snapshot.ts`, `app/api/prevalence/route.ts`,
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
- **Console:** the case page shows, under each detection, "seen on N hosts, first
  <date>" for the hash, image path, parent-to-child transition or domain of its event,
  rarest first ("never seen on this fleet before" leads). One grouped lookup per case,
  capped at 200 keys; `GET /api/cases/{id}` returns the same lines as `prevalence`.
- **Retention:** `GET /api/cron/prune-prevalence` (bearer `CRON_SECRET`) drops
  sightings not renewed for `PREVALENCE_RETENTION_DAYS` (default 180; a binary that
  returns after that is "first seen" again) and, for a tenant over
  `PREVALENCE_MAX_ROWS_PER_TENANT` (default 5,000,000), the oldest-seen rows. Every
  event is counted and an agent chooses its own paths and domains, so without this the
  table grows with the number of distinct keys anyone can invent. Schedule it daily.

- **Snapshot (ADR-0020):** `getCommonHashes` (the `sha256` keys seen on at least K distinct
  hosts, reporting `truncated` instead of dropping members past its limit) and
  `countReportingHosts` (a snapshot's `hosts_covered`) read the counters;
  `lib/common-set-snapshot.ts` builds the Bloom-filter bytes and parses them strictly, byte for
  byte as `docs/detection/common-set-snapshot-format.md` and the golden fixture define. **Nothing
  builds one on a schedule or serves it yet**: that is slices 5 and 6 of
  `docs/detection/fleet-prevalence-snapshot-plan.md`, waiting on how a per-tenant snapshot is
  signed and refreshed. The agent already loads a snapshot it finds in its content directory and
  adds a capped, weak "not in the common set" term to a process's belief.
- **Checked end to end (2026-10-13/14):** two enrolled lab identities, a real sign-in, and the
  case page showing "seen on 1 host" for a transition one host ran and "seen on 2 hosts" for one
  both ran (`lab/scenarios/prevalence-lineage.sh`).

**Known limits:** the counters can be **recomputed and compared** from the lake
(`lib/prevalence-rebuild.ts`, `server/datalake/README.md`), which proves the fold is a pure function
of the events within the lake's retention; there is no apply path (replace or merge into the table is
an open decision, `issues/issue-77.md`), and a rebuild cannot reach events the lake dropped or
deleted, so prevalence still cannot be rebuilt past the lake's retention if the counting rules change. The triage counts include the event that raised the detection, so "seen on 1
host" means only this host has shown it.

Decided (ADR-0020, accepted): the correlator evidence and the ML rarity feature, both fed
from a pushed common-set snapshot. Not decided: opt-in global statistics (decision 3 of
ADR-0020 is left open).
