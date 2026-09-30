import { Prisma, type PrismaClient } from "@prisma/client";

/**
 * Fleet prevalence (issue #76, Layer 5): how many hosts of a tenant have
 * shown a hash, image path, parent->child transition or domain, and since
 * when. Counters are per tenant and per agent; cross-tenant statistics are
 * deliberately not derivable from this table.
 */
export const PREVALENCE_KINDS = ["sha256", "image_path", "transition", "domain"] as const;
export type PrevalenceKind = (typeof PREVALENCE_KINDS)[number];

export type Observation = { kind: PrevalenceKind; key: string };

export type Prevalence = {
  hostCount: number;
  eventCount: number;
  firstSeen: Date;
  lastSeen: Date;
};

/** Bounds a single key so an attacker-chosen path or domain cannot bloat the table. */
const MAX_KEY_LENGTH = 1024;

const SHA256 = /^[0-9a-f]{64}$/;
const WINDOWS_PATH = /^([a-z]:\\|\\\\)/i;

function nonEmptyString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

/**
 * Windows paths compare case-insensitively, so `C:\Windows\X.exe` and
 * `c:\windows\x.exe` must be one key or a single binary reads as rare.
 * POSIX paths are case-sensitive and stay as reported.
 */
export function normalizeImagePath(path: string): string {
  return WINDOWS_PATH.test(path) ? path.toLowerCase() : path;
}

/** Trailing-dot and case-insensitive: `Example.COM.` and `example.com` are one domain. */
export function normalizeDomain(domain: string): string {
  return domain.toLowerCase().replace(/\.$/, "");
}

/**
 * What one serialized `schema::Event` says about prevalence. Pure, and
 * tolerant: an event of an unknown shape yields nothing rather than an error,
 * because this runs on attacker-influenced JSON after the detection is stored.
 */
export function extractObservations(event: unknown): Observation[] {
  if (typeof event !== "object" || event === null) return [];
  const e = event as Record<string, unknown>;
  const found: Observation[] = [];

  if (e.type === "exec") {
    const image = nonEmptyString(e.image_path);
    const sha = nonEmptyString(e.sha256)?.toLowerCase();
    if (sha && SHA256.test(sha)) found.push({ kind: "sha256", key: sha });
    if (image) {
      const normalizedImage = normalizeImagePath(image);
      found.push({ kind: "image_path", key: normalizedImage });
      // The parent's full path when the platform resolved one, else its comm.
      const parent = nonEmptyString(e.parent_image_path) ?? nonEmptyString(e.parent_comm);
      if (parent) {
        found.push({ kind: "transition", key: `${normalizeImagePath(parent)} -> ${normalizedImage}` });
      }
    }
  } else if (e.type === "dns_query") {
    const query = nonEmptyString(e.query);
    if (query) found.push({ kind: "domain", key: normalizeDomain(query) });
  }

  return found.filter((o) => o.key.length > 0 && o.key.length <= MAX_KEY_LENGTH);
}

/** One `(kind, key)` folded over however many events showed it. */
export type Sighting = Observation & { firstSeen: Date; lastSeen: Date; count: number };

/**
 * Folds events into one sighting per `(kind, key)`: a batch of a hundred
 * `curl` execs becomes one row to write, not a hundred. Also what makes a
 * single multi-row upsert legal, since Postgres refuses to touch the same
 * conflict target twice in one statement.
 */
export function aggregateSightings(
  items: { at: Date; observations: Observation[] }[]
): Sighting[] {
  const folded = new Map<string, Sighting>();
  for (const { at, observations } of items) {
    for (const { kind, key } of observations) {
      const id = `${kind}\u0000${key}`;
      const seen = folded.get(id);
      if (!seen) {
        folded.set(id, { kind, key, firstSeen: at, lastSeen: at, count: 1 });
      } else {
        if (at < seen.firstSeen) seen.firstSeen = at;
        if (at > seen.lastSeen) seen.lastSeen = at;
        seen.count += 1;
      }
    }
  }
  return Array.from(folded.values());
}

/** 7 bound parameters per row against Postgres's 32767 limit, with headroom. */
const ROWS_PER_STATEMENT = 1000;

/**
 * Writes sightings for `agentId`. `first_seen` only ever moves earlier and
 * `last_seen` later, so events arriving out of order (an agent flushing a
 * spool after an outage) cannot make something look newer than it is;
 * Prisma's upsert cannot express LEAST/GREATEST, hence SQL. `sightings` must
 * hold each `(kind, key)` once ([`aggregateSightings`]).
 */
export async function recordSightings(
  db: Pick<PrismaClient, "$executeRaw">,
  tenantId: string,
  agentId: string,
  sightings: Sighting[]
): Promise<void> {
  for (let i = 0; i < sightings.length; i += ROWS_PER_STATEMENT) {
    const rows = sightings
      .slice(i, i + ROWS_PER_STATEMENT)
      .map(
        (s) =>
          Prisma.sql`(gen_random_uuid()::text, ${tenantId}, ${agentId}, ${s.kind}, ${s.key}, ${s.firstSeen}, ${s.lastSeen}, ${s.count})`
      );
    await db.$executeRaw(Prisma.sql`
      INSERT INTO prevalence_sightings (id, tenant_id, agent_id, kind, key, first_seen, last_seen, count)
      VALUES ${Prisma.join(rows)}
      ON CONFLICT (tenant_id, kind, key, agent_id) DO UPDATE SET
        first_seen = LEAST(prevalence_sightings.first_seen, EXCLUDED.first_seen),
        last_seen = GREATEST(prevalence_sightings.last_seen, EXCLUDED.last_seen),
        count = prevalence_sightings.count + EXCLUDED.count`);
  }
}

/** Records that `agentId` showed each observation at `at` (one event's worth). */
export async function recordObservations(
  db: Pick<PrismaClient, "$executeRaw">,
  tenantId: string,
  agentId: string,
  at: Date,
  observations: Observation[]
): Promise<void> {
  await recordSightings(db, tenantId, agentId, aggregateSightings([{ at, observations }]));
}

/** The fleet's prevalence of one key, or `null` if this tenant has never seen it. */
export async function getPrevalence(
  db: Pick<PrismaClient, "prevalenceSighting">,
  tenantId: string,
  kind: PrevalenceKind,
  key: string
): Promise<Prevalence | null> {
  const agg = await db.prevalenceSighting.aggregate({
    where: { tenantId, kind, key },
    _count: { _all: true },
    _sum: { count: true },
    _min: { firstSeen: true },
    _max: { lastSeen: true },
  });
  if (agg._count._all === 0 || !agg._min.firstSeen || !agg._max.lastSeen) return null;
  return {
    hostCount: agg._count._all,
    eventCount: agg._sum.count ?? 0,
    firstSeen: agg._min.firstSeen,
    lastSeen: agg._max.lastSeen,
  };
}

/** Stable map key for one `(kind, key)`. */
export function prevalenceKey(kind: PrevalenceKind, key: string): string {
  return `${kind}\u0000${key}`;
}

/** Most distinct keys looked up for one page: bounds the query a case with many detections issues. */
export const MAX_LOOKUPS = 200;

/**
 * Prevalence of many keys at once, for the console. One grouped query, not one
 * per key; keys beyond [`MAX_LOOKUPS`] are not looked up (and so are absent from
 * the result, which a caller must not read as "never seen").
 */
export async function getPrevalenceBatch(
  db: Pick<PrismaClient, "prevalenceSighting">,
  tenantId: string,
  observations: Observation[]
): Promise<Map<string, Prevalence>> {
  const wanted = new Map<string, Observation>();
  for (const o of observations) wanted.set(prevalenceKey(o.kind, o.key), o);
  const keys = Array.from(wanted.values()).slice(0, MAX_LOOKUPS);
  const found = new Map<string, Prevalence>();
  if (keys.length === 0) return found;

  const rows = await db.prevalenceSighting.groupBy({
    by: ["kind", "key"],
    where: { tenantId, OR: keys.map(({ kind, key }) => ({ kind, key })) },
    _count: { _all: true },
    _sum: { count: true },
    _min: { firstSeen: true },
    _max: { lastSeen: true },
  });
  for (const row of rows) {
    if (!row._min.firstSeen || !row._max.lastSeen) continue;
    found.set(prevalenceKey(row.kind as PrevalenceKind, row.key), {
      hostCount: row._count._all,
      eventCount: row._sum.count ?? 0,
      firstSeen: row._min.firstSeen,
      lastSeen: row._max.lastSeen,
    });
  }
  return found;
}

/** The distinct observations across a set of detections' stored events. */
export function observationsOfDetections(detections: { event: unknown }[]): Observation[] {
  const distinct = new Map<string, Observation>();
  for (const d of detections) {
    for (const o of extractObservations(d.event)) distinct.set(prevalenceKey(o.kind, o.key), o);
  }
  return Array.from(distinct.values());
}

/**
 * The triage fact for one key: "seen on N hosts, first <date>". `null` means
 * this tenant has never seen it, which is the answer a triager most wants, so it
 * is said outright rather than left blank.
 */
export function describePrevalence(p: Prevalence | null): string {
  if (!p) return "never seen on this fleet before";
  const hosts = `${p.hostCount} host${p.hostCount === 1 ? "" : "s"}`;
  return `seen on ${hosts}, first ${p.firstSeen.toISOString().slice(0, 10)}`;
}

export type TriageLine = { kind: PrevalenceKind; key: string; label: string; text: string };

const KIND_LABEL: Record<PrevalenceKind, string> = {
  sha256: "hash",
  image_path: "image",
  transition: "parent → child",
  domain: "domain",
};

/** A long hash or path stays readable; the full value is still in `key`. */
function shorten(kind: PrevalenceKind, key: string): string {
  if (kind === "sha256") return `${key.slice(0, 12)}…`;
  return key.length > 80 ? `${key.slice(0, 77)}…` : key;
}

/**
 * The triage lines for one detection's observations, rarest first: a key seen on
 * one host (or none) is what a triager needs to see before the ones every host
 * has. Only the first [`MAX_LOOKUPS`] keys were looked up
 * ([`getPrevalenceBatch`]), so only those are rendered; `omitted` counts the rest
 * rather than showing them as "never seen", which they were not checked for.
 */
export function triageLines(
  observations: Observation[],
  found: Map<string, Prevalence>
): { lines: TriageLine[]; omitted: number } {
  const shown = observations.slice(0, MAX_LOOKUPS);
  const lines = shown
    .map((o) => ({ o, p: found.get(prevalenceKey(o.kind, o.key)) ?? null }))
    .sort((a, b) => (a.p?.hostCount ?? 0) - (b.p?.hostCount ?? 0))
    .map(({ o, p }) => ({
      kind: o.kind,
      key: o.key,
      label: `${KIND_LABEL[o.kind]} ${shorten(o.kind, o.key)}`,
      text: describePrevalence(p),
    }));
  return { lines, omitted: observations.length - shown.length };
}

/** Row cap per tenant beyond which the oldest-seen sightings are dropped. */
export const DEFAULT_MAX_ROWS_PER_TENANT = 5_000_000;
/** A sighting not renewed for this long is dropped; if it returns it is "first seen" again. */
export const DEFAULT_RETENTION_DAYS = 180;

export type PruneResult = { expired: number; overCap: number };

/**
 * Bounds the sightings table. Every uploaded event is counted, and an enrolled
 * agent chooses its own paths and domains, so without this the table grows with
 * the number of *distinct* keys anyone can invent. Two rules:
 *
 * 1. Age: drop sightings whose `last_seen` is older than `olderThan`.
 * 2. Size: for a tenant still over `maxRowsPerTenant`, drop the oldest-seen rows
 *    down to the cap, so one tenant flooding the table cannot starve the rest.
 */
export async function prunePrevalence(
  db: Pick<PrismaClient, "prevalenceSighting" | "$executeRaw">,
  opts: { olderThan: Date; maxRowsPerTenant: number }
): Promise<PruneResult> {
  const expired = (
    await db.prevalenceSighting.deleteMany({ where: { lastSeen: { lt: opts.olderThan } } })
  ).count;

  let overCap = 0;
  const perTenant = await db.prevalenceSighting.groupBy({
    by: ["tenantId"],
    _count: { _all: true },
  });
  for (const { tenantId, _count } of perTenant) {
    if (_count._all <= opts.maxRowsPerTenant) continue;
    // Keep the newest `maxRowsPerTenant`; everything past that offset goes.
    overCap += await db.$executeRaw`
      DELETE FROM prevalence_sightings WHERE id IN (
        SELECT id FROM prevalence_sightings
        WHERE tenant_id = ${tenantId}
        ORDER BY last_seen DESC, id
        OFFSET ${opts.maxRowsPerTenant})`;
  }
  return { expired, overCap };
}

