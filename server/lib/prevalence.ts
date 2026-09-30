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
