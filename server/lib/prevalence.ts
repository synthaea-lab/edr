import type { PrismaClient } from "@prisma/client";

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

/**
 * Records that `agentId` showed each observation at `at`. `first_seen` only
 * ever moves earlier and `last_seen` later, so events arriving out of order
 * (an agent flushing a spool after an outage) cannot make something look
 * newer than it is; Prisma's upsert cannot express LEAST/GREATEST, hence SQL.
 */
export async function recordObservations(
  db: Pick<PrismaClient, "$executeRaw">,
  tenantId: string,
  agentId: string,
  at: Date,
  observations: Observation[]
): Promise<void> {
  for (const { kind, key } of observations) {
    await db.$executeRaw`
      INSERT INTO prevalence_sightings (id, tenant_id, agent_id, kind, key, first_seen, last_seen, count)
      VALUES (gen_random_uuid()::text, ${tenantId}, ${agentId}, ${kind}, ${key}, ${at}, ${at}, 1)
      ON CONFLICT (tenant_id, kind, key, agent_id) DO UPDATE SET
        first_seen = LEAST(prevalence_sightings.first_seen, EXCLUDED.first_seen),
        last_seen = GREATEST(prevalence_sightings.last_seen, EXCLUDED.last_seen),
        count = prevalence_sightings.count + 1`;
  }
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
