import { Prisma, type PrismaClient } from "@prisma/client";

/**
 * Ingest health (issue #899): what the server accepted, refused and skipped per agent, per kind
 * of data and per hour, and how late it was. Written best effort by the ingest routes; read by
 * `/console/ops`. The definition is the one proposed in #899 and awaits the owner's confirmation.
 *
 * Only a request that identified an enrolled agent is counted: a refusal before that (bad proxy
 * secret, no certificate, unknown agent) has no agent to attribute it to.
 */
export const INGEST_KINDS = ["events", "detection", "beacon"] as const;
export type IngestKind = (typeof INGEST_KINDS)[number];

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

/** How long hourly rows are kept (the dashboard reads the last hour; the rest is for diagnosis). */
export const DEFAULT_INGEST_STATS_RETENTION_DAYS = 14;

/** What one request contributes to its hour bucket. */
export type IngestOutcome = {
  received: number;
  accepted: number;
  /** Entries of an accepted batch dropped as malformed. */
  skipped: number;
  /** HTTP status when the whole request was refused; `null` when it was accepted. */
  refusedStatus: number | null;
  /** Ingest time minus event time over the batch; `null` when it carries no event time. */
  lag: Lag | null;
};

/** Sum, count and worst of ingest time minus event time, ms: a row cannot hold a median, it holds these. */
export type Lag = { sumMs: number; count: number; maxMs: number };

/** The start of the hour `at` falls in. */
export function hourBucket(at: Date): Date {
  return new Date(Math.floor(at.getTime() / HOUR_MS) * HOUR_MS);
}

/** An accepted request of `received` entries, `skipped` of which were dropped. */
export function acceptedOutcome(received: number, skipped: number, lag: Lag | null): IngestOutcome {
  return { received, accepted: received - skipped, skipped, refusedStatus: null, lag };
}

/** A request refused with `status`; its entries (`received`, 0 if unread) were not taken. */
export function refusedOutcome(status: number, received = 0): IngestOutcome {
  return { received, accepted: 0, skipped: 0, refusedStatus: status, lag: null };
}

/**
 * Ingest time minus event time over a batch. Never negative: an event stamped in the future
 * (inside the clock-skew allowance) is on time, not early. `null` for an empty list.
 */
export function lagOf(eventTimes: Date[], now: Date): Lag | null {
  if (eventTimes.length === 0) return null;
  const lag: Lag = { sumMs: 0, count: eventTimes.length, maxMs: 0 };
  for (const at of eventTimes) {
    const ms = Math.max(0, now.getTime() - at.getTime());
    lag.sumMs += ms;
    lag.maxMs = Math.max(lag.maxMs, ms);
  }
  return lag;
}

/**
 * Adds `outcome` to the agent's bucket for `kind`. Never throws: a stats failure must not fail an
 * ingest or make the agent retry a batch the server already took.
 */
export async function recordIngest(
  db: Pick<PrismaClient, "$executeRaw">,
  tenantId: string,
  agentId: string,
  kind: IngestKind,
  outcome: IngestOutcome,
  now: Date
): Promise<void> {
  const refused4xx = outcome.refusedStatus !== null && outcome.refusedStatus < 500 ? 1 : 0;
  const refused5xx = outcome.refusedStatus !== null && outcome.refusedStatus >= 500 ? 1 : 0;
  const acceptedAt = outcome.refusedStatus === null ? now : null;
  try {
    await db.$executeRaw(Prisma.sql`
      INSERT INTO ingest_stats (id, tenant_id, agent_id, kind, bucket, received, accepted, skipped,
                                refused_4xx, refused_5xx, lag_sum_ms, lag_count, lag_max_ms,
                                last_accepted_at)
      VALUES (gen_random_uuid()::text, ${tenantId}, ${agentId}, ${kind}, ${hourBucket(now)},
              ${outcome.received}, ${outcome.accepted}, ${outcome.skipped}, ${refused4xx}, ${refused5xx},
              ${outcome.lag?.sumMs ?? 0}::bigint, ${outcome.lag?.count ?? 0},
              ${outcome.lag?.maxMs ?? null}::bigint, ${acceptedAt})
      ON CONFLICT (tenant_id, agent_id, kind, bucket) DO UPDATE SET
        received = ingest_stats.received + EXCLUDED.received,
        accepted = ingest_stats.accepted + EXCLUDED.accepted,
        skipped = ingest_stats.skipped + EXCLUDED.skipped,
        refused_4xx = ingest_stats.refused_4xx + EXCLUDED.refused_4xx,
        refused_5xx = ingest_stats.refused_5xx + EXCLUDED.refused_5xx,
        lag_sum_ms = ingest_stats.lag_sum_ms + EXCLUDED.lag_sum_ms,
        lag_count = ingest_stats.lag_count + EXCLUDED.lag_count,
        lag_max_ms = GREATEST(ingest_stats.lag_max_ms, EXCLUDED.lag_max_ms),
        last_accepted_at = GREATEST(ingest_stats.last_accepted_at, EXCLUDED.last_accepted_at)`);
  } catch (error) {
    console.error("Ingest stats update failed:", error);
  }
}

/** One agent's ingest health: per kind, when data last got in, and what was refused or late. */
export type AgentIngestHealth = {
  agentId: string;
  /** ISO time of the last accepted request per kind; `null` when none is retained. */
  lastAccepted: Record<IngestKind, string | null>;
  /** Over the window: whole requests refused (4xx / 5xx), and entries skipped as malformed. */
  refused4xx: number;
  refused5xx: number;
  skipped: number;
  /** Event lag over the window, ms: mean and worst; `null` when nothing with an event time came in. */
  lagMeanMs: number | null;
  lagMaxMs: number | null;
};

/** The dashboard window: the hour buckets from the one `now - 1 h` falls in (so 1 to 2 hours of data). */
export function windowStart(now: Date): Date {
  return hourBucket(new Date(now.getTime() - HOUR_MS));
}

type Row = {
  agent_id: string;
  kind: string;
  last_accepted_at: Date | null;
  refused_4xx: number | null;
  refused_5xx: number | null;
  skipped: number | null;
  lag_sum_ms: number | null;
  lag_count: number | null;
  lag_max_ms: number | null;
};

/** Ingest health of every agent of the tenant that has any retained row. */
export async function loadIngestHealth(
  db: Pick<PrismaClient, "$queryRaw">,
  tenantId: string,
  now: Date
): Promise<Map<string, AgentIngestHealth>> {
  const since = windowStart(now);
  const rows = await db.$queryRaw<Row[]>(Prisma.sql`
    SELECT agent_id, kind,
           MAX(last_accepted_at) AS last_accepted_at,
           (SUM(refused_4xx) FILTER (WHERE bucket >= ${since}))::int AS refused_4xx,
           (SUM(refused_5xx) FILTER (WHERE bucket >= ${since}))::int AS refused_5xx,
           (SUM(skipped) FILTER (WHERE bucket >= ${since}))::int AS skipped,
           (SUM(lag_sum_ms) FILTER (WHERE bucket >= ${since}))::float8 AS lag_sum_ms,
           (SUM(lag_count) FILTER (WHERE bucket >= ${since}))::int AS lag_count,
           (MAX(lag_max_ms) FILTER (WHERE bucket >= ${since}))::float8 AS lag_max_ms
    FROM ingest_stats
    WHERE tenant_id = ${tenantId}
    GROUP BY agent_id, kind`);
  return foldRows(rows);
}

/** Pure part of [`loadIngestHealth`]: one entry per agent, summed over its kinds. */
export function foldRows(rows: Row[]): Map<string, AgentIngestHealth> {
  const byAgent = new Map<string, AgentIngestHealth>();
  const lagTotals = new Map<string, { sum: number; count: number }>();
  for (const r of rows) {
    let h = byAgent.get(r.agent_id);
    if (!h) {
      h = {
        agentId: r.agent_id,
        lastAccepted: { events: null, detection: null, beacon: null },
        refused4xx: 0,
        refused5xx: 0,
        skipped: 0,
        lagMeanMs: null,
        lagMaxMs: null,
      };
      byAgent.set(r.agent_id, h);
    }
    if ((INGEST_KINDS as readonly string[]).includes(r.kind)) {
      h.lastAccepted[r.kind as IngestKind] = r.last_accepted_at?.toISOString() ?? null;
    }
    h.refused4xx += r.refused_4xx ?? 0;
    h.refused5xx += r.refused_5xx ?? 0;
    h.skipped += r.skipped ?? 0;
    if (r.lag_max_ms !== null) h.lagMaxMs = Math.max(h.lagMaxMs ?? 0, Number(r.lag_max_ms));
    lagTotals.set(r.agent_id, {
      sum: (lagTotals.get(r.agent_id)?.sum ?? 0) + Number(r.lag_sum_ms ?? 0),
      count: (lagTotals.get(r.agent_id)?.count ?? 0) + Number(r.lag_count ?? 0),
    });
  }
  for (const [agentId, { sum, count }] of Array.from(lagTotals)) {
    if (count > 0) byAgent.get(agentId)!.lagMeanMs = sum / count;
  }
  return byAgent;
}

/** Drops hourly rows older than the retention; returns how many. */
export async function pruneIngestStats(
  db: Pick<PrismaClient, "ingestStat">,
  now: Date,
  retentionDays = DEFAULT_INGEST_STATS_RETENTION_DAYS
): Promise<number> {
  const olderThan = new Date(now.getTime() - retentionDays * DAY_MS);
  return (await db.ingestStat.deleteMany({ where: { bucket: { lt: olderThan } } })).count;
}
