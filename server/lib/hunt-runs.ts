import { Prisma, type PrismaClient } from "@prisma/client";
import type { RunLike } from "@/lib/hunt-view";

/**
 * What the hunt list shows of each hunt's runs (#61): the newest run, which says what is
 * happening, and the newest one that produced a result, which has the numbers. One query with
 * two lateral index lookups per hunt (`hunt_runs (hunt_id, started_at)`), so the page never
 * loads every kept run of every hunt (up to 100 each) to keep two of them.
 */
export type HuntRunSummary = {
  latest: RunLike | null;
  /** The newest finished run without an error: the numbers to show, when `latest` has none. */
  result: { startedAt: Date; matchCount: number; newMatchCount: number } | null;
};

type Row = {
  huntId: string;
  latestStartedAt: Date | null;
  latestFinishedAt: Date | null;
  latestError: string | null;
  resultStartedAt: Date | null;
  matchCount: number | null;
  newMatchCount: number | null;
};

export async function newestRunsByHunt(
  db: Pick<PrismaClient, "$queryRaw">,
  tenantId: string,
  huntIds: string[]
): Promise<Map<string, HuntRunSummary>> {
  const summaries = new Map<string, HuntRunSummary>();
  if (huntIds.length === 0) return summaries;
  const rows = await db.$queryRaw<Row[]>(Prisma.sql`
    SELECT h.id AS "huntId",
           l.started_at AS "latestStartedAt", l.finished_at AS "latestFinishedAt", l.error AS "latestError",
           g.started_at AS "resultStartedAt", g.match_count AS "matchCount", g.new_match_count AS "newMatchCount"
    FROM hunts h
    LEFT JOIN LATERAL (
      SELECT started_at, finished_at, error FROM hunt_runs
      WHERE hunt_id = h.id AND tenant_id = h.tenant_id
      ORDER BY started_at DESC LIMIT 1
    ) l ON true
    LEFT JOIN LATERAL (
      SELECT started_at, match_count, new_match_count FROM hunt_runs
      WHERE hunt_id = h.id AND tenant_id = h.tenant_id AND finished_at IS NOT NULL AND error IS NULL
      ORDER BY started_at DESC LIMIT 1
    ) g ON true
    WHERE h.tenant_id = ${tenantId} AND h.id IN (${Prisma.join(huntIds)})
  `);
  for (const row of rows) {
    summaries.set(row.huntId, {
      latest: row.latestStartedAt
        ? { startedAt: row.latestStartedAt, finishedAt: row.latestFinishedAt, error: row.latestError }
        : null,
      result:
        row.resultStartedAt && row.matchCount !== null && row.newMatchCount !== null
          ? { startedAt: row.resultStartedAt, matchCount: row.matchCount, newMatchCount: row.newMatchCount }
          : null,
    });
  }
  return summaries;
}
