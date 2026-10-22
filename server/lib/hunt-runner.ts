import { Prisma, type PrismaClient } from "@prisma/client";
import {
  describeRunError,
  executeHunt,
  HUNT_RUNS_KEPT,
  HUNT_TRANSACTION_TIMEOUT_MS,
  MAX_RUNS_PER_TENANT_PER_MINUTE,
  parseHuntQuery,
  type ExecuteOptions,
} from "@/lib/hunt";
import { notifyHuntNewMatches } from "@/lib/notify/hunt-matches";

/**
 * Running saved hunts and keeping their history (#61): the part of the hunt code that talks to the
 * database's run history and to the notification outbox. **Server only.** The query model, its
 * validation and the constants stay in `lib/hunt.ts`, which client components import; this module
 * reaches `node:crypto` through the outbox, so a client component that imported it would break the
 * browser bundle (#926). `tests/unit/client-bundle-imports.test.ts` fails when one does.
 */

export type RunTrigger = "manual" | "schedule";

type HuntToRun = { id: string; tenantId: string; version: number; query: unknown };

/**
 * Runs a hunt and appends its HuntRun. A failing query (timeout, database error) is
 * recorded on the run, not thrown: the history says the hunt could not run, which is
 * itself worth knowing on a schedule.
 *
 * The run's row is written when it starts (`finishedAt` null) and completed when it
 * ends, so a run in flight is visible in the history and counted against the tenant's
 * allowance. A run whose server died is left with `finishedAt` null; it is never taken
 * for the previous run (see `newSince` below).
 */
export async function runHunt(
  prisma: PrismaClient,
  hunt: HuntToRun,
  trigger: RunTrigger,
  now: Date = new Date(),
  options: ExecuteOptions = {}
) {
  // With no limit a run is always started, so this is never null.
  return (await startAndExecute(prisma, hunt, trigger, now, options, undefined))!;
}

/**
 * Like `runHunt`, but starts the run only if `tenantId` has started fewer than `limit`
 * runs in the last minute, and returns null when it has. The check and the insert of the
 * run's row are one step under a per-tenant lock, so requests sent together cannot all
 * see "below the limit" and all run: the limit holds for parallel requests, not only for
 * runs chained one after another.
 */
export async function runHuntWithinLimit(
  prisma: PrismaClient,
  hunt: HuntToRun,
  trigger: RunTrigger,
  limit: number = MAX_RUNS_PER_TENANT_PER_MINUTE,
  now: Date = new Date(),
  options: ExecuteOptions = {}
) {
  return startAndExecute(prisma, hunt, trigger, now, options, limit);
}

async function startAndExecute(
  prisma: PrismaClient,
  hunt: HuntToRun,
  trigger: RunTrigger,
  now: Date,
  options: ExecuteOptions,
  limit: number | undefined
) {
  // The previous run is the last one that produced a result: a run that is still going,
  // or that never finished, has nothing to compare with and must not move the baseline.
  const previous = await prisma.huntRun.findFirst({
    where: { huntId: hunt.id, tenantId: hunt.tenantId, error: null, finishedAt: { not: null } },
    orderBy: { startedAt: "desc" },
    select: { startedAt: true },
  });
  const started = await prisma.$transaction(
    async (tx) => {
      if (limit !== undefined) {
        // Serializes the count and the insert for this tenant only. Held until the
        // transaction ends, which is a few milliseconds: the search runs after it.
        await tx.$executeRaw(Prisma.sql`SELECT pg_advisory_xact_lock(hashtext(${`hunt_runs:${hunt.tenantId}`}))`);
        const recent = await tx.huntRun.count({
          where: { tenantId: hunt.tenantId, startedAt: { gt: new Date(now.getTime() - 60_000) } },
        });
        if (recent >= limit) return null;
      }
      return tx.huntRun.create({
        data: {
          huntId: hunt.id,
          tenantId: hunt.tenantId,
          startedAt: now,
          queryVersion: hunt.version,
          query: (hunt.query ?? {}) as Prisma.InputJsonValue,
          sampleDetectionIds: [],
          trigger,
        },
      });
    },
    { timeout: HUNT_TRANSACTION_TIMEOUT_MS, maxWait: HUNT_TRANSACTION_TIMEOUT_MS }
  );
  if (!started) return null;
  try {
    // Validated here, inside the try, so one hunt whose stored query no longer parses
    // is a failed run in its history and not an error that stops the cron's batch.
    const query = parseHuntQuery(hunt.query);
    const result = await executeHunt(prisma, hunt.tenantId, query, now, previous?.startedAt ?? null, options);
    const run = await prisma.huntRun.update({
      where: { id: started.id },
      data: {
        finishedAt: new Date(),
        matchCount: result.matchCount,
        newMatchCount: result.newMatchCount,
        sampleDetectionIds: result.sample,
      },
    });
    // After the run is recorded. `notifyHuntNewMatches` does not throw: a notification problem
    // is logged, never a second (failed) run row for the same run (ADR-0036, #863).
    await notifyHuntNewMatches(prisma, hunt, run);
    return run;
  } catch (error) {
    console.error("Hunt run failed:", hunt.id, error);
    return prisma.huntRun.update({
      where: { id: started.id },
      data: { finishedAt: new Date(), sampleDetectionIds: [], error: describeRunError(error) },
    });
  }
}

/** Active scheduled hunts whose last run (any outcome) is older than their schedule, or that never ran. */
export async function dueHunts(prisma: PrismaClient, now: Date = new Date()) {
  const scheduled = await prisma.hunt.findMany({
    where: { active: true, scheduleMinutes: { not: null } },
    orderBy: { createdAt: "asc" },
  });
  if (scheduled.length === 0) return [];
  // One grouped query for every hunt's last run, not one per hunt.
  const lastRuns = await prisma.huntRun.groupBy({
    by: ["huntId"],
    where: { huntId: { in: scheduled.map((h) => h.id) } },
    _max: { startedAt: true },
  });
  const last = new Map(lastRuns.map((r) => [r.huntId, r._max.startedAt]));
  return scheduled.filter((hunt) => {
    const lastStart = last.get(hunt.id);
    const intervalMs = (hunt.scheduleMinutes as number) * 60_000;
    return !lastStart || now.getTime() - lastStart.getTime() >= intervalMs;
  });
}

/** Deletes all but the newest `keep` runs of every hunt; returns how many went. */
export async function pruneHuntRuns(prisma: PrismaClient, keep: number = HUNT_RUNS_KEPT): Promise<number> {
  const result = await prisma.$executeRaw`
    DELETE FROM hunt_runs WHERE id IN (
      SELECT id FROM (
        SELECT id, ROW_NUMBER() OVER (PARTITION BY hunt_id ORDER BY started_at DESC, id) AS rn
        FROM hunt_runs
      ) ranked WHERE rn > ${keep}
    )`;
  return Number(result);
}
