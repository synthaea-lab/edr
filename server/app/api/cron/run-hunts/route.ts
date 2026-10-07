import { NextRequest, NextResponse } from "next/server";
import { verifyCronRequest } from "@/lib/cron-auth";
import { prisma } from "@/lib/prisma";
import { dueHunts, pruneHuntRuns, runHunt } from "@/lib/hunt";

/** Hunts one call runs, and the time after which it starts no more, so a backlog cannot make one request run for minutes. The rest wait for the next call. */
const MAX_HUNTS_PER_CALL = 20;
const TIME_BUDGET_MS = 30_000;

/**
 * GET /api/cron/run-hunts
 * Scheduled job (issue #61): runs the active scheduled hunts that are due (a hunt
 * whose last run is older than its `scheduleMinutes`, or that never ran), then prunes
 * run history to the newest HUNT_RUNS_KEPT per hunt. Call it every few minutes; the
 * hunt's own schedule decides whether it runs. A call runs at most 20 hunts and starts no
 * new one after 30 s; what is left stays due for the next call.
 *
 * Authentication: CRON_SECRET bearer (`verifyCronRequest`).
 */
export async function GET(req: NextRequest) {
  try {
    const denied = await verifyCronRequest(req);
    if (denied) return denied;

    const due = await dueHunts(prisma);
    const deadline = Date.now() + TIME_BUDGET_MS;
    let ran = 0;
    let failed = 0;
    for (const hunt of due.slice(0, MAX_HUNTS_PER_CALL)) {
      if (Date.now() > deadline) break;
      const run = await runHunt(prisma, hunt, "schedule");
      ran += 1;
      if (run.error) failed += 1;
    }
    const pruned = await pruneHuntRuns(prisma);
    return NextResponse.json({ due: due.length, ran, failed, deferred: due.length - ran, pruned });
  } catch (error) {
    console.error("Run hunts error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
