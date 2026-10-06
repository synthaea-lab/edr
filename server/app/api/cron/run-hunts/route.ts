import { NextRequest, NextResponse } from "next/server";
import { verifyCronRequest } from "@/lib/cron-auth";
import { prisma } from "@/lib/prisma";
import { dueHunts, pruneHuntRuns, runHunt } from "@/lib/hunt";

/** Hunts one call runs, so a backlog cannot make a single request unbounded. */
const MAX_HUNTS_PER_CALL = 50;

/**
 * GET /api/cron/run-hunts
 * Scheduled job (issue #61): runs the active scheduled hunts that are due (a hunt
 * whose last run is older than its `scheduleMinutes`, or that never ran), then prunes
 * run history to the newest HUNT_RUNS_KEPT per hunt. Call it every few minutes; the
 * hunt's own schedule decides whether it runs.
 *
 * Authentication: CRON_SECRET bearer (`verifyCronRequest`).
 */
export async function GET(req: NextRequest) {
  try {
    const denied = verifyCronRequest(req);
    if (denied) return denied;

    const due = await dueHunts(prisma);
    const batch = due.slice(0, MAX_HUNTS_PER_CALL);
    let failed = 0;
    for (const hunt of batch) {
      const run = await runHunt(prisma, hunt, "schedule");
      if (run.error) failed += 1;
    }
    const pruned = await pruneHuntRuns(prisma);
    return NextResponse.json({ due: due.length, ran: batch.length, failed, deferred: due.length - batch.length, pruned });
  } catch (error) {
    console.error("Run hunts error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
