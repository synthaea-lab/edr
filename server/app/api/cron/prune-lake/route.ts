import { NextRequest, NextResponse } from "next/server";
import { verifyCronRequest } from "@/lib/cron-auth";
import { prisma } from "@/lib/prisma";
import { lakeStoreFromEnv } from "@/lib/lake-store";
import { pruneLake } from "@/lib/lake-retention";

/**
 * GET /api/cron/prune-lake
 * Scheduled job: deletes the telemetry lake's `date=` partitions that have outlived their tenant's
 * `lake_retention_days`, and records each deletion in `lake_deletions` (issue #77, ADR-0041
 * section 5). Run it once a day; running it more often only repeats nothing.
 *
 * Authentication: CRON_SECRET bearer (`verifyCronRequest`).
 * 503 when the lake is off (`LAKE_DIR` unset). 500, with the counts, when a deleted partition still
 * lists files: the audit row says so, and a schedule that alerts on a 500 sees it.
 */
export async function GET(req: NextRequest) {
  try {
    const denied = await verifyCronRequest(req);
    if (denied) return denied;

    const store = lakeStoreFromEnv();
    if (!store) {
      return NextResponse.json({ error: "The telemetry lake is off (LAKE_DIR is not set)" }, { status: 503 });
    }

    const result = await pruneLake(prisma, store, new Date());
    return NextResponse.json(result, { status: result.notEmpty > 0 ? 500 : 200 });
  } catch (error) {
    console.error("Lake retention error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
