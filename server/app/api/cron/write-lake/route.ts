import { NextRequest, NextResponse } from "next/server";
import { verifyCronRequest } from "@/lib/cron-auth";
import { prisma } from "@/lib/prisma";
import { lakeStoreFromEnv } from "@/lib/lake-store";
import { DEFAULT_MAX_BATCHES, drainLakeQueue } from "@/lib/lake-writer";

/** A positive integer from the environment, or `fallback` when unset. A value that is set but wrong throws: a typo must not silently mean "keep the default". */
function positiveInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  const n = Number(raw);
  if (!Number.isInteger(n) || n <= 0) throw new Error(`${name} must be a positive integer, got "${raw}"`);
  return n;
}

/**
 * GET /api/cron/write-lake
 * Scheduled job: drains the telemetry lake queue into Parquet files (issue #77, ADR-0041). Takes
 * at most LAKE_WRITER_MAX_BATCHES queued batches (default 200) per call; the response says how many
 * are left, so a schedule that does not keep up shows as a `remaining` that grows.
 *
 * Authentication: CRON_SECRET bearer (`verifyCronRequest`).
 * 503 when the lake is off (`LAKE_DIR` unset): nothing was queued and there is nothing to write.
 */
export async function GET(req: NextRequest) {
  try {
    const denied = await verifyCronRequest(req);
    if (denied) return denied;

    const store = lakeStoreFromEnv();
    if (!store) {
      return NextResponse.json({ error: "The telemetry lake is off (LAKE_DIR is not set)" }, { status: 503 });
    }

    const maxBatches = positiveInt("LAKE_WRITER_MAX_BATCHES", DEFAULT_MAX_BATCHES);
    const result = await drainLakeQueue(prisma, store, { maxBatches });
    return NextResponse.json({ ...result, maxBatches });
  } catch (error) {
    console.error("Lake writer error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
