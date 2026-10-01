import { NextRequest, NextResponse } from "next/server";
import { verifyCronRequest } from "@/lib/cron-auth";
import { prisma } from "@/lib/prisma";
import {
  DEFAULT_MAX_ROWS_PER_TENANT,
  DEFAULT_RETENTION_DAYS,
  prunePrevalence,
} from "@/lib/prevalence";

const DAY_MS = 24 * 60 * 60 * 1000;

/** A positive integer from the environment, or `fallback` when unset. A value that is set but wrong throws: a typo must not silently mean "keep the default". */
function positiveInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  const n = Number(raw);
  if (!Number.isInteger(n) || n <= 0) throw new Error(`${name} must be a positive integer, got "${raw}"`);
  return n;
}

/**
 * GET /api/cron/prune-prevalence
 * Scheduled job: bounds the prevalence table (issue #76). Sightings not renewed
 * for PREVALENCE_RETENTION_DAYS (default 180) go, and a tenant over
 * PREVALENCE_MAX_ROWS_PER_TENANT (default 5,000,000) loses its oldest-seen rows.
 *
 * Authentication: CRON_SECRET bearer (`verifyCronRequest`).
 */
export async function GET(req: NextRequest) {
  try {
    const denied = verifyCronRequest(req);
    if (denied) return denied;

    const retentionDays = positiveInt("PREVALENCE_RETENTION_DAYS", DEFAULT_RETENTION_DAYS);
    const maxRowsPerTenant = positiveInt("PREVALENCE_MAX_ROWS_PER_TENANT", DEFAULT_MAX_ROWS_PER_TENANT);
    const olderThan = new Date(Date.now() - retentionDays * DAY_MS);

    const result = await prunePrevalence(prisma, { olderThan, maxRowsPerTenant });
    return NextResponse.json({ ...result, retentionDays, maxRowsPerTenant, olderThan: olderThan.toISOString() });
  } catch (error) {
    console.error("Prevalence prune error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
