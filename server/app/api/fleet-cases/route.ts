import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getTenantId } from "@/lib/tenant";
import { listFleetCases } from "@/lib/fleet-case-load";

/**
 * GET /api/fleet-cases — the tenant's fleet cases (#62), the ones `cron/join-fleet-cases` made
 * by joining detections of several hosts on a shared hash or identity. Newest activity first, at
 * most 200 (`truncated` says there were more).
 * Response: `{ cases: FleetCaseSummary[], truncated }`.
 */
export async function GET(req: NextRequest) {
  try {
    const tenantId = await getTenantId(req);
    return NextResponse.json(await listFleetCases(prisma, tenantId));
  } catch (error) {
    console.error("Fleet case list error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
