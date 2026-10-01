import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getTenantId } from "@/lib/tenant";
import { loadFleet } from "@/lib/fleet";

/**
 * GET /api/ops/fleet
 * Console endpoint: the caller's tenant's agents with their latest health
 * beacon and a derived status (silent, degraded, no_beacon, healthy), worst first.
 *
 * Response: { agents: FleetAgent[] }
 */
export async function GET(req: NextRequest) {
  try {
    const tenantId = await getTenantId(req);
    return NextResponse.json({ agents: await loadFleet(prisma, tenantId) });
  } catch (error) {
    console.error("Fleet health query error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
