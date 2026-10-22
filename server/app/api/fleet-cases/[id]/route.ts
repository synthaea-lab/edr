import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getTenantId } from "@/lib/tenant";
import { loadFleetCase } from "@/lib/fleet-case-load";

/**
 * GET /api/fleet-cases/[id] — one fleet case with its entities, its hosts and its detections
 * (oldest first, at most 200). Another tenant's fleet case is a 404, not a 403.
 */
export async function GET(req: NextRequest, { params }: { params: { id: string } }) {
  try {
    const tenantId = await getTenantId(req);
    const found = await loadFleetCase(prisma, tenantId, params.id);
    if (!found) return NextResponse.json({ error: "Fleet case not found" }, { status: 404 });
    return NextResponse.json(found);
  } catch (error) {
    console.error("Fleet case detail error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
