import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getTenantId } from "@/lib/tenant";
import { loadRings } from "@/lib/rings";

/**
 * GET /api/ops/rings
 * Console endpoint: per ring, the content rollout state (serving, halted,
 * rolled_back, no_release), the newest and the served release version, and the
 * health of the agents in it.
 *
 * Response: { rings: RingStatus[], truncated: boolean }
 */
export async function GET(req: NextRequest) {
  try {
    const tenantId = await getTenantId(req);
    return NextResponse.json(await loadRings(prisma, tenantId));
  } catch (error) {
    console.error("Ring status query error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
