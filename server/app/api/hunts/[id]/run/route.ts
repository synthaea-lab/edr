import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getTenantId } from "@/lib/tenant";
import { runHunt } from "@/lib/hunt";

/**
 * POST /api/hunts/[id]/run — run the hunt now and return the new run. A query that
 * fails (statement timeout) still answers 200 with the run, its `error` set: the
 * history records it either way.
 */
export async function POST(req: NextRequest, { params }: { params: { id: string } }) {
  try {
    const tenantId = await getTenantId(req);
    const hunt = await prisma.hunt.findFirst({ where: { id: params.id, tenantId } });
    if (!hunt) return NextResponse.json({ error: "Hunt not found" }, { status: 404 });
    const run = await runHunt(prisma, hunt, "manual");
    return NextResponse.json({ run });
  } catch (error) {
    console.error("Hunt run error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
