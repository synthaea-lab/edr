import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getTenantId } from "@/lib/tenant";
import { MAX_RUNS_PER_TENANT_PER_MINUTE, runHuntWithinLimit } from "@/lib/hunt";

/**
 * POST /api/hunts/[id]/run — run the hunt now and return the new run. A query that
 * fails (statement timeout) still answers 200 with the run, its `error` set to a short
 * message that never carries driver internals: the history records it either way. A tenant
 * that already started its per-minute allowance of runs gets a 429, also when the requests
 * arrive together. The run's row exists from the start with `finishedAt` null, so a reader of
 * the history sees a run in flight as a row with no `finishedAt`.
 */
export async function POST(req: NextRequest, { params }: { params: { id: string } }) {
  try {
    const tenantId = await getTenantId(req);
    const hunt = await prisma.hunt.findFirst({ where: { id: params.id, tenantId } });
    if (!hunt) return NextResponse.json({ error: "Hunt not found" }, { status: 404 });
    // The allowance is checked and the run's row written in one step, so parallel
    // requests cannot all pass the check (see `runHuntWithinLimit`).
    const run = await runHuntWithinLimit(prisma, hunt, "manual");
    if (!run) {
      return NextResponse.json(
        { error: `At most ${MAX_RUNS_PER_TENANT_PER_MINUTE} hunt runs per minute per tenant; try again shortly` },
        { status: 429, headers: { "Retry-After": "30" } }
      );
    }
    return NextResponse.json({ run });
  } catch (error) {
    console.error("Hunt run error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
