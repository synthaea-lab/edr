import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getTenantId } from "@/lib/tenant";
import { HuntValidationError, parseHuntQuery } from "@/lib/hunt";
import { parseHuntInput, sameQuery } from "@/lib/hunt-input";

type Params = { params: { id: string } };

/**
 * GET /api/hunts/[id] — the hunt and its run history (newest first, `?limit=`, default 20).
 * PATCH — change name, description, query, schedule or active. A change to `query`
 *   bumps `version`; past runs keep the version and query they ran.
 * DELETE — the hunt and its history.
 *
 * Every lookup is `{ id, tenantId }`: another tenant's hunt is a 404, not a 403.
 */
export async function GET(req: NextRequest, { params }: Params) {
  try {
    const tenantId = await getTenantId(req);
    const limit = Math.min(Math.max(Number(new URL(req.url).searchParams.get("limit")) || 20, 1), 100);
    const hunt = await prisma.hunt.findFirst({ where: { id: params.id, tenantId } });
    if (!hunt) return NextResponse.json({ error: "Hunt not found" }, { status: 404 });
    const runs = await prisma.huntRun.findMany({
      where: { huntId: hunt.id, tenantId },
      orderBy: { startedAt: "desc" },
      take: limit,
    });
    return NextResponse.json({ hunt, runs });
  } catch (error) {
    console.error("Hunt get error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

export async function PATCH(req: NextRequest, { params }: Params) {
  try {
    const tenantId = await getTenantId(req);
    const input = parseHuntInput(await req.json().catch(() => null), true);
    const hunt = await prisma.hunt.findFirst({ where: { id: params.id, tenantId } });
    if (!hunt) return NextResponse.json({ error: "Hunt not found" }, { status: 404 });

    const queryChanged = input.query !== undefined && !sameQuery(input.query, parseHuntQuery(hunt.query));
    const updated = await prisma.hunt.update({
      where: { id: hunt.id },
      data: {
        ...(input.name !== undefined && { name: input.name }),
        ...(input.description !== undefined && { description: input.description }),
        ...(input.scheduleMinutes !== undefined && { scheduleMinutes: input.scheduleMinutes }),
        ...(input.active !== undefined && { active: input.active }),
        ...(queryChanged && { query: input.query as object, version: { increment: 1 } }),
      },
    });
    return NextResponse.json({ hunt: updated });
  } catch (error) {
    if (error instanceof HuntValidationError) {
      return NextResponse.json({ error: error.message }, { status: 400 });
    }
    console.error("Hunt update error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

export async function DELETE(req: NextRequest, { params }: Params) {
  try {
    const tenantId = await getTenantId(req);
    const { count } = await prisma.hunt.deleteMany({ where: { id: params.id, tenantId } });
    if (count === 0) return NextResponse.json({ error: "Hunt not found" }, { status: 404 });
    return new NextResponse(null, { status: 204 });
  } catch (error) {
    console.error("Hunt delete error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
