import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getTenantId, getUserId } from "@/lib/tenant";
import { HuntValidationError } from "@/lib/hunt";
import { parseHuntInput } from "@/lib/hunt-input";

/** Hunts a tenant may have; a bound on rows and on what the cron has to run. */
const MAX_HUNTS_PER_TENANT = 200;

/**
 * GET /api/hunts — the tenant's hunts, newest first, each with its latest run.
 * POST /api/hunts — create one: { name, description?, query, scheduleMinutes? }.
 */
export async function GET(req: NextRequest) {
  try {
    const tenantId = await getTenantId(req);
    const hunts = await prisma.hunt.findMany({
      where: { tenantId },
      orderBy: { createdAt: "desc" },
      include: { runs: { orderBy: { startedAt: "desc" }, take: 1 } },
    });
    return NextResponse.json({
      hunts: hunts.map(({ runs, ...hunt }) => ({ ...hunt, lastRun: runs[0] ?? null })),
    });
  } catch (error) {
    console.error("Hunt list error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

export async function POST(req: NextRequest) {
  try {
    const tenantId = await getTenantId(req);
    const ownerId = await getUserId(req);
    const input = parseHuntInput(await req.json().catch(() => null), false);

    if ((await prisma.hunt.count({ where: { tenantId } })) >= MAX_HUNTS_PER_TENANT) {
      return NextResponse.json({ error: `A tenant may have at most ${MAX_HUNTS_PER_TENANT} hunts` }, { status: 409 });
    }
    const hunt = await prisma.hunt.create({
      data: {
        tenantId,
        ownerId,
        name: input.name as string,
        description: input.description ?? null,
        query: input.query as object,
        scheduleMinutes: input.scheduleMinutes ?? null,
        active: input.active ?? true,
      },
    });
    return NextResponse.json({ hunt }, { status: 201 });
  } catch (error) {
    if (error instanceof HuntValidationError) {
      return NextResponse.json({ error: error.message }, { status: 400 });
    }
    console.error("Hunt create error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
