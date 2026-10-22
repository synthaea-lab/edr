import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getTenantId } from "@/lib/tenant";
import { HuntValidationError, parseHuntQuery } from "@/lib/hunt";
import { MAX_CONCURRENT_SEARCHES_PER_TENANT, searchFailure, searchWithinLimit } from "@/lib/hunt-search";

/**
 * GET /api/hunts/[id]/matches?cursor= — one page of what the hunt's query matches now, newest
 * first (a saved hunt's runs keep counts and ids; this is the detections themselves). Read-only,
 * does not record a run. Another tenant's hunt is a 404; a stored query that no longer parses
 * is a 422 (edit the hunt). Same limits as `POST /api/hunts/search`.
 */
export async function GET(req: NextRequest, { params }: { params: { id: string } }) {
  try {
    const tenantId = await getTenantId(req);
    const hunt = await prisma.hunt.findFirst({ where: { id: params.id, tenantId } });
    if (!hunt) return NextResponse.json({ error: "Hunt not found" }, { status: 404 });
    let query;
    try {
      query = parseHuntQuery(hunt.query);
    } catch (error) {
      if (!(error instanceof HuntValidationError)) throw error;
      return NextResponse.json({ error: "The hunt's stored query no longer parses; edit the hunt first" }, { status: 422 });
    }
    const cursor = req.nextUrl.searchParams.get("cursor") ?? undefined;
    const outcome = await searchWithinLimit(prisma, tenantId, { source: "detections", query, cursor });
    if (outcome.status === "busy") {
      return NextResponse.json(
        { error: `At most ${MAX_CONCURRENT_SEARCHES_PER_TENANT} searches at a time per tenant; try again shortly` },
        { status: 429, headers: { "Retry-After": "5" } }
      );
    }
    return NextResponse.json(outcome.page);
  } catch (error) {
    const failure = searchFailure(error);
    if (failure.status === 500) console.error("Hunt matches error:", error);
    return NextResponse.json({ error: failure.message }, { status: failure.status });
  }
}
