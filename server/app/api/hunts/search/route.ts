import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getTenantId } from "@/lib/tenant";
import { MAX_CONCURRENT_SEARCHES_PER_TENANT, parseSearchRequest, searchFailure, searchWithinLimit } from "@/lib/hunt-search";

/**
 * POST /api/hunts/search — one page of an ad-hoc search over the detection or case store.
 * Body: `{ source?: "detections" | "cases", query, cursor? }` where `query` is a `HuntQuery`
 * (detections) or a `CaseQuery` (cases, `kind: "cases"`), validated as strictly as a saved hunt's.
 * Answers `{ source, rows, nextCursor, total }` (`total` only on the first page). Read-only and
 * scoped to the session's tenant. A tenant may have a few searches in flight (429 beyond that,
 * also across server instances); a search over its time limit is a 504.
 */
export async function POST(req: NextRequest) {
  try {
    const tenantId = await getTenantId(req);
    const request = parseSearchRequest(await req.json().catch(() => null));
    const outcome = await searchWithinLimit(prisma, tenantId, request);
    if (outcome.status === "busy") {
      return NextResponse.json(
        { error: `At most ${MAX_CONCURRENT_SEARCHES_PER_TENANT} searches at a time per tenant; try again shortly` },
        { status: 429, headers: { "Retry-After": "5" } }
      );
    }
    return NextResponse.json(outcome.page);
  } catch (error) {
    const failure = searchFailure(error);
    if (failure.status === 500) console.error("Hunt search error:", error);
    return NextResponse.json({ error: failure.message }, { status: failure.status });
  }
}
