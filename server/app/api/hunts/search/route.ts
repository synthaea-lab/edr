import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getTenantId } from "@/lib/tenant";
import { MAX_CONCURRENT_SEARCHES_PER_TENANT, parseSearchRequest, searchFailure, searchWithinLimit } from "@/lib/hunt-search";
import { searchEventsWithinLimit } from "@/lib/hunt-events-search";
import { lakeReaderFromEnv } from "@/lib/lake-store";

/**
 * POST /api/hunts/search — one page of an ad-hoc search over the detection or case store, or over the
 * raw event archive.
 * Body: `{ source?: "detections" | "cases" | "events", query, cursor? }` where `query` is a `HuntQuery`
 * (detections), a `CaseQuery` (cases, `kind: "cases"`) or an `EventQuery` (events, `kind: "events"`),
 * validated as strictly as a saved hunt's.
 * Answers `{ source, rows, nextCursor, total }` (`total` only on the first page) for the first two, and
 * `{ source: "events", rows, truncated, incomplete, from, to }` for the archive: the newest events, one
 * page, no cursor, the typed columns only. Read-only and scoped to the session's tenant, which no part
 * of the body can change. A tenant may have a few searches in flight whatever the source (429 beyond
 * that, also across server instances); a search over its time limit is a 504; the archive is a 503
 * while the lake is off.
 */
export async function POST(req: NextRequest) {
  try {
    const tenantId = await getTenantId(req);
    const request = parseSearchRequest(await req.json().catch(() => null));
    const outcome =
      request.source === "events"
        ? await searchEventsWithinLimit(prisma, lakeReaderFromEnv(), tenantId, request.query)
        : await searchWithinLimit(prisma, tenantId, request);
    if (outcome.status === "lake_off") {
      return NextResponse.json({ error: "The event archive is not available (the telemetry lake is off)" }, { status: 503 });
    }
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
