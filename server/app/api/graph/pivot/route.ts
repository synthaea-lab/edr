import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getTenantId } from "@/lib/tenant";
import { getSightingsOf, PREVALENCE_KINDS, type PrevalenceKind } from "@/lib/prevalence";
import { hashPivot, sortGraph } from "@/lib/graph";

/**
 * GET /api/graph/pivot?kind={kind}&key={key}
 *
 * "Everywhere this ran" (issue #72): every host that showed one hash, image
 * path or domain, as a two-level graph (the subject node plus one host node
 * per sighting). Sourced from `PrevalenceSighting`, not `Detection` — see
 * `lib/graph.ts`'s `hashPivot` for why that is wider, not narrower.
 *
 * `{ nodes: [], edges: [] }` (not a 404) for a key never seen on this
 * tenant's fleet, same convention as `GET /api/prevalence`.
 */
export async function GET(req: NextRequest) {
  try {
    const tenantId = await getTenantId(req);
    const { searchParams } = new URL(req.url);
    const kind = searchParams.get("kind");
    const key = searchParams.get("key");

    if (!kind || !(PREVALENCE_KINDS as readonly string[]).includes(kind)) {
      return NextResponse.json(
        { error: "Invalid kind", validKinds: PREVALENCE_KINDS },
        { status: 400 }
      );
    }
    if (!key) {
      return NextResponse.json({ error: "Missing 'key' query parameter" }, { status: 400 });
    }

    const sightings = await getSightingsOf(prisma, tenantId, kind as PrevalenceKind, key);
    if (!sightings) return NextResponse.json({ nodes: [], edges: [] });

    return NextResponse.json(sortGraph(hashPivot(kind as PrevalenceKind, key, sightings)));
  } catch (error) {
    console.error("Graph pivot query error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
