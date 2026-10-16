import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getTenantId } from "@/lib/tenant";
import { getSightingsOf, PREVALENCE_KINDS, type PrevalenceKind } from "@/lib/prevalence";
import { hashPivot, sortGraph, type PivotKind } from "@/lib/graph";

/** The pivot kinds this route actually renders — `PREVALENCE_KINDS` minus
 * `transition`, whose key is a `"parent -> child"` pair rather than one
 * entity (see `lib/graph.ts`'s `PivotKind`). */
const PIVOT_KINDS: readonly string[] = PREVALENCE_KINDS.filter((k) => k !== "transition");

/**
 * GET /api/graph/pivot?kind={kind}&key={key}
 *
 * "Everywhere this ran" (issue #72): every host that showed one hash, image
 * path or domain, as a two-level graph (the subject node plus one host node
 * per sighting). Sourced from `PrevalenceSighting`, not `Detection` — see
 * `lib/graph.ts`'s `hashPivot` for why that is wider, not narrower.
 *
 * `{ nodes: [], edges: [], truncated: false }` (not a 404) for a key never
 * seen on this tenant's fleet, same convention as `GET /api/prevalence`.
 * `truncated: true` means the fleet had more than `MAX_PIVOT_HOSTS` hosts for
 * this key and the list was capped — say so rather than let a console read a
 * capped list as the whole fleet.
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
    if (!PIVOT_KINDS.includes(kind)) {
      return NextResponse.json(
        { error: "'transition' pairs two entities, not one, and cannot be pivoted", validKinds: PIVOT_KINDS },
        { status: 400 }
      );
    }
    if (!key) {
      return NextResponse.json({ error: "Missing 'key' query parameter" }, { status: 400 });
    }

    const page = await getSightingsOf(prisma, tenantId, kind as PrevalenceKind, key);
    if (!page) return NextResponse.json({ nodes: [], edges: [], truncated: false });

    const graph = sortGraph(hashPivot(kind as PivotKind, key, page.sightings));
    return NextResponse.json({ ...graph, truncated: page.truncated });
  } catch (error) {
    console.error("Graph pivot query error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
