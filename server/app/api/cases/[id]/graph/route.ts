import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getTenantId } from "@/lib/tenant";
import { caseSubgraph, sortGraph } from "@/lib/graph";

/**
 * GET /api/cases/[id]/graph
 *
 * This case's subgraph (issue #72): every host, process, file, network
 * endpoint/domain and identity its detections' events name, and the edges
 * between them. See `lib/graph.ts` for what it is built from and why.
 *
 * Response: { nodes: GraphNode[], edges: GraphEdge[] }
 */
export async function GET(req: NextRequest, { params }: { params: { id: string } }) {
  try {
    const tenantId = await getTenantId(req);
    const caseId = params.id;

    // `tenantId` repeated on the relation filter, not left to the `caseId`
    // match alone: nothing in this codebase can actually attach another
    // tenant's detection to this tenant's case today (the grouping cron
    // groups a tenant's own detections into that tenant's own cases), but
    // this route does not need to stay correct only because of that — a
    // future bug elsewhere must not become a cross-tenant graph leak here
    // (caught by the integration test below forcing exactly that shape).
    const case_ = await prisma.case.findFirst({
      where: { id: caseId, tenantId },
      include: {
        detections: { where: { tenantId }, select: { agentId: true, event: true, timestamp: true } },
      },
    });
    if (!case_) {
      return NextResponse.json({ error: "Case not found" }, { status: 404 });
    }

    return NextResponse.json(sortGraph(caseSubgraph(case_.detections)));
  } catch (error) {
    console.error("Case graph query error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
