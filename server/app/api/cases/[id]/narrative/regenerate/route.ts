import { NextRequest, NextResponse } from "next/server";
import { Prisma } from "@prisma/client";
import { prisma } from "@/lib/prisma";
import { getTenantId, getUserId } from "@/lib/tenant";
import { buildEvidenceGraph } from "@/assistant/evidence-graph";
import { generateNarrative, NarrativeGenerationError } from "@/assistant/llm-client";

/**
 * POST /api/cases/[id]/narrative/regenerate
 *
 * Analyst-triggered (or system-triggered) case narration (issue #50).
 * Explicit action, not a side effect of viewing the case: an implicit
 * generate-on-GET would couple page loads to LLM latency/failures and
 * double-spend calls on repeated views.
 *
 * Response: { narrative: CaseNarrative }
 */
export async function POST(req: NextRequest, { params }: { params: { id: string } }) {
  try {
    const tenantId = await getTenantId(req);
    const userId = await getUserId(req);
    const caseId = params.id;

    const graph = await buildEvidenceGraph(tenantId, caseId);
    if (!graph) {
      return NextResponse.json({ error: "Case not found" }, { status: 404 });
    }
    if (graph.items.length === 0) {
      return NextResponse.json(
        { error: "Case has no evidence to narrate" },
        { status: 400 }
      );
    }

    const result = await generateNarrative(graph);

    const narrative = await prisma.caseNarrative.create({
      data: {
        tenantId,
        caseId,
        narrative: result.text,
        citations: result.citations as unknown as Prisma.InputJsonValue,
        model: result.model,
        provider: result.provider,
        promptVersion: result.promptVersion,
        generatedBy: `user:${userId}`,
      },
    });

    await prisma.auditLog.create({
      data: {
        tenantId,
        userId,
        action: "case.narrative.generate",
        resource: `cases/${caseId}`,
        details: {
          narrativeId: narrative.id,
          model: result.model,
          provider: result.provider,
          promptVersion: result.promptVersion,
          citationCount: result.citations.length,
        },
      },
    });

    return NextResponse.json({ narrative });
  } catch (error) {
    if (error instanceof NarrativeGenerationError) {
      console.error("Narrative generation error:", error.message);
      return NextResponse.json({ error: "Narrative generation failed" }, { status: 502 });
    }

    console.error("Narrative regeneration error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
