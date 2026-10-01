import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getTenantId } from "@/lib/tenant";
import {
  getPrevalenceBatch,
  lookedUpKeys,
  observationsOfDetections,
  prevalenceKey,
  triageLines,
} from "@/lib/prevalence";

/**
 * GET /api/cases/[id]
 *
 * Response: { case, detections, narrative: (CaseNarrative & { stale }) | null,
 *             prevalence: { [detectionId]: { lines, omitted } } }
 *
 * `prevalence` is the fleet triage fact for what each detection's event touched
 * (issue #76): "seen on N hosts, first <date>", rarest first.
 *
 * `stale` is derived, not stored: true when a detection was attached to the
 * case after the latest narrative was generated.
 */
export async function GET(req: NextRequest, { params }: { params: { id: string } }) {
  try {
    const tenantId = await getTenantId(req);
    const caseId = params.id;

    const case_ = await prisma.case.findFirst({
      where: { id: caseId, tenantId },
      include: { detections: { orderBy: { timestamp: "desc" } } },
    });

    if (!case_) {
      return NextResponse.json({ error: "Case not found" }, { status: 404 });
    }

    const { detections, ...caseFields } = case_;

    const latestNarrative = await prisma.caseNarrative.findFirst({
      where: { caseId },
      orderBy: { generatedAt: "desc" },
    });

    const narrative = latestNarrative
      ? {
          ...latestNarrative,
          stale: detections.some((d) => d.updatedAt > latestNarrative.generatedAt),
        }
      : null;

    const caseObservations = observationsOfDetections(detections);
    const found = await getPrevalenceBatch(prisma, tenantId, caseObservations);
    const lookedUp = new Set(lookedUpKeys(caseObservations).map((o) => prevalenceKey(o.kind, o.key)));
    const prevalence = Object.fromEntries(
      detections.map((d) => [d.id, triageLines(observationsOfDetections([d]), found, lookedUp)])
    );

    return NextResponse.json({ case: caseFields, detections, narrative, prevalence });
  } catch (error) {
    console.error("Case detail query error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
