import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getTenantId } from "@/lib/tenant";

/**
 * GET /api/cases/[id]
 *
 * Response: { case, detections, narrative: (CaseNarrative & { stale }) | null }
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

    return NextResponse.json({ case: caseFields, detections, narrative });
  } catch (error) {
    console.error("Case detail query error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
