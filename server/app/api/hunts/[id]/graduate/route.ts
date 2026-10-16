import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getTenantId } from "@/lib/tenant";
import { HuntValidationError, parseHuntQuery } from "@/lib/hunt";
import { draftRuleFromHunt, parseGraduationRequest } from "@/lib/hunt-graduation";

/**
 * POST /api/hunts/[id]/graduate — a draft Sigma rule from a saved hunt (#618).
 * Body: `{ platform: "linux" | "windows" | "macos", negative?: { image, cmdline, note? } }`.
 * Answers 200 with `files` (`rules/sigma/<platform>/<slug>.yml` and `.samples.json`, as text)
 * and `todo` (what a person must still do), or 422 with `problems` when no draft can be
 * made. It reads the detections of the hunt's newest finished run and writes nothing:
 * the files are for a person to review and open as a PR.
 */
export async function POST(req: NextRequest, { params }: { params: { id: string } }) {
  try {
    const tenantId = await getTenantId(req);
    const request = parseGraduationRequest(await req.json().catch(() => null));
    const hunt = await prisma.hunt.findFirst({ where: { id: params.id, tenantId } });
    if (!hunt) return NextResponse.json({ error: "Hunt not found" }, { status: 404 });

    const run = await prisma.huntRun.findFirst({
      where: { huntId: hunt.id, tenantId, finishedAt: { not: null }, error: null },
      orderBy: { startedAt: "desc" },
    });
    if (!run) {
      return NextResponse.json(
        { error: "This hunt has no finished run to graduate from; run it first", problems: ["no finished run"] },
        { status: 422 }
      );
    }
    // A stored query that no longer parses (ADR-0025 point 4) is the hunt's fault, not the request's.
    let query;
    try {
      query = parseHuntQuery(hunt.query);
    } catch (error) {
      if (!(error instanceof HuntValidationError)) throw error;
      return NextResponse.json(
        { error: "The hunt's stored query no longer parses; edit the hunt first", problems: [error.message] },
        { status: 422 }
      );
    }
    const ids = Array.isArray(run.sampleDetectionIds)
      ? run.sampleDetectionIds.filter((id): id is string => typeof id === "string")
      : [];
    const detections = await prisma.detection.findMany({
      where: { tenantId, id: { in: ids } },
      select: { id: true, technique: true, severity: true, event: true, timestamp: true },
      orderBy: { timestamp: "desc" },
    });
    const result = draftRuleFromHunt(
      { id: hunt.id, name: hunt.name, description: hunt.description, version: hunt.version, query },
      detections,
      request
    );
    if (!result.ok) {
      return NextResponse.json({ error: "No draft rule can be made from this hunt", problems: result.problems }, { status: 422 });
    }
    return NextResponse.json({ files: result.files, todo: result.todo });
  } catch (error) {
    if (error instanceof HuntValidationError) {
      return NextResponse.json({ error: error.message }, { status: 400 });
    }
    console.error("Hunt graduate error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
