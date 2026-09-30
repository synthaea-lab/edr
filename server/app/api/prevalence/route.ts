import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getTenantId } from "@/lib/tenant";
import { getPrevalence, PREVALENCE_KINDS, type PrevalenceKind } from "@/lib/prevalence";

/**
 * GET /api/prevalence?kind={kind}&key={key}
 * Console endpoint (session): "seen on N hosts, first <date>" for one hash,
 * image path, transition or domain, scoped to the caller's tenant.
 *
 * `seen: false` (not a 404) for an unknown key: "never seen on this fleet" is
 * the answer the triage line exists to give, not an error.
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

    const prevalence = await getPrevalence(prisma, tenantId, kind as PrevalenceKind, key);
    if (!prevalence) return NextResponse.json({ kind, key, seen: false });
    return NextResponse.json({ kind, key, seen: true, ...prevalence });
  } catch (error) {
    console.error("Prevalence query error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
