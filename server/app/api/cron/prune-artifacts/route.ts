import { NextRequest, NextResponse } from "next/server";
import { verifyCronRequest } from "@/lib/cron-auth";
import { prisma } from "@/lib/prisma";
import { pruneUnreferencedArtifacts } from "@/lib/content-retention";

/**
 * GET /api/cron/prune-artifacts
 * Scheduled job (#834): deletes the content artifacts (`storage/artifacts/<sha256>`) that no
 * release of any tenant or ring references any more. Fails closed: if a release's manifest cannot
 * be read, it answers 500 and deletes nothing. See `lib/content-retention.ts`.
 *
 * Authentication: CRON_SECRET bearer (`verifyCronRequest`).
 */
export async function GET(req: NextRequest) {
  try {
    const denied = await verifyCronRequest(req);
    if (denied) return denied;

    const result = await pruneUnreferencedArtifacts(prisma);
    return NextResponse.json(result);
  } catch (error) {
    console.error("Artifact prune error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
