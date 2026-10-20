import { NextRequest, NextResponse } from "next/server";
import { verifyCronRequest } from "@/lib/cron-auth";
import { prisma } from "@/lib/prisma";
import { DEFAULT_SNAPSHOT_PARAMS, publishCommonSetSnapshot, type SnapshotParams } from "@/lib/snapshot-publish";
import { loadSnapshotSigner } from "@/lib/snapshot-manifest";

/** A positive number from the environment, or `fallback` when unset; a value that is set but wrong throws. */
function numberFromEnv(name: string, fallback: number, integer: boolean): number {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0 || (integer && !Number.isInteger(n))) {
    throw new Error(`${name} must be a positive ${integer ? "integer" : "number"}, got "${raw}"`);
  }
  return n;
}

/** Provisional starting points, set from the environment until slice 6 calibrates them. */
function paramsFromEnv(): SnapshotParams {
  const d = DEFAULT_SNAPSHOT_PARAMS;
  return {
    minHosts: numberFromEnv("SNAPSHOT_MIN_HOSTS", d.minHosts, true),
    minHostsCovered: numberFromEnv("SNAPSHOT_MIN_HOSTS_COVERED", d.minHostsCovered, true),
    falsePositiveRate: numberFromEnv("SNAPSHOT_FALSE_POSITIVE_RATE", d.falsePositiveRate, false),
    maxBytes: numberFromEnv("SNAPSHOT_MAX_BYTES", d.maxBytes, true),
    maxEntries: numberFromEnv("SNAPSHOT_MAX_ENTRIES", d.maxEntries, true),
    minEntryFraction: numberFromEnv("SNAPSHOT_MIN_ENTRY_FRACTION", d.minEntryFraction, false),
  };
}

/**
 * GET /api/cron/build-snapshots
 * Scheduled job (ADR-0033, #76 box 2): builds, guards, signs and stores each tenant's common-set
 * snapshot. Meant to run daily. Without a configured signer (`SYNTHAEA_SNAPSHOT_SIGNER`, today only
 * the public test key) it builds nothing and answers 503: the endpoints then have nothing to serve
 * and agents keep what they have. One tenant's failure does not stop the others.
 *
 * Authentication: CRON_SECRET bearer (`verifyCronRequest`).
 */
export async function GET(req: NextRequest) {
  try {
    const denied = await verifyCronRequest(req);
    if (denied) return denied;

    const signer = loadSnapshotSigner();
    if (!signer) {
      return NextResponse.json({ error: "Snapshot signing is not configured" }, { status: 503 });
    }
    const params = paramsFromEnv();
    const now = new Date();

    const tenants = await prisma.tenant.findMany({ select: { id: true } });
    const results: { tenantId: string; status: string; reason?: string }[] = [];
    for (const { id } of tenants) {
      try {
        const outcome = await publishCommonSetSnapshot(prisma, id, signer, now, params);
        results.push(
          outcome.status === "published"
            ? { tenantId: id, status: "published" }
            : { tenantId: id, status: "skipped", reason: outcome.reason }
        );
      } catch (error) {
        console.error(`Snapshot build failed for tenant ${id}:`, error);
        results.push({ tenantId: id, status: "failed" });
      }
    }
    return NextResponse.json({ tenants: results.length, results });
  } catch (error) {
    console.error("Snapshot build cron error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
