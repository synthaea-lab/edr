import { createHash } from "node:crypto";
import type { PrismaClient } from "@prisma/client";
import { buildCommonSetSnapshot, SnapshotTooLargeError } from "@/lib/common-set-snapshot";
import { countReportingHosts, getCommonHashes } from "@/lib/prevalence";
import {
  signSnapshotManifest,
  SnapshotManifest,
  type SnapshotSigner,
} from "@/lib/snapshot-manifest";

/**
 * Builds, guards, signs and stores one tenant's common-set snapshot (ADR-0033, #76 box 2). One
 * row per tenant: the latest. The numbers below are provisional starting points; calibrating
 * them on lab data is slice 6, and each can be set per call or from the environment.
 */
export type SnapshotParams = {
  /** K: a hash is common when seen on at least this many hosts. */
  minHosts: number;
  /** The fewest reporting hosts a tenant needs for a snapshot to be built at all. */
  minHostsCovered: number;
  falsePositiveRate: number;
  maxBytes: number;
  /** Most hashes one build may read; more is a refusal, never a truncation. */
  maxEntries: number;
  /** A build whose entry count falls below this fraction of the previous one is refused,
   * unless the hosts covered fell too (a truncated build, ADR-0033 decision 3). */
  minEntryFraction: number;
};

export const DEFAULT_SNAPSHOT_PARAMS: SnapshotParams = {
  minHosts: 2,
  minHostsCovered: 2,
  falsePositiveRate: 0.01,
  maxBytes: 4 * 1024 * 1024,
  maxEntries: 500_000,
  minEntryFraction: 0.5,
};

export type PublishOutcome =
  | { status: "published"; builtAt: number; hostsCovered: number; entryCount: number; size: number }
  | { status: "skipped"; reason: string };

type Previous = { builtAt: Date; hostsCovered: number; entryCount: number } | null;

/**
 * The guards run before a signature is requested (ADR-0033 decision 3), so a failure leaves
 * the previous snapshot served, to age out normally. `null` means the build may go ahead.
 */
export function guardFailure(
  params: SnapshotParams,
  build: { hostsCovered: number; entryCount: number; builtAt: number },
  previous: Previous
): string | null {
  if (build.hostsCovered < params.minHostsCovered) {
    return `only ${build.hostsCovered} hosts have reported, at least ${params.minHostsCovered} are needed`;
  }
  if (previous) {
    const previousAt = Math.floor(previous.builtAt.getTime() / 1000);
    if (build.builtAt <= previousAt) {
      return `built_at ${build.builtAt} is not later than the snapshot in force (${previousAt})`;
    }
    const truncated = build.entryCount < previous.entryCount * params.minEntryFraction;
    if (truncated && build.hostsCovered >= previous.hostsCovered) {
      return `${build.entryCount} entries against ${previous.entryCount} before, with no fall in hosts covered: a truncated build`;
    }
  }
  return null;
}

/**
 * One tenant. Never throws for an expected refusal (`skipped` with the reason); a database or
 * signing failure propagates, and the caller isolates it per tenant.
 */
export async function publishCommonSetSnapshot(
  db: Pick<PrismaClient, "$queryRaw" | "commonSetSnapshot">,
  tenantId: string,
  signer: SnapshotSigner,
  now: Date,
  overrides: Partial<SnapshotParams> = {}
): Promise<PublishOutcome> {
  const params = { ...DEFAULT_SNAPSHOT_PARAMS, ...overrides };
  const builtAt = Math.floor(now.getTime() / 1000);
  const previous = await db.commonSetSnapshot.findUnique({
    where: { tenantId },
    select: { builtAt: true, hostsCovered: true, entryCount: true },
  });

  const hostsCovered = await countReportingHosts(db, tenantId);
  // Cheap refusal first: nothing is read or built for a tenant that cannot pass.
  const early = guardFailure(params, { hostsCovered, entryCount: Number.MAX_SAFE_INTEGER, builtAt }, previous);
  if (early) return { status: "skipped", reason: early };

  const { hashes, truncated } = await getCommonHashes(db, tenantId, params.minHosts, params.maxEntries);
  // A filter missing common hashes reads them as rare: refuse, never drop (ADR-0020).
  if (truncated) {
    return { status: "skipped", reason: `more than ${params.maxEntries} common hashes: raise K or the entry cap` };
  }
  const late = guardFailure(params, { hostsCovered, entryCount: hashes.length, builtAt }, previous);
  if (late) return { status: "skipped", reason: late };

  let artifact: Uint8Array;
  try {
    artifact = buildCommonSetSnapshot({
      hashes,
      minHosts: params.minHosts,
      hostsCovered,
      builtAt,
      falsePositiveRate: params.falsePositiveRate,
      maxBytes: params.maxBytes,
    });
  } catch (error) {
    if (error instanceof SnapshotTooLargeError) return { status: "skipped", reason: error.message };
    throw error;
  }

  const manifest = SnapshotManifest.parse(
    await signSnapshotManifest(
      {
        schema_version: 1,
        kind: "common-set",
        built_at: builtAt,
        hosts_covered: hostsCovered,
        min_hosts: params.minHosts,
        entry_count: hashes.length,
        sha256: createHash("sha256").update(artifact).digest("hex"),
        size: artifact.length,
      },
      signer
    )
  );

  const data = {
    builtAt: new Date(builtAt * 1000),
    hostsCovered,
    minHosts: params.minHosts,
    entryCount: hashes.length,
    sha256: manifest.sha256,
    size: manifest.size,
    manifest,
    artifact: Buffer.from(artifact),
  };
  await db.commonSetSnapshot.upsert({ where: { tenantId }, create: { tenantId, ...data }, update: data });
  return { status: "published", builtAt, hostsCovered, entryCount: hashes.length, size: manifest.size };
}
