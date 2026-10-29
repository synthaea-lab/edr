import { readdir, stat, unlink } from "fs/promises";
import path from "path";
import type { PrismaClient } from "@prisma/client";
import { ContentManifest, loadManifestBytes } from "@/lib/content-manifest";

/**
 * Retention for the content artifact store (#834, follow-up of #804).
 *
 * The store is keyed by content hash (`storage/artifacts/<sha256>`), so a release's bytes stay
 * available for as long as something references them, and nothing used to remove them after. This
 * removes the files no release references any more.
 *
 * The referenced set is every `sha256` listed by the manifest of **every** `ContentRelease` row,
 * whatever its status, tenant or ring: a `rolled_back` or `halted` release can still be the one an
 * offline or stuck agent is served, and a corrective release's own manifest lists the hash it
 * restores. A mistake here deletes bytes a served release depends on, so two rules:
 *
 * - **Fail closed.** If any release's manifest cannot be read or parsed, nothing is deleted (the
 *   run throws), since that manifest's hashes are unknown.
 * - **A grace period.** An artifact is uploaded before the release that lists it is published, so
 *   a file younger than `minAgeMs` is kept even when no release lists it yet; this is the race with
 *   a publish in flight.
 */
export const DEFAULT_MIN_AGE_MS = 24 * 60 * 60 * 1000;

const HASH_NAME = /^[a-f0-9]{64}$/;

export type ArtifactRetentionOptions = {
  now?: Date;
  minAgeMs?: number;
  artifactsDir?: string;
  /** How a manifest URL is read; the real one by default. */
  loadBytes?: (manifestUrl: string) => Promise<Buffer>;
};

export type ArtifactRetentionResult = {
  releases: number;
  referenced: number;
  deleted: number;
  keptReferenced: number;
  keptRecent: number;
};

/** Every artifact hash listed by any release's manifest. Throws when a manifest cannot be read or is not a content manifest. */
export async function referencedArtifactHashes(
  prisma: Pick<PrismaClient, "contentRelease">,
  loadBytes: (manifestUrl: string) => Promise<Buffer> = loadManifestBytes
): Promise<{ hashes: Set<string>; releases: number }> {
  const releases = await prisma.contentRelease.findMany({
    select: { id: true, manifestUrl: true },
  });
  const hashes = new Set<string>();
  for (const release of releases) {
    let manifest: ContentManifest;
    try {
      const bytes = await loadBytes(release.manifestUrl);
      manifest = ContentManifest.parse(JSON.parse(bytes.toString("utf-8")));
    } catch (error) {
      throw new Error(
        `release ${release.id}: its manifest at ${release.manifestUrl} cannot be read, so which artifacts it lists is unknown; nothing was deleted (${(error as Error).message})`
      );
    }
    for (const entry of manifest.entries) hashes.add(entry.sha256);
  }
  return { hashes, releases: releases.length };
}

/** Deletes the files of the artifact store that no release references and that are older than the grace period. */
export async function pruneUnreferencedArtifacts(
  prisma: Pick<PrismaClient, "contentRelease">,
  options: ArtifactRetentionOptions = {}
): Promise<ArtifactRetentionResult> {
  const now = options.now ?? new Date();
  const minAgeMs = options.minAgeMs ?? DEFAULT_MIN_AGE_MS;
  const dir = options.artifactsDir ?? path.join(process.cwd(), "storage", "artifacts");

  // Read the referenced set first: a file listed by a release published while this runs is
  // protected by the grace period, not by this set.
  const { hashes, releases } = await referencedArtifactHashes(prisma, options.loadBytes);

  let names: string[];
  try {
    names = await readdir(dir);
  } catch (error) {
    if ((error as { code?: string }).code === "ENOENT") {
      return { releases, referenced: hashes.size, deleted: 0, keptReferenced: 0, keptRecent: 0 };
    }
    throw error;
  }

  const result: ArtifactRetentionResult = { releases, referenced: hashes.size, deleted: 0, keptReferenced: 0, keptRecent: 0 };
  for (const name of names) {
    // Only files named by a hash are the store's; anything else in the directory is not ours to delete.
    if (!HASH_NAME.test(name)) continue;
    if (hashes.has(name)) {
      result.keptReferenced++;
      continue;
    }
    const file = path.join(dir, name);
    const info = await stat(file);
    if (!info.isFile()) continue;
    if (now.getTime() - info.mtimeMs < minAgeMs) {
      result.keptRecent++;
      continue;
    }
    await unlink(file);
    result.deleted++;
  }
  return result;
}
