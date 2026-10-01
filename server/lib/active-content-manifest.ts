import crypto from "crypto";
import { prisma } from "@/lib/prisma";
import type { AuthenticatedAgent } from "@/lib/agent-auth";
import { ContentManifest, loadManifestBytes } from "@/lib/content-manifest";

export type ActiveManifest =
  | { ok: true; manifest: ContentManifest }
  | { ok: false; status: number; error: string };

/**
 * The content manifest an agent is currently offered: the newest `active`
 * release of its own tenant and ring, with the stored bytes checked against the
 * row's SHA-256 and the manifest's ring and version checked against the row.
 *
 * Shared by the manifest route (which serves it) and the artifact route (which
 * serves only what it lists), so the two cannot disagree about what "the
 * agent's manifest" is.
 */
export async function loadActiveManifest(agent: AuthenticatedAgent): Promise<ActiveManifest> {
  const { ring } = agent;
  const release = await prisma.contentRelease.findFirst({
    where: { tenantId: agent.tenantId, ring, status: "active" },
    orderBy: { releaseVersion: "desc" },
  });
  if (!release) {
    return { ok: false, status: 404, error: "No content release available for ring" };
  }

  // storage:// locally, a real object store URL in production (see loadManifestBytes).
  let manifestBytes: Buffer;
  try {
    manifestBytes = await loadManifestBytes(release.manifestUrl);
  } catch (error) {
    console.error("Content manifest fetch error:", error);
    return { ok: false, status: 502, error: "Manifest artifact unavailable" };
  }

  const actualSha256 = crypto.createHash("sha256").update(manifestBytes).digest("hex");
  if (actualSha256 !== release.manifestSha256) {
    console.error(
      `Manifest integrity mismatch for release ${release.id}: expected ${release.manifestSha256}, got ${actualSha256}`
    );
    return { ok: false, status: 502, error: "Manifest integrity check failed" };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(manifestBytes.toString("utf-8"));
  } catch {
    return { ok: false, status: 502, error: "Manifest is not valid JSON" };
  }

  const validation = ContentManifest.safeParse(parsed);
  if (!validation.success) {
    console.error("Content manifest shape validation error:", validation.error);
    return { ok: false, status: 502, error: "Manifest does not match the expected schema" };
  }

  const manifest = validation.data;
  if (manifest.ring !== ring) {
    // What was signed disagrees with the row it was looked up from; never
    // expected from the release creation path.
    console.error(
      `Manifest ring mismatch for release ${release.id}: row says ${ring}, manifest says ${manifest.ring}`
    );
    return { ok: false, status: 502, error: "Manifest ring mismatch" };
  }
  if (manifest.release_version !== release.releaseVersion) {
    console.error(
      `Manifest release_version mismatch for release ${release.id}: row says ${release.releaseVersion}, manifest says ${manifest.release_version}`
    );
    return { ok: false, status: 502, error: "Manifest release_version mismatch" };
  }
  return { ok: true, manifest };
}
