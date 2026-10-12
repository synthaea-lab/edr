import crypto from "crypto";
import { readFile } from "fs/promises";
import path from "path";
import { ContentManifest, loadManifestBytes } from "@/lib/content-manifest";

/**
 * Publish-time checks for a content release (#665, the review of #782): everything an agent
 * would otherwise find out when the manifest is served, which is when it fails for the whole
 * ring at once. The Ed25519 signature is not checked here (the server never holds the key);
 * every agent verifies it.
 */
export type Publishable =
  | { ok: true; manifest: ContentManifest }
  | { ok: false; error: string };

/** An entry path is a relative path inside the artifact store, never one that leaves it. */
export function isSafeArtifactPath(entryPath: string): boolean {
  return (
    entryPath.length > 0 &&
    !entryPath.startsWith("/") &&
    !entryPath.includes("\\") &&
    !entryPath.includes("\0") &&
    entryPath.split("/").every((segment) => segment !== "" && segment !== "." && segment !== "..")
  );
}

/**
 * The manifest must be the one it is published as (bytes, schema with at least one entry,
 * ring and number), and every artifact it lists must already be in the store and hash to the
 * value the manifest signs.
 *
 * The store (`storage/artifacts/<path>`) is keyed by path and shared across releases, so a
 * release that lists content an earlier release later modified (a corrective release over a
 * changed path) needs those earlier bytes put back first: otherwise every agent that applies
 * it gets a 502 on that fetch and the bad content stays (ADR-0032).
 */
export async function validatePublishable(input: {
  ring: string;
  releaseVersion: number;
  manifestUrl: string;
  manifestSha256: string;
}): Promise<Publishable> {
  let bytes: Buffer;
  try {
    bytes = await loadManifestBytes(input.manifestUrl);
  } catch {
    return { ok: false, error: `The manifest at ${input.manifestUrl} could not be read` };
  }
  if (crypto.createHash("sha256").update(bytes).digest("hex") !== input.manifestSha256) {
    return { ok: false, error: "The manifest does not hash to manifestSha256" };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytes.toString("utf-8"));
  } catch {
    return { ok: false, error: "The manifest is not valid JSON" };
  }
  const shape = ContentManifest.safeParse(parsed);
  if (!shape.success) {
    return {
      ok: false,
      error: `The manifest does not match the content manifest schema (it must list at least one entry): ${shape.error.issues[0]?.message ?? "invalid"}`,
    };
  }
  const manifest = shape.data;
  if (manifest.ring !== input.ring) {
    return {
      ok: false,
      error: `The manifest is for ring ${manifest.ring}, not ${input.ring}`,
    };
  }
  if (manifest.release_version !== input.releaseVersion) {
    return {
      ok: false,
      error:
        `The manifest says release ${manifest.release_version}, but the control plane will ` +
        `number this release ${input.releaseVersion} (one above the ring's highest, rolled-back ` +
        `releases included): build and sign it as ${input.releaseVersion}`,
    };
  }
  for (const entry of manifest.entries) {
    if (!isSafeArtifactPath(entry.path)) {
      return { ok: false, error: `Entry path ${JSON.stringify(entry.path)} is not a path inside the artifact store` };
    }
    let stored: Buffer;
    try {
      stored = await readFile(path.join(process.cwd(), "storage", "artifacts", entry.path));
    } catch (error) {
      if ((error as { code?: string }).code === "ENOENT") {
        return { ok: false, error: `Artifact ${entry.path} is not in the store` };
      }
      throw error;
    }
    const actual = crypto.createHash("sha256").update(stored).digest("hex");
    if (actual !== entry.sha256) {
      return {
        ok: false,
        error:
          `Artifact ${entry.path} in the store hashes to ${actual}, but the manifest lists ` +
          `${entry.sha256}. The store is keyed by path and shared across releases: put the bytes ` +
          `this release lists back at ${entry.path} first (a corrective release that restores ` +
          `content a later release modified needs the earlier bytes back in the store).`,
      };
    }
  }
  return { ok: true, manifest };
}
