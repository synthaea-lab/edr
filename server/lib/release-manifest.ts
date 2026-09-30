/**
 * Binary release manifest (ADR-0015, issue #30's update trigger): the signed
 * list of files that make up one agent release. This is the wire shape of
 * `crates/updater::ReleaseManifest` — the Rust agent is what verifies the
 * Ed25519 signature; the server stores and serves the manifest as signed
 * offline (it never holds the private key) and checks integrity and shape only.
 *
 * Unlike a content manifest it has no `ring` and no per-entry size: which
 * release an agent is offered is decided here from the agent's ring, and the
 * agent bounds downloads with its own constant.
 */

import { createHash } from "crypto";
import { readFile } from "fs/promises";
import path from "path";
import { z } from "zod";
import { loadManifestBytes } from "@/lib/content-manifest";

/** Windows device names, reserved regardless of extension (same list as the
 * agent-side `updater::content` path check). */
const WINDOWS_RESERVED = new Set([
  "CON", "PRN", "AUX", "NUL",
  "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
  "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
  "COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³",
  "CONIN$", "CONOUT$",
]);

/**
 * True if `p` is safe as a release entry path: the same rule the agent applies
 * (`ReleaseManifest::validate_entry_paths`), so the server never publishes a
 * release its agents would refuse outright.
 */
export function isSafeReleasePath(p: string): boolean {
  if (p === "" || p.startsWith("/") || p.includes("\\") || p.includes("\0")) {
    return false;
  }
  return p.split("/").every((segment) => {
    if (segment === "" || segment === "." || segment === "..") return false;
    if (segment.includes(":")) return false;
    if (segment.endsWith(".") || segment.endsWith(" ")) return false;
    const stem = segment.split(".")[0].toUpperCase();
    return !WINDOWS_RESERVED.has(stem);
  });
}

const SHA256_HEX = /^[a-f0-9]{64}$/;

export const ReleaseManifest = z
  .object({
    schema_version: z.literal(1),
    release_version: z.number().int().min(1),
    /** path (relative to the release directory) -> lowercase-hex SHA-256 */
    entries: z.record(z.string(), z.string().regex(SHA256_HEX)),
    signature: z.string(),
  })
  // Unknown fields would sit outside the signed canonical form.
  .strict()
  .superRefine((manifest, ctx) => {
    for (const entryPath of Object.keys(manifest.entries)) {
      if (!isSafeReleasePath(entryPath)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `unsafe release entry path: ${JSON.stringify(entryPath)}`,
        });
      }
    }
    if (Object.keys(manifest.entries).length === 0) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "release has no entries" });
    }
  });

export type ReleaseManifest = z.infer<typeof ReleaseManifest>;

/** Where a release's signed manifest is stored (`storage://` dev convention). */
export function releaseManifestPath(ring: string, version: number): string {
  return `manifests/release-${ring}-v${version}.json`;
}

/**
 * Filesystem path of one release artifact under `storage/releases/v<N>/`.
 * The caller must already have checked `isSafeReleasePath(entryPath)`.
 */
export function releaseArtifactFile(version: number, entryPath: string): string {
  return path.join(process.cwd(), "storage", "releases", `v${version}`, ...entryPath.split("/"));
}

export type LoadedManifest =
  | { ok: true; manifest: ReleaseManifest }
  | { ok: false; status: 502; error: string };

/**
 * Loads the manifest a `BinaryRelease` row points at and checks what the
 * server can check: bytes hash to `manifestSha256`, JSON matches the schema
 * (strict, safe paths), and the manifest's own `release_version` equals the
 * row's. Any failure is a 502 — a stored release that disagrees with itself is
 * a server-side fault, never the agent's.
 */
export async function loadReleaseManifest(release: {
  id: string;
  manifestUrl: string;
  manifestSha256: string;
  releaseVersion: number;
}): Promise<LoadedManifest> {
  let bytes: Buffer;
  try {
    bytes = await loadManifestBytes(release.manifestUrl);
  } catch (error) {
    console.error("Release manifest fetch error:", error);
    return { ok: false, status: 502, error: "Manifest artifact unavailable" };
  }

  const actual = createHash("sha256").update(bytes).digest("hex");
  if (actual !== release.manifestSha256) {
    console.error(
      `Release manifest integrity mismatch for ${release.id}: expected ${release.manifestSha256}, got ${actual}`
    );
    return { ok: false, status: 502, error: "Manifest integrity check failed" };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(bytes.toString("utf-8"));
  } catch {
    return { ok: false, status: 502, error: "Manifest is not valid JSON" };
  }

  const validation = ReleaseManifest.safeParse(parsed);
  if (!validation.success) {
    console.error("Release manifest shape validation error:", validation.error);
    return { ok: false, status: 502, error: "Manifest does not match the expected schema" };
  }

  if (validation.data.release_version !== release.releaseVersion) {
    console.error(
      `Release manifest version mismatch for ${release.id}: row says ${release.releaseVersion}, manifest says ${validation.data.release_version}`
    );
    return { ok: false, status: 502, error: "Manifest release_version mismatch" };
  }

  return { ok: true, manifest: validation.data };
}

export type LoadedArtifact =
  | { ok: true; bytes: Buffer }
  | { ok: false; status: 404 | 502; error: string };

/**
 * Reads one artifact from storage and checks it hashes to the manifest's
 * signed value — a corrupt or swapped stored file is a 502, not something the
 * agent should be handed to discover.
 */
export async function loadReleaseArtifact(
  version: number,
  entryPath: string,
  expectedSha256: string
): Promise<LoadedArtifact> {
  let bytes: Buffer;
  try {
    bytes = await readFile(releaseArtifactFile(version, entryPath));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return { ok: false, status: 404, error: "Artifact not found" };
    }
    console.error("Release artifact read error:", error);
    return { ok: false, status: 502, error: "Artifact unavailable" };
  }
  const actual = createHash("sha256").update(bytes).digest("hex");
  if (actual !== expectedSha256) {
    console.error(
      `Release artifact integrity mismatch v${version}/${entryPath}: manifest ${expectedSha256}, stored ${actual}`
    );
    return { ok: false, status: 502, error: "Stored artifact does not match the signed manifest" };
  }
  return { ok: true, bytes };
}
