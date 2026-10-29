import crypto from "crypto";
import { readFile } from "fs/promises";
import path from "path";
import { ContentManifest, loadManifestBytes } from "@/lib/content-manifest";
import { buildFeed, isValidFeedName } from "@/lib/ioc-feed";
import { isPublicSuffix } from "@/lib/public-suffix";

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
 * The IOC feeds an agent loads are every `*.txt` under `<content_root>/ioc/` plus an optional
 * `ioc/VERSION` (`agent/src/ioc.rs`), picked by path: the agent never looks at an entry's `type`.
 * So the pairing is enforced here, in both directions: only an `ioc` entry may sit under `ioc/`
 * (a `rule` entry named `ioc/x.txt` would otherwise be loaded as a feed), and an `ioc` entry may
 * only be a feed or the version file. A feed must also be one the device would load whole: every
 * line a `sha256:`, `ip:` or `domain:` indicator that passes the device's own rules and the
 * public-suffix check (`buildFeed`), because a bad line is skipped on the device without anyone
 * being told, and a listed `co.uk` would flag a whole country. Returns the reason, or `null`.
 */
export function iocEntryError(entry: { path: string; type: string }, stored: Buffer): string | null {
  const underIoc = entry.path.startsWith("ioc/");
  if (entry.type !== "ioc") {
    return underIoc
      ? `Entry ${entry.path} is under ioc/, which only an entry of type "ioc" may be (the agent loads it as a feed whatever its type)`
      : null;
  }
  if (!underIoc) return `Entry ${entry.path} has type "ioc" but is not under ioc/`;
  const file = entry.path.slice("ioc/".length);
  const text = stored.toString("utf8");
  if (file === "VERSION") {
    return /^[\x21-\x7e]{1,64}\n?$/.test(text)
      ? null
      : `Entry ioc/VERSION must be one line of 1 to 64 printable characters`;
  }
  const stem = file.endsWith(".txt") ? file.slice(0, -".txt".length) : "";
  if (!isValidFeedName(stem)) {
    return `Entry ${entry.path} is not a feed: expected ioc/<name>.txt with a name of lowercase letters, digits, ".", "_" or "-" (1 to 64 characters)`;
  }
  let result;
  try {
    result = buildFeed({ feed: stem, text, isPublicSuffix });
  } catch (error) {
    if (error instanceof RangeError) return `Feed ${entry.path} is refused: ${error.message}`;
    throw error;
  }
  if (result.rejectedTotal > 0) {
    const first = result.rejected[0];
    return (
      `Feed ${entry.path} has ${result.rejectedTotal} line(s) the device would refuse; ` +
      `the first is line ${first.line}: ${first.reason} (${JSON.stringify(first.value)})`
    );
  }
  return null;
}

/**
 * The manifest must be the one it is published as (bytes, schema with at least one entry,
 * ring and number), and every artifact it lists must already be in the store under its own
 * hash.
 *
 * The store (`storage/artifacts/<sha256>`, #804) is keyed by content hash, not by path: a
 * release that lists content an earlier release later modified (a corrective release over a
 * changed path, ADR-0032) needs nothing restored first, since the earlier bytes never moved —
 * they are still sitting under their own hash, wherever they were first uploaded. The only way
 * this still refuses (422) is an artifact that was genuinely never uploaded under the hash the
 * manifest lists.
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
    // `path` no longer addresses the store (the store is keyed by `sha256`), but it is
    // still what the agent queries `/api/content/artifact` with and still needs to be a
    // sane relative path for that, display, and the diff tooling.
    if (!isSafeArtifactPath(entry.path)) {
      return { ok: false, error: `Entry path ${JSON.stringify(entry.path)} is not a path inside the artifact store` };
    }
    let stored: Buffer;
    try {
      stored = await readFile(path.join(process.cwd(), "storage", "artifacts", entry.sha256));
    } catch (error) {
      if ((error as { code?: string }).code === "ENOENT") {
        return {
          ok: false,
          error: `Artifact ${entry.sha256} for ${entry.path} is not in the store`,
        };
      }
      throw error;
    }
    // Belt and braces: the file is looked up by its own claimed hash, so this can only
    // fail if the bytes on disk were corrupted or the upload was mislabeled — never
    // because a later release changed what lives at `entry.path` (#804).
    const actual = crypto.createHash("sha256").update(stored).digest("hex");
    if (actual !== entry.sha256) {
      return {
        ok: false,
        error:
          `The artifact stored under ${entry.sha256} (for ${entry.path}) actually hashes to ` +
          `${actual} — corrupted on disk or uploaded under the wrong name`,
      };
    }
    const iocError = iocEntryError(entry, stored);
    if (iocError !== null) return { ok: false, error: iocError };
  }
  return { ok: true, manifest };
}
