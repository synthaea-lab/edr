/**
 * Content Manifest Schema (extends ADR-0015 for non-binary artifacts)
 *
 * Supports canary-ring deployment of rules, models, and policy without
 * requiring binary updates. Mirrors updater manifest format for consistency.
 *
 * Related: Issue #30 (updater rings), Issue #49 (per-site model adaptation)
 */

import { readFile } from "fs/promises";
import path from "path";
import { z } from "zod";

/**
 * Content types supported by the content distribution system
 */
export const ContentType = z.enum([
  "rule",   // Sigma YAML detection rule
  "model",  // ML model (pickle + model_record.json)
  "policy", // JSON policy configuration
]);

export type ContentType = z.infer<typeof ContentType>;

/**
 * Single content artifact entry
 */
export const ContentEntry = z.object({
  path: z.string(),           // Relative path: rules/beacon.sigma, models/cmdline-iforest-linux.pkl
  type: ContentType,          // Content type for validation
  sha256: z.string(),         // SHA-256 hash (hex) for integrity verification
  size: z.number(),           // File size in bytes
  metadata: z.record(z.any()).optional(), // Optional metadata (e.g., model version, MITRE technique)
});

export type ContentEntry = z.infer<typeof ContentEntry>;

/**
 * Content manifest — signed list of artifacts for a specific ring
 *
 * Example filename: content-canary_0-v42.json
 * Schema mirrors ADR-0015 binary manifest for consistency
 */
export const ContentManifest = z.object({
  schema_version: z.literal(1),           // Schema version (strict validation, reject unknown)
  release_version: z.number().int().min(1), // Monotone counter (anti-rollback)
  ring: z.enum(["canary_0", "canary_1", "canary_2", "prod"]), // Target ring
  released_at: z.string(),                // ISO 8601 UTC timestamp
  entries: z.array(ContentEntry),         // List of content artifacts
  signature: z.string(),                  // Ed25519 signature (hex) over canonical JSON
});

export type ContentManifest = z.infer<typeof ContentManifest>;

/**
 * Recursively sorts object keys so `JSON.stringify` produces the same bytes
 * regardless of property insertion order, at every nesting level — not just
 * the top one.
 */
function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortKeysDeep);
  }
  if (value !== null && typeof value === "object") {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[key] = sortKeysDeep((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return value;
}

/**
 * Canonical JSON for signing — byte-for-byte the same scheme as
 * `crates/updater::content::ContentManifest::canonical_bytes` (the Rust agent
 * side that actually enforces the signature), not an independent TS
 * convention: a prior version of this function dropped the `signature` key
 * entirely instead of keeping it present-but-empty, so a manifest signed
 * against Rust's canonical bytes could never verify here and vice versa
 * (PR #509 review). Both sides must agree on:
 * - 2-space indent
 * - Sorted keys, at every nesting level (not just top-level manifest fields —
 *   a naive `JSON.stringify(value, Object.keys(value).sort(), 2)` replacer
 *   array applies that SAME top-level key allowlist recursively to every
 *   nested object too, so `entries[]`' own fields (path/type/sha256/...)
 *   would silently serialize as `{}` — verified and fixed; see
 *   `tests/unit/content-manifest.test.ts`)
 * - `signature` present in the signed payload, forced to `""` — not omitted
 *
 * `tests/unit/content-manifest.test.ts` and `cargo test -p updater` both
 * verify against the same checked-in golden fixture
 * (`tests/fixtures/content-manifest-golden.json`) so the two sides can't
 * silently drift apart again.
 */
export function canonicalJSON(
  manifest: ContentManifest | Omit<ContentManifest, "signature">
): string {
  const unsigned = { ...manifest, signature: "" };
  return JSON.stringify(sortKeysDeep(unsigned), null, 2);
}

/**
 * Verify manifest signature using Ed25519 public key
 * Returns true if signature is valid, false otherwise
 */
export async function verifySignature(
  manifest: ContentManifest,
  publicKey: Uint8Array
): Promise<boolean> {
  try {
    // canonicalJSON forces `signature` to "" itself — pass the full manifest.
    const canonical = canonicalJSON(manifest);

    // Convert hex signature to bytes
    const signatureBytes = hexToBytes(manifest.signature);

    // Verify using Web Crypto API (Ed25519)
    const key = await crypto.subtle.importKey(
      "raw",
      publicKey,
      { name: "Ed25519" },
      false,
      ["verify"]
    );

    const encoder = new TextEncoder();
    const data = encoder.encode(canonical);

    return await crypto.subtle.verify(
      "Ed25519",
      key,
      signatureBytes,
      data
    );
  } catch (error) {
    console.error("Signature verification error:", error);
    return false;
  }
}

/**
 * Check if release version is newer than current
 * Prevents rollback attacks per ADR-0015 Decision 5
 */
export function isNewerRelease(
  current: number,
  candidate: number
): boolean {
  return candidate > current;
}

/**
 * Convert hex string to Uint8Array
 */
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Content manifest storage path pattern
 * Example: manifests/content-canary_0-v42.json
 */
export function contentManifestPath(ring: string, version: number): string {
  return `manifests/content-${ring}-v${version}.json`;
}

/**
 * Fetches the raw manifest bytes a `ContentRelease.manifestUrl` points at.
 *
 * `storage://<path>` is the local-filesystem convention this dev deployment
 * uses (mirrors `/api/content/artifact`'s own `storage/artifacts/` — see that
 * route — rather than a real object store, which doesn't exist in this repo
 * yet). Any other scheme (`https://...`) is fetched over the network — the
 * production path once a real object store is behind `manifestUrl`, untested
 * here since nothing serves one in this environment.
 *
 * Deliberately does not validate content here — the caller (the manifest
 * route) checks the returned bytes' SHA-256 against `manifestSha256` and
 * parses/validates the shape, so a corrupt or tampered file fails there with
 * the caller's own error handling, not a thrown exception from this helper.
 */
export async function loadManifestBytes(manifestUrl: string): Promise<Buffer> {
  const STORAGE_SCHEME = "storage://";
  if (manifestUrl.startsWith(STORAGE_SCHEME)) {
    const relativePath = manifestUrl.slice(STORAGE_SCHEME.length);
    // Same path-traversal guard as /api/content/artifact.
    if (relativePath.includes("..") || relativePath.startsWith("/")) {
      throw new Error(`invalid storage:// manifest path: ${manifestUrl}`);
    }
    const storagePath = path.join(process.cwd(), "storage", relativePath);
    return readFile(storagePath);
  }

  const response = await fetch(manifestUrl);
  if (!response.ok) {
    throw new Error(`failed to fetch manifest from ${manifestUrl}: ${response.status}`);
  }
  return Buffer.from(await response.arrayBuffer());
}

/**
 * Content artifact storage path pattern
 * Example: artifacts/rules/beacon.sigma
 */
export function contentArtifactPath(entry: ContentEntry): string {
  return `artifacts/${entry.path}`;
}

/**
 * Example content manifest for canary_0 ring
 */
export const EXAMPLE_MANIFEST: ContentManifest = {
  schema_version: 1,
  release_version: 42,
  ring: "canary_0",
  released_at: "2026-09-23T16:00:00Z",
  entries: [
    {
      path: "rules/beacon.sigma",
      type: "rule",
      sha256: "a".repeat(64),
      size: 1234,
      metadata: { technique: "T1071.001", severity: "high" },
    },
    {
      path: "models/cmdline-iforest-linux/0.3.0/model.pkl",
      type: "model",
      sha256: "b".repeat(64),
      size: 10485760, // 10 MB
      metadata: { version: "0.3.0", escape_rate: 0.08 },
    },
    {
      path: "models/cmdline-iforest-linux/0.3.0/model_record.json",
      type: "model",
      sha256: "c".repeat(64),
      size: 2048,
      metadata: { version: "0.3.0" },
    },
    {
      path: "policy/site-policy-v5.json",
      type: "policy",
      sha256: "d".repeat(64),
      size: 512,
      metadata: { version: 5 },
    },
  ],
  signature: "0".repeat(128), // Ed25519 signature (64 bytes hex)
};
