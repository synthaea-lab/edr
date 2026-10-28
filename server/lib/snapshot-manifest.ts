import { createPrivateKey, createPublicKey, sign as edSign, verify as edVerify } from "node:crypto";
import { z } from "zod";
import { sortKeysDeep } from "@/lib/content-manifest";

/**
 * The signed manifest of a common-set snapshot (ADR-0033, issue #76 box 2). Its own document,
 * outside the content manifest and the rings: one tenant's snapshot, rebuilt on a cadence and
 * signed by the `snapshot` key, the only key that may sign this kind.
 *
 * Canonical bytes are the content manifest's scheme (2-space JSON, keys sorted at every level,
 * `signature` present and forced to `""`), which `crates/updater` mirrors field for field;
 * `tests/fixtures/snapshot-manifest-golden.json` is the seam both sides test against.
 */
export const SNAPSHOT_MANIFEST_SCHEMA_VERSION = 1;

export const SnapshotManifest = z
  .object({
    schema_version: z.literal(SNAPSHOT_MANIFEST_SCHEMA_VERSION),
    kind: z.literal("common-set"),
    /** Unix seconds when the snapshot was built; equals the artifact header's `built_at`. */
    built_at: z.number().int().min(0),
    hosts_covered: z.number().int().min(0),
    min_hosts: z.number().int().min(1),
    entry_count: z.number().int().min(0),
    /** The artifact's SHA-256 (lowercase hex) and size in bytes. */
    sha256: z.string().regex(/^[0-9a-f]{64}$/),
    size: z.number().int().min(1),
    signature: z.string(),
  })
  .strict();
export type SnapshotManifest = z.infer<typeof SnapshotManifest>;

export function canonicalSnapshotManifest(manifest: SnapshotManifest | Omit<SnapshotManifest, "signature">): string {
  return JSON.stringify(sortKeysDeep({ ...manifest, signature: "" }), null, 2);
}

/**
 * Whatever holds the `snapshot` key. The control plane may *request* a signature and never
 * reads the key (ADR-0033 decision 2); the real implementation is a signing-only key service
 * and waits on the custody decision (#753). Until then only the public test key below exists.
 */
export interface SnapshotSigner {
  /** The raw 32-byte Ed25519 public key a verifier needs. */
  publicKey(): Uint8Array;
  sign(bytes: Uint8Array): Promise<Uint8Array>;
}

/** PKCS#8 prefix of an Ed25519 private key; the 32-byte seed follows. */
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

/**
 * Seed of the public test `snapshot` key: the same constant `crates/updater` derives its test
 * `snapshot` public key from (`key.rs`, `TEST_SNAPSHOT_SEED`). Public, checked in, and good for
 * nothing but a lab: a build that trusts it trusts anyone who reads this file.
 */
export const TEST_SNAPSHOT_SEED = Buffer.alloc(32, 0x44);

export function signerFromSeed(seed: Uint8Array): SnapshotSigner {
  const privateKey = createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(seed)]),
    format: "der",
    type: "pkcs8",
  });
  const publicKey = new Uint8Array(
    createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(-32)
  );
  return {
    publicKey: () => publicKey,
    sign: async (bytes) => new Uint8Array(edSign(null, Buffer.from(bytes), privateKey)),
  };
}

let warned = false;

/**
 * The signer this server instance may use, or `null` when snapshot signing is not configured
 * (then nothing is built or published, and the endpoints have nothing to serve). The only signer
 * today is the public test key, and only when asked for by name: `SYNTHAEA_SNAPSHOT_SIGNER=test`.
 * A production deployment sets nothing. Any other value is an error, not a fallback.
 */
export function loadSnapshotSigner(env: Record<string, string | undefined> = process.env): SnapshotSigner | null {
  const wanted = env.SYNTHAEA_SNAPSHOT_SIGNER;
  if (wanted === undefined || wanted === "") return null;
  if (wanted !== "test") {
    throw new Error(`SYNTHAEA_SNAPSHOT_SIGNER must be "test" or unset, got "${wanted}"`);
  }
  if (!warned) {
    warned = true;
    console.warn("Snapshot signing uses the PUBLIC TEST key (SYNTHAEA_SNAPSHOT_SIGNER=test): lab use only.");
  }
  return signerFromSeed(TEST_SNAPSHOT_SEED);
}

/** Signs `manifest` (its `signature` is replaced) over the canonical bytes. */
export async function signSnapshotManifest(
  manifest: Omit<SnapshotManifest, "signature">,
  signer: SnapshotSigner
): Promise<SnapshotManifest> {
  const unsigned = { ...manifest, signature: "" };
  const signature = await signer.sign(Buffer.from(canonicalSnapshotManifest(unsigned)));
  return { ...unsigned, signature: Buffer.from(signature).toString("hex") };
}

/** Verifies a manifest's signature against a raw 32-byte public key. False on any malformation. */
export function verifySnapshotManifest(manifest: SnapshotManifest, publicKey: Uint8Array): boolean {
  try {
    const key = createPublicKey({
      key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(publicKey)]),
      format: "der",
      type: "spki",
    });
    if (!/^[0-9a-f]{128}$/.test(manifest.signature)) return false;
    return edVerify(
      null,
      Buffer.from(canonicalSnapshotManifest(manifest)),
      key,
      Buffer.from(manifest.signature, "hex")
    );
  } catch {
    return false;
  }
}
