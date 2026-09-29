import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { generateKeyPairSync, sign as ed25519Sign } from "crypto";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import {
  ContentManifest,
  canonicalJSON,
  verifySignature,
  isNewerRelease,
  loadManifestBytes,
  EXAMPLE_MANIFEST,
} from "@/lib/content-manifest";

/** A real Ed25519 keypair, generated fresh per test file — this only needs to
 * self-consistently exercise sign/verify, not match the Rust agent's embedded
 * test key (a different keypair entirely; production signing composes a real
 * key with `crates/updater`'s canonical-bytes scheme, not this TS helper). */
const { publicKey, privateKey } = generateKeyPairSync("ed25519");

function publicKeyRawBytes(): Uint8Array {
  // Node's `crypto.subtle`-compatible raw export: SPKI DER minus its fixed
  // 12-byte prefix for an Ed25519 key, matching how the browser/Node Web
  // Crypto `importKey("raw", ...)` call in `verifySignature` expects it.
  const spki = publicKey.export({ type: "spki", format: "der" });
  return new Uint8Array(spki.subarray(spki.length - 32));
}

function signManifest(manifest: Omit<ContentManifest, "signature">): string {
  const canonical = canonicalJSON(manifest);
  const sig = ed25519Sign(null, Buffer.from(canonical), privateKey);
  return sig.toString("hex");
}

function baseManifest(): Omit<ContentManifest, "signature"> {
  return {
    schema_version: 1,
    release_version: 1,
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
    ],
  };
}

describe("canonicalJSON", () => {
  it("includes entries' own fields, not just the top-level manifest keys", () => {
    // Regression: a naive `JSON.stringify(value, Object.keys(value).sort(), 2)`
    // replacer-array approach applies that SAME top-level allowlist
    // recursively to nested objects too, so every entry silently serialized
    // as `{}` — a signature computed over that canonical form would verify
    // successfully even if `entries` were tampered with after the fact.
    const canonical = canonicalJSON(baseManifest());
    expect(canonical).toContain("rules/beacon.sigma");
    expect(canonical).toContain("a".repeat(64));
    expect(canonical).toContain("T1071.001");
  });

  it("sorts keys at every nesting level, not just the top", () => {
    const canonical = canonicalJSON(baseManifest());
    const parsed = JSON.parse(canonical);
    // entries[0]'s own keys, alphabetical: metadata, path, sha256, size, type
    expect(Object.keys(parsed.entries[0])).toEqual([
      "metadata",
      "path",
      "sha256",
      "size",
      "type",
    ]);
  });

  it("uses 2-space indent", () => {
    const canonical = canonicalJSON(baseManifest());
    expect(canonical).toContain('\n  "entries"');
  });

  it("is stable regardless of the input object's key insertion order", () => {
    const a = baseManifest();
    const b = {
      released_at: a.released_at,
      ring: a.ring,
      schema_version: a.schema_version,
      entries: a.entries,
      release_version: a.release_version,
    };
    expect(canonicalJSON(a)).toBe(canonicalJSON(b));
  });
});

describe("verifySignature", () => {
  it("verifies a freshly signed manifest", async () => {
    const unsigned = baseManifest();
    const manifest: ContentManifest = { ...unsigned, signature: signManifest(unsigned) };
    await expect(verifySignature(manifest, publicKeyRawBytes())).resolves.toBe(true);
  });

  it("rejects a manifest whose entries were tampered with after signing", async () => {
    const unsigned = baseManifest();
    const manifest: ContentManifest = { ...unsigned, signature: signManifest(unsigned) };
    manifest.entries.push({
      path: "rules/injected.sigma",
      type: "rule",
      sha256: "b".repeat(64),
      size: 1,
    });
    await expect(verifySignature(manifest, publicKeyRawBytes())).resolves.toBe(false);
  });

  it("rejects a manifest signed with a different key", async () => {
    const unsigned = baseManifest();
    const manifest: ContentManifest = { ...unsigned, signature: signManifest(unsigned) };
    const other = generateKeyPairSync("ed25519");
    const spki = other.publicKey.export({ type: "spki", format: "der" });
    const otherRaw = new Uint8Array(spki.subarray(spki.length - 32));
    await expect(verifySignature(manifest, otherRaw)).resolves.toBe(false);
  });

  it("rejects a malformed signature instead of throwing", async () => {
    const unsigned = baseManifest();
    const manifest: ContentManifest = { ...unsigned, signature: "not-hex-zz" };
    await expect(verifySignature(manifest, publicKeyRawBytes())).resolves.toBe(false);
  });
});

describe("isNewerRelease", () => {
  it("accepts strictly greater, rejects equal or lower", () => {
    expect(isNewerRelease(5, 6)).toBe(true);
    expect(isNewerRelease(5, 5)).toBe(false);
    expect(isNewerRelease(5, 4)).toBe(false);
  });
});

describe("loadManifestBytes", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "content-manifest-test-"));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("reads a storage:// URL from the local storage/ directory under cwd", async () => {
    // loadManifestBytes resolves storage:// against process.cwd()/storage —
    // spoof cwd for the duration of this test rather than writing into the
    // real repo's storage/ directory.
    const originalCwd = process.cwd();
    process.chdir(dir);
    try {
      const storageDir = join(dir, "storage", "manifests");
      mkdirSync(storageDir, { recursive: true });
      writeFileSync(join(storageDir, "content-canary_0-v1.json"), '{"hello":"world"}');

      const bytes = await loadManifestBytes("storage://manifests/content-canary_0-v1.json");
      expect(bytes.toString("utf-8")).toBe('{"hello":"world"}');
    } finally {
      process.chdir(originalCwd);
    }
  });

  it("rejects a storage:// path attempting traversal", async () => {
    await expect(
      loadManifestBytes("storage://../../etc/passwd")
    ).rejects.toThrow(/invalid storage/);
  });

  it("rejects a storage:// path with a leading slash", async () => {
    await expect(loadManifestBytes("storage:///etc/passwd")).rejects.toThrow(/invalid storage/);
  });
});

describe("EXAMPLE_MANIFEST", () => {
  it("matches the ContentManifest schema", () => {
    expect(() => ContentManifest.parse(EXAMPLE_MANIFEST)).not.toThrow();
  });
});
