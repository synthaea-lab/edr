import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";
import {
  canonicalSnapshotManifest,
  loadSnapshotSigner,
  signerFromSeed,
  signSnapshotManifest,
  SnapshotManifest,
  TEST_SNAPSHOT_SEED,
  verifySnapshotManifest,
} from "@/lib/snapshot-manifest";

/**
 * Parity seam (CLAUDE.md): `tests/fixtures/snapshot-manifest-golden.json` is a manifest signed
 * by the public test `snapshot` key; `crates/updater` reads the same file and derives the same
 * public key from the same seed. If the canonical bytes drift on either side, one of the two
 * tests fails without a live agent.
 */
const golden = JSON.parse(
  readFileSync(path.join(process.cwd(), "tests", "fixtures", "snapshot-manifest-golden.json"), "utf-8")
) as { public_key: string; manifest: SnapshotManifest };
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const unsigned = (({ signature: _s, ...rest }) => rest)(golden.manifest);

describe("snapshot manifest golden fixture", () => {
  it("is signed by the public test key, derived from its seed and not copied", () => {
    expect(hex(signerFromSeed(TEST_SNAPSHOT_SEED).publicKey())).toBe(golden.public_key);
    expect(verifySnapshotManifest(SnapshotManifest.parse(golden.manifest), Buffer.from(golden.public_key, "hex"))).toBe(true);
  });

  it("signs to the golden bytes: Ed25519 is deterministic", async () => {
    const signed = await signSnapshotManifest(unsigned, signerFromSeed(TEST_SNAPSHOT_SEED));
    expect(signed).toEqual(golden.manifest);
  });

  it("has canonical bytes with sorted keys, 2-space indent and an empty signature kept in place", () => {
    const text = canonicalSnapshotManifest(golden.manifest);
    expect(text).toBe(
      [
        "{",
        '  "built_at": 1760000000,',
        '  "entry_count": 4096,',
        '  "hosts_covered": 12,',
        '  "kind": "common-set",',
        '  "min_hosts": 3,',
        '  "schema_version": 1,',
        `  "sha256": "${"ab".repeat(32)}",`,
        '  "signature": "",',
        '  "size": 5432',
        "}",
      ].join("\n")
    );
  });
});

describe("verifySnapshotManifest", () => {
  const key = Buffer.from(golden.public_key, "hex");

  it("refuses a manifest changed after signing, in any field", () => {
    const changes: Partial<SnapshotManifest>[] = [
      { built_at: golden.manifest.built_at + 1 },
      { hosts_covered: 13 },
      { entry_count: 1 },
      { min_hosts: 2 },
      { sha256: "cd".repeat(32) },
      { size: 1 },
    ];
    for (const change of changes) {
      expect(verifySnapshotManifest({ ...golden.manifest, ...change }, key), JSON.stringify(change)).toBe(false);
    }
  });

  it("refuses another key, a malformed signature and a malformed key without throwing", () => {
    expect(verifySnapshotManifest(golden.manifest, new Uint8Array(32).fill(7))).toBe(false);
    for (const signature of ["", "zz", "ab".repeat(63), golden.manifest.signature.toUpperCase()]) {
      expect(verifySnapshotManifest({ ...golden.manifest, signature }, key)).toBe(false);
    }
    expect(verifySnapshotManifest(golden.manifest, new Uint8Array(5))).toBe(false);
  });
});

describe("SnapshotManifest schema", () => {
  it("accepts the golden manifest and refuses unknown fields, another kind or version, a bad hash", () => {
    expect(SnapshotManifest.safeParse(golden.manifest).success).toBe(true);
    for (const bad of [
      { extra: 1 },
      { kind: "policy" },
      { schema_version: 2 },
      { sha256: "AB".repeat(32) },
      { size: 0 },
      { min_hosts: 0 },
      { built_at: -1 },
    ]) {
      expect(SnapshotManifest.safeParse({ ...golden.manifest, ...bad }).success, JSON.stringify(bad)).toBe(false);
    }
  });
});

describe("loadSnapshotSigner", () => {
  it("is null unless the public test key is asked for by name", () => {
    expect(loadSnapshotSigner({})).toBeNull();
    expect(loadSnapshotSigner({ SYNTHAEA_SNAPSHOT_SIGNER: "" })).toBeNull();
  });

  it("gives the test signer when asked, and says so on the log", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const signer = loadSnapshotSigner({ SYNTHAEA_SNAPSHOT_SIGNER: "test" });
    expect(hex(signer!.publicKey())).toBe(golden.public_key);
    warn.mockRestore();
  });

  it("refuses an unknown value instead of falling back to a key", () => {
    expect(() => loadSnapshotSigner({ SYNTHAEA_SNAPSHOT_SIGNER: "kms" })).toThrow(/must be "test" or unset/);
  });
});
