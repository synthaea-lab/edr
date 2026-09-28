import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import path from "path";
import { ContentManifest, canonicalJSON, verifySignature } from "@/lib/content-manifest";

/**
 * Parity-seam golden fixture (CLAUDE.md): the same
 * `content-manifest-golden.json` file is read by
 * `crates/updater/src/content.rs`'s `golden_fixture` test module — a real
 * manifest signed with `updater::key::test_key_pair`'s embedded Ed25519 seed.
 * If this crate's `canonicalJSON`/`verifySignature` ever drift from Rust's
 * `ContentManifest::canonical_bytes` (PR #509 review found exactly this:
 * different field handling for `signature`, and a field order that wasn't
 * really alphabetical), this test fails without needing a live agent.
 *
 * The public key below is `updater::key::UPDATER_PUBLIC_KEY` — the public
 * half of the same fixed test seed — hex-copied here rather than derived,
 * since Node's Web Crypto Ed25519 import needs raw bytes and this crate has
 * no Rust FFI to fetch them from.
 */
const GOLDEN_PUBLIC_KEY_HEX =
  "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12";

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function loadGoldenManifest(): ContentManifest {
  const raw = readFileSync(
    path.join(process.cwd(), "tests", "fixtures", "content-manifest-golden.json"),
    "utf-8"
  );
  return ContentManifest.parse(JSON.parse(raw));
}

describe("content-manifest golden fixture (Rust/TS parity)", () => {
  it("verifies against the embedded test public key", async () => {
    const manifest = loadGoldenManifest();
    await expect(
      verifySignature(manifest, hexToBytes(GOLDEN_PUBLIC_KEY_HEX))
    ).resolves.toBe(true);
  });

  it("produces the same canonical bytes this crate would sign", () => {
    const manifest = loadGoldenManifest();
    const raw = readFileSync(
      path.join(process.cwd(), "tests", "fixtures", "content-manifest-golden.json"),
      "utf-8"
    );
    // The fixture file's own bytes ARE `crates/updater`'s canonical form with
    // the real signature filled in; canonicalJSON must reproduce it exactly
    // once the signature is zeroed back out, on both sides of the seam.
    const expected = raw.trim().replace(
      /"signature": "[0-9a-f]+"/,
      '"signature": ""'
    );
    expect(canonicalJSON(manifest)).toBe(expected);
  });
});
