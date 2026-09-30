import { describe, expect, it } from "vitest";
import { isSafeReleasePath, ReleaseManifest } from "@/lib/release-manifest";

const SHA = "a".repeat(64);

function manifest(overrides: Record<string, unknown> = {}) {
  return {
    schema_version: 1,
    release_version: 2,
    entries: { agent: SHA, watchdog: SHA },
    signature: "00",
    ...overrides,
  };
}

describe("isSafeReleasePath (same rule as the agent's validate_entry_paths)", () => {
  it.each(["agent", "watchdog", "cli", "lib/libort.so.1"])("accepts %s", (p) => {
    expect(isSafeReleasePath(p)).toBe(true);
  });

  it.each([
    "",
    "../evil",
    "a/../../evil",
    "/etc/cron.d/x",
    "a\\b",
    "C:evil",
    "agent:stream",
    "evil.",
    "evil ",
    "a//b",
    "nul",
    "rules/COM1.txt",
    "CONIN$",
    "a\0b",
  ])("rejects %j", (p) => {
    expect(isSafeReleasePath(p)).toBe(false);
  });
});

describe("ReleaseManifest schema", () => {
  it("accepts the wire shape crates/updater serializes", () => {
    expect(ReleaseManifest.safeParse(manifest()).success).toBe(true);
  });

  it("rejects an unknown schema_version", () => {
    expect(ReleaseManifest.safeParse(manifest({ schema_version: 2 })).success).toBe(false);
  });

  it("rejects fields outside the signed canonical form", () => {
    expect(ReleaseManifest.safeParse(manifest({ ring: "prod" })).success).toBe(false);
  });

  it("rejects a bad hash, an unsafe path and an empty release", () => {
    expect(ReleaseManifest.safeParse(manifest({ entries: { agent: "nothex" } })).success).toBe(false);
    expect(ReleaseManifest.safeParse(manifest({ entries: { "../evil": SHA } })).success).toBe(false);
    expect(ReleaseManifest.safeParse(manifest({ entries: {} })).success).toBe(false);
  });

  it("rejects a non-positive or fractional release_version", () => {
    expect(ReleaseManifest.safeParse(manifest({ release_version: 0 })).success).toBe(false);
    expect(ReleaseManifest.safeParse(manifest({ release_version: 1.5 })).success).toBe(false);
  });
});
