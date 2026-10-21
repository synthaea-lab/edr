import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createHash } from "crypto";
import { existsSync, mkdirSync, mkdtempSync, rmSync, utimesSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { DEFAULT_MIN_AGE_MS, pruneUnreferencedArtifacts } from "@/lib/content-retention";

const sha = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");

const RULE_V2 = Buffer.from("title: rule as of release 2\n");
const RULE_V4 = Buffer.from("title: rule as modified by release 4\n");
const ORPHAN = Buffer.from("title: no release lists this\n");

const NOW = new Date("2026-10-20T12:00:00Z");
const OLD = new Date(NOW.getTime() - 3 * DEFAULT_MIN_AGE_MS);
const FRESH = new Date(NOW.getTime() - 60_000);

let dir: string;

function put(bytes: Buffer, mtime: Date) {
  const file = join(dir, sha(bytes));
  writeFileSync(file, bytes);
  utimesSync(file, mtime, mtime);
  return file;
}

function manifest(version: number, ...artifacts: Buffer[]) {
  return Buffer.from(
    JSON.stringify({
      schema_version: 1,
      release_version: version,
      ring: "canary_0",
      released_at: "2026-10-12T09:30:00Z",
      entries: artifacts.map((a, i) => ({ path: `rules/${i}.sigma`, type: "rule", sha256: sha(a), size: a.length })),
      signature: "00",
    })
  );
}

/** A Prisma stand-in with the releases given as [id, manifest bytes]; the manifest URL is the id. */
function world(releases: Array<[string, Buffer | Error]>) {
  const bytes = new Map(releases);
  return {
    prisma: { contentRelease: { findMany: async () => releases.map(([id]) => ({ id, manifestUrl: id })) } } as never,
    loadBytes: async (url: string) => {
      const b = bytes.get(url);
      if (b instanceof Error) throw b;
      if (!b) throw new Error("no such manifest");
      return b;
    },
  };
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "artifacts-"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("pruneUnreferencedArtifacts (#834)", () => {
  it("deletes an old artifact no release lists, and keeps one a release lists", async () => {
    const kept = put(RULE_V2, OLD);
    const gone = put(ORPHAN, OLD);
    const { prisma, loadBytes } = world([["r1", manifest(1, RULE_V2)]]);

    const result = await pruneUnreferencedArtifacts(prisma, { now: NOW, artifactsDir: dir, loadBytes });

    expect(existsSync(kept)).toBe(true);
    expect(existsSync(gone)).toBe(false);
    expect(result).toMatchObject({ releases: 1, referenced: 1, deleted: 1, keptReferenced: 1, keptRecent: 0 });
  });

  it("keeps a hash that only an older, not-active release still lists", async () => {
    // Release 2 lists the modified rule; release 1 (rolled back, or just superseded) lists the
    // original. The release rows carry no status here: the job reads every row, not the active one.
    const original = put(RULE_V2, OLD);
    const modified = put(RULE_V4, OLD);
    const { prisma, loadBytes } = world([
      ["r1", manifest(1, RULE_V2)],
      ["r2", manifest(2, RULE_V4)],
    ]);

    const result = await pruneUnreferencedArtifacts(prisma, { now: NOW, artifactsDir: dir, loadBytes });

    expect(existsSync(original)).toBe(true);
    expect(existsSync(modified)).toBe(true);
    expect(result.deleted).toBe(0);
  });

  it("keeps an unreferenced artifact younger than the grace period (a publish in flight)", async () => {
    const fresh = put(ORPHAN, FRESH);
    const { prisma, loadBytes } = world([["r1", manifest(1, RULE_V2)]]);

    const result = await pruneUnreferencedArtifacts(prisma, { now: NOW, artifactsDir: dir, loadBytes });

    expect(existsSync(fresh)).toBe(true);
    expect(result).toMatchObject({ deleted: 0, keptRecent: 1 });
  });

  it("deletes nothing when a release's manifest cannot be read", async () => {
    const orphan = put(ORPHAN, OLD);
    const listed = put(RULE_V2, OLD);
    const { prisma, loadBytes } = world([
      ["r1", manifest(1, RULE_V2)],
      ["r2", new Error("ENOENT")],
    ]);

    await expect(pruneUnreferencedArtifacts(prisma, { now: NOW, artifactsDir: dir, loadBytes })).rejects.toThrow(/release r2/);

    expect(existsSync(orphan)).toBe(true);
    expect(existsSync(listed)).toBe(true);
  });

  it("deletes nothing when a manifest is not a content manifest", async () => {
    const orphan = put(ORPHAN, OLD);
    const { prisma, loadBytes } = world([["r1", Buffer.from(JSON.stringify({ entries: [] }))]]);

    await expect(pruneUnreferencedArtifacts(prisma, { now: NOW, artifactsDir: dir, loadBytes })).rejects.toThrow(/nothing was deleted/);

    expect(existsSync(orphan)).toBe(true);
  });

  it("leaves files that are not named by a hash, and directories, alone", async () => {
    const stray = join(dir, "README.txt");
    writeFileSync(stray, "not ours");
    utimesSync(stray, OLD, OLD);
    mkdirSync(join(dir, sha("a-directory")));
    const { prisma, loadBytes } = world([["r1", manifest(1, RULE_V2)]]);

    const result = await pruneUnreferencedArtifacts(prisma, { now: NOW, artifactsDir: dir, loadBytes });

    expect(existsSync(stray)).toBe(true);
    expect(existsSync(join(dir, sha("a-directory")))).toBe(true);
    expect(result.deleted).toBe(0);
  });

  it("a second run changes nothing", async () => {
    put(ORPHAN, OLD);
    put(RULE_V2, OLD);
    const { prisma, loadBytes } = world([["r1", manifest(1, RULE_V2)]]);
    await pruneUnreferencedArtifacts(prisma, { now: NOW, artifactsDir: dir, loadBytes });

    const again = await pruneUnreferencedArtifacts(prisma, { now: NOW, artifactsDir: dir, loadBytes });

    expect(again).toMatchObject({ deleted: 0, keptReferenced: 1 });
  });

  it("answers an empty result when the store does not exist yet", async () => {
    const { prisma, loadBytes } = world([]);

    const result = await pruneUnreferencedArtifacts(prisma, { now: NOW, artifactsDir: join(dir, "missing"), loadBytes });

    expect(result).toEqual({ releases: 0, referenced: 0, deleted: 0, keptReferenced: 0, keptRecent: 0 });
  });
});
