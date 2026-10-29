import { mkdtemp, readdir, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { PrismaClient } from "@prisma/client";
import { FsLakeStore, type LakeStore } from "@/lib/lake-store";
import { ageInDays, isExpired, manifestHash, pruneLake } from "@/lib/lake-retention";

const NOW = new Date(Date.UTC(2026, 9, 29, 15, 30, 0));
const file = (tenant: string, date: string, type = "exec", name = "f") => `tenant=${tenant}/date=${date}/type=${type}/${name}.parquet`;

describe("ageInDays and isExpired", () => {
  it("counts whole UTC days to today, whatever the time of day", () => {
    expect(ageInDays("2026-10-29", NOW)).toBe(0);
    expect(ageInDays("2026-10-28", new Date(Date.UTC(2026, 9, 29, 0, 0, 0)))).toBe(1);
    expect(ageInDays("2026-07-31", NOW)).toBe(90);
    expect(ageInDays("2026-10-30", NOW)).toBe(-1);
  });

  it("expires a partition once it is retentionDays old, and not a day before", () => {
    expect(isExpired("2026-08-01", 90, NOW)).toBe(false); // 89 days
    expect(isExpired("2026-07-31", 90, NOW)).toBe(true); // 90 days
  });

  it("keeps nothing at 0 retention, today included, but never a future date by mistake of age", () => {
    expect(isExpired("2026-10-29", 0, NOW)).toBe(true);
    expect(isExpired("2026-10-30", 0, NOW)).toBe(false);
  });

  it("never expires a date that does not parse", () => {
    for (const bad of ["", "not-a-date", "2026-13-45", "2026-1-1"]) expect(isExpired(bad, 0, NOW)).toBe(false);
  });
});

describe("manifestHash", () => {
  it("is the same whatever the listing order, and changes with a name or a size", () => {
    const a = { key: "k1", size: 1 };
    const b = { key: "k2", size: 2 };
    expect(manifestHash([a, b])).toBe(manifestHash([b, a]));
    expect(manifestHash([a, b])).not.toBe(manifestHash([a, { key: "k2", size: 3 }]));
    expect(manifestHash([a, b])).not.toBe(manifestHash([a, { key: "k3", size: 2 }]));
  });
});

describe("FsLakeStore list and delete", () => {
  let dir: string;
  let store: FsLakeStore;
  beforeEach(async () => {
    dir = await mkdtemp(path.join(os.tmpdir(), "lake-ret-"));
    store = new FsLakeStore(dir);
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("lists files under a prefix with their sizes, sorted, and nothing for a missing prefix", async () => {
    await store.put(file("t1", "2026-10-01", "exec", "b"), new Uint8Array(3));
    await store.put(file("t1", "2026-10-01", "connect", "a"), new Uint8Array(5));
    await store.put(file("t2", "2026-10-01"), new Uint8Array(1));
    expect(await store.list("tenant=t1/")).toEqual([
      { key: "tenant=t1/date=2026-10-01/type=connect/a.parquet", size: 5 },
      { key: "tenant=t1/date=2026-10-01/type=exec/b.parquet", size: 3 },
    ]);
    expect((await store.list("")).length).toBe(3);
    expect(await store.list("tenant=nobody/")).toEqual([]);
  });

  it("does not list a file still being written", async () => {
    await store.put(file("t1", "2026-10-01"), new Uint8Array(1));
    const { writeFile } = await import("node:fs/promises");
    await writeFile(path.join(dir, "tenant=t1/date=2026-10-01/type=exec/g.parquet.tmp-123"), "x");
    expect((await store.list("tenant=t1/")).map((f) => f.key)).toEqual([file("t1", "2026-10-01")]);
  });

  it("does not let a prefix match half a segment", async () => {
    await store.put(file("t1", "2026-10-01"), new Uint8Array(1));
    await store.put(file("t10", "2026-10-01"), new Uint8Array(1));
    expect((await store.list("tenant=t1/")).map((f) => f.key)).toEqual([file("t1", "2026-10-01")]);
  });

  it("deletes the files and the directories they leave empty, and tolerates a file already gone", async () => {
    const k = file("t1", "2026-10-01");
    await store.put(k, new Uint8Array(1));
    await store.put(file("t1", "2026-10-02"), new Uint8Array(1));
    await store.delete([k, k]);
    expect(await store.list("tenant=t1/date=2026-10-01/")).toEqual([]);
    expect(await readdir(path.join(dir, "tenant=t1"))).toEqual(["date=2026-10-02"]);
  });

  it("refuses to delete or list a key that could leave the root", async () => {
    await expect(store.delete(["../x"])).rejects.toThrow(/Unsafe lake key/);
    await expect(store.list("../")).rejects.toThrow(/Unsafe lake key/);
  });
});

/** The slice of Prisma `pruneLake` uses, backed by arrays. */
function fakeDb(tenants: { id: string; lakeRetentionDays: number }[]) {
  const deletions: Record<string, unknown>[] = [];
  const db = {
    tenant: { findMany: vi.fn(async ({ where }: { where: { id: { in: string[] } } }) => tenants.filter((t) => where.id.in.includes(t.id))) },
    lakeDeletion: { create: vi.fn(async ({ data }: { data: Record<string, unknown> }) => { deletions.push(data); return data; }) },
  } as unknown as Pick<PrismaClient, "tenant" | "lakeDeletion">;
  return { db, deletions };
}

class MemoryStore implements LakeStore {
  files = new Map<string, number>();
  stuck = new Set<string>();
  async put(key: string, body: Uint8Array) { this.files.set(key, body.length); }
  async list(prefix: string) {
    return Array.from(this.files).filter(([k]) => k.startsWith(prefix)).map(([key, size]) => ({ key, size })).sort((a, b) => (a.key < b.key ? -1 : 1));
  }
  async delete(keys: string[]) { for (const k of keys) if (!this.stuck.has(k)) this.files.delete(k); }
}

describe("pruneLake", () => {
  it("deletes the expired partitions of a tenant and records each one", async () => {
    const store = new MemoryStore();
    await store.put(file("t1", "2026-07-01", "exec", "a"), new Uint8Array(10));
    await store.put(file("t1", "2026-07-01", "connect", "b"), new Uint8Array(5));
    await store.put(file("t1", "2026-10-28"), new Uint8Array(7));
    const { db, deletions } = fakeDb([{ id: "t1", lakeRetentionDays: 90 }]);
    const result = await pruneLake(db, store, NOW);
    expect(result).toMatchObject({ partitionsDeleted: 1, filesDeleted: 2, bytesDeleted: 15, notEmpty: 0, orphanTenantPrefixes: 0 });
    expect(Array.from(store.files.keys())).toEqual([file("t1", "2026-10-28")]);
    expect(deletions).toHaveLength(1);
    expect(deletions[0]).toMatchObject({ tenantId: "t1", date: "2026-07-01", objectCount: 2, bytes: BigInt(15), verifiedEmpty: true, runId: result.runId, deletedAt: NOW });
    expect(deletions[0].manifestSha256).toBe(
      manifestHash([{ key: file("t1", "2026-07-01", "exec", "a"), size: 10 }, { key: file("t1", "2026-07-01", "connect", "b"), size: 5 }])
    );
  });

  it("applies each tenant's own retention", async () => {
    const store = new MemoryStore();
    await store.put(file("short", "2026-10-20"), new Uint8Array(1));
    await store.put(file("long", "2026-10-20"), new Uint8Array(1));
    const { db } = fakeDb([{ id: "short", lakeRetentionDays: 7 }, { id: "long", lakeRetentionDays: 365 }]);
    await pruneLake(db, store, NOW);
    expect(Array.from(store.files.keys())).toEqual([file("long", "2026-10-20")]);
  });

  it("keeps nothing for a tenant at 0, today's partition included", async () => {
    const store = new MemoryStore();
    await store.put(file("none", "2026-10-29"), new Uint8Array(1));
    const { db } = fakeDb([{ id: "none", lakeRetentionDays: 0 }]);
    expect((await pruneLake(db, store, NOW)).partitionsDeleted).toBe(1);
    expect(store.files.size).toBe(0);
  });

  it("leaves a tenant prefix whose tenant does not exist, and counts it", async () => {
    const store = new MemoryStore();
    await store.put(file("ghost", "2020-01-01"), new Uint8Array(1));
    const { db, deletions } = fakeDb([]);
    expect(await pruneLake(db, store, NOW)).toMatchObject({ orphanTenantPrefixes: 1, partitionsDeleted: 0 });
    expect(store.files.size).toBe(1);
    expect(deletions).toHaveLength(0);
  });

  it("does not touch a key that is not a lake partition", async () => {
    const store = new MemoryStore();
    await store.put("README.txt", new Uint8Array(1));
    await store.put("tenant=t1/notes.txt", new Uint8Array(1));
    await store.put("tenant=t1/date=garbage/type=exec/f.parquet", new Uint8Array(1));
    const { db } = fakeDb([{ id: "t1", lakeRetentionDays: 0 }]);
    expect((await pruneLake(db, store, NOW)).partitionsDeleted).toBe(0);
    expect(store.files.size).toBe(3);
  });

  it("records a partition that still lists files as not verified empty, and counts it", async () => {
    const store = new MemoryStore();
    const k = file("t1", "2026-07-01");
    await store.put(k, new Uint8Array(4));
    store.stuck.add(k);
    const { db, deletions } = fakeDb([{ id: "t1", lakeRetentionDays: 30 }]);
    const result = await pruneLake(db, store, NOW);
    expect(result).toMatchObject({ partitionsDeleted: 1, notEmpty: 1 });
    expect(deletions[0]).toMatchObject({ verifiedEmpty: false, objectCount: 1 });
  });

  it("does nothing on an empty lake", async () => {
    const { db } = fakeDb([]);
    expect(await pruneLake(db, new MemoryStore(), NOW)).toMatchObject({ partitionsDeleted: 0, filesDeleted: 0, bytesDeleted: 0 });
  });
});
