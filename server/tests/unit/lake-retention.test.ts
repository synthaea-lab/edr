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
    expect(await store.delete([k, k])).toEqual({ deleted: [k, k], failed: [] });
    expect(await store.list("tenant=t1/date=2026-10-01/")).toEqual([]);
    expect(await readdir(path.join(dir, "tenant=t1"))).toEqual(["date=2026-10-02"]);
  });

  it("reports a file it cannot remove instead of throwing, and goes on to the others", async () => {
    const { mkdir } = await import("node:fs/promises");
    const good = file("t1", "2026-10-01", "exec", "good");
    await store.put(good, new Uint8Array(1));
    // A directory where a file is expected: unlink refuses it, which stands in for any removal error.
    const bad = file("t1", "2026-10-01", "exec", "bad");
    await mkdir(path.join(dir, bad), { recursive: true });
    const result = await store.delete([bad, good]);
    expect(result.deleted).toEqual([good]);
    expect(result.failed).toHaveLength(1);
    expect(result.failed[0].key).toBe(bad);
  });

  it("refuses to delete or list a key that could leave the root", async () => {
    await expect(store.delete(["../x"])).rejects.toThrow(/Unsafe lake key/);
    await expect(store.list("../")).rejects.toThrow(/Unsafe lake key/);
  });
});

/** The slice of Prisma `pruneLake` uses, backed by arrays; each write can be made to fail. */
function fakeDb(
  tenants: { id: string; lakeRetentionDays: number }[],
  failures: { create?: (n: number) => boolean; update?: boolean } = {}
) {
  const rows: Record<string, any>[] = [];
  let creates = 0;
  const db = {
    tenant: { findMany: vi.fn(async ({ where }: { where: { id: { in: string[] } } }) => tenants.filter((t) => where.id.in.includes(t.id))) },
    lakeDeletion: {
      create: vi.fn(async ({ data }: { data: Record<string, unknown> }) => {
        creates += 1;
        if (failures.create?.(creates)) throw new Error("db down (create)");
        const row = { id: `row-${rows.length}`, completedAt: null, deletedCount: null, failedCount: null, error: null, verifiedEmpty: false, ...data };
        rows.push(row);
        return row;
      }),
      update: vi.fn(async ({ where, data }: { where: { id: string }; data: Record<string, unknown> }) => {
        if (failures.update) throw new Error("db down (update)");
        Object.assign(rows.find((r) => r.id === where.id)!, data);
        return {};
      }),
    },
  } as unknown as Pick<PrismaClient, "tenant" | "lakeDeletion">;
  return { db, deletions: rows };
}

/** A store in memory. `stuck` keys cannot be removed (reported), `throwAfter` makes `delete` throw once that many keys have gone. */
class MemoryStore implements LakeStore {
  files = new Map<string, number>();
  stuck = new Set<string>();
  throwAfter: number | null = null;
  listThrowsAfterDelete = false;
  deleted = false;
  async put(key: string, body: Uint8Array) { this.files.set(key, body.length); }
  async list(prefix: string) {
    if (this.deleted && this.listThrowsAfterDelete && prefix !== "") throw new Error("list failed");
    return Array.from(this.files).filter(([k]) => k.startsWith(prefix)).map(([key, size]) => ({ key, size })).sort((a, b) => (a.key < b.key ? -1 : 1));
  }
  async delete(keys: string[]) {
    this.deleted = true;
    const result = { deleted: [] as string[], failed: [] as { key: string; error: string }[] };
    for (const k of keys) {
      if (this.throwAfter !== null && result.deleted.length >= this.throwAfter) throw new Error("connection reset");
      if (this.stuck.has(k)) { result.failed.push({ key: k, error: "AccessDenied" }); continue; }
      this.files.delete(k);
      result.deleted.push(k);
    }
    return result;
  }
}

describe("pruneLake", () => {
  it("deletes the expired partitions of a tenant and records each one", async () => {
    const store = new MemoryStore();
    await store.put(file("t1", "2026-07-01", "exec", "a"), new Uint8Array(10));
    await store.put(file("t1", "2026-07-01", "connect", "b"), new Uint8Array(5));
    await store.put(file("t1", "2026-10-28"), new Uint8Array(7));
    const { db, deletions } = fakeDb([{ id: "t1", lakeRetentionDays: 90 }]);
    const result = await pruneLake(db, store, NOW);
    expect(result).toMatchObject({ partitionsDeleted: 1, filesDeleted: 2, bytesDeleted: 15, notEmpty: 0, failedPartitions: 0, errors: [], orphanTenantPrefixes: 0 });
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

  it("records what a partial delete really removed, and says the rest is still there", async () => {
    const store = new MemoryStore();
    const [a, b, c] = ["a", "b", "c"].map((n) => file("t1", "2026-07-01", "exec", n));
    for (const k of [a, b, c]) await store.put(k, new Uint8Array(4));
    store.stuck.add(b);
    const { db, deletions } = fakeDb([{ id: "t1", lakeRetentionDays: 30 }]);
    const result = await pruneLake(db, store, NOW);
    expect(result).toMatchObject({ partitionsDeleted: 1, filesDeleted: 2, notEmpty: 1, failedPartitions: 1 });
    expect(result.errors[0]).toMatch(/AccessDenied/);
    expect(Array.from(store.files.keys())).toEqual([b]);
    expect(deletions[0]).toMatchObject({ objectCount: 3, deletedCount: 2, failedCount: 1, verifiedEmpty: false });
    expect(deletions[0].error).toMatch(/AccessDenied/);
  });

  it("counts only the sizes of the files that went, not the planned total, when the delete was partial", async () => {
    const store = new MemoryStore();
    const [a, b] = ["a", "b"].map((n) => file("t1", "2026-07-01", "exec", n));
    await store.put(a, new Uint8Array(10));
    await store.put(b, new Uint8Array(3));
    store.stuck.add(a);
    const { db, deletions } = fakeDb([{ id: "t1", lakeRetentionDays: 30 }]);
    const result = await pruneLake(db, store, NOW);
    expect(result).toMatchObject({ filesDeleted: 1, bytesDeleted: 3 });
    expect(deletions[0]).toMatchObject({ bytes: BigInt(13), deletedCount: 1 });
  });

  it("does not call a file the writer added meanwhile a failed deletion, and leaves it to the next run", async () => {
    const store = new MemoryStore();
    const [a, b] = ["a", "b"].map((n) => file("t1", "2026-07-01", "exec", n));
    await store.put(a, new Uint8Array(4));
    await store.put(b, new Uint8Array(6));
    const late = file("t1", "2026-07-01", "exec", "late");
    const del = store.delete.bind(store);
    store.delete = async (keys: string[]) => {
      const r = await del(keys);
      await store.put(late, new Uint8Array(9)); // a flush lands after the listing, before the check
      return r;
    };
    const { db, deletions } = fakeDb([{ id: "t1", lakeRetentionDays: 30 }]);
    const result = await pruneLake(db, store, NOW);
    expect(result).toMatchObject({ partitionsDeleted: 1, filesDeleted: 2, bytesDeleted: 10, notEmpty: 0, failedPartitions: 0, errors: [] });
    expect(deletions[0]).toMatchObject({ objectCount: 2, deletedCount: 2, failedCount: 0, arrivedDuringDeletion: 1, verifiedEmpty: true, error: null });
    expect(Array.from(store.files.keys())).toEqual([late]);
    // The next run finds the newcomer as its own listing and deletes it.
    store.delete = del;
    const again = await pruneLake(db, store, NOW);
    expect(again).toMatchObject({ partitionsDeleted: 1, filesDeleted: 1, bytesDeleted: 9 });
    expect(store.files.size).toBe(0);
  });

  it("still records the deletion when the store throws partway, from what is really left", async () => {
    const store = new MemoryStore();
    for (const n of ["a", "b", "c", "d"]) await store.put(file("t1", "2026-07-01", "exec", n), new Uint8Array(1));
    store.throwAfter = 2;
    const { db, deletions } = fakeDb([{ id: "t1", lakeRetentionDays: 30 }]);
    const result = await pruneLake(db, store, NOW);
    expect(result).toMatchObject({ filesDeleted: 2, notEmpty: 1, failedPartitions: 1 });
    expect(deletions).toHaveLength(1);
    expect(deletions[0]).toMatchObject({ objectCount: 4, deletedCount: 2, failedCount: 2, verifiedEmpty: false, error: "connection reset" });
    expect(deletions[0].completedAt).toBeInstanceOf(Date);
  });

  it("goes on to the next partition and tenant when one fails", async () => {
    const store = new MemoryStore();
    const stuck = file("t1", "2026-07-01", "exec", "stuck");
    await store.put(stuck, new Uint8Array(1));
    await store.put(file("t1", "2026-07-02"), new Uint8Array(1));
    await store.put(file("t2", "2026-07-01"), new Uint8Array(1));
    store.stuck.add(stuck);
    const { db, deletions } = fakeDb([{ id: "t1", lakeRetentionDays: 30 }, { id: "t2", lakeRetentionDays: 30 }]);
    const result = await pruneLake(db, store, NOW);
    expect(result).toMatchObject({ partitionsDeleted: 2, notEmpty: 1, failedPartitions: 1 });
    expect(Array.from(store.files.keys())).toEqual([stuck]);
    expect(deletions).toHaveLength(3);
  });

  it("writes the intent before it deletes anything", async () => {
    const store = new MemoryStore();
    await store.put(file("t1", "2026-07-01"), new Uint8Array(3));
    const order: string[] = [];
    const realDelete = store.delete.bind(store);
    store.delete = async (keys) => { order.push("delete"); return realDelete(keys); };
    const { db } = fakeDb([{ id: "t1", lakeRetentionDays: 30 }]);
    (db.lakeDeletion.create as any).mockImplementationOnce(async ({ data }: any) => { order.push("create"); return { id: "r0", ...data }; });
    (db.lakeDeletion.update as any).mockImplementationOnce(async () => { order.push("update"); return {}; });
    await pruneLake(db, store, NOW);
    expect(order).toEqual(["create", "delete", "update"]);
  });

  it("deletes nothing for a partition whose intent could not be recorded, and carries on", async () => {
    const store = new MemoryStore();
    await store.put(file("t1", "2026-07-01"), new Uint8Array(1));
    await store.put(file("t1", "2026-07-02"), new Uint8Array(1));
    const { db, deletions } = fakeDb([{ id: "t1", lakeRetentionDays: 30 }], { create: (n) => n === 1 });
    const result = await pruneLake(db, store, NOW);
    expect(result).toMatchObject({ partitionsDeleted: 1, failedPartitions: 1 });
    expect(result.errors[0]).toMatch(/not deleted, the audit row could not be written/);
    expect(Array.from(store.files.keys())).toEqual([file("t1", "2026-07-01")]);
    expect(deletions).toHaveLength(1);
  });

  it("leaves the intent row open (no completedAt) when completing it fails, and says so", async () => {
    const store = new MemoryStore();
    await store.put(file("t1", "2026-07-01"), new Uint8Array(1));
    const { db, deletions } = fakeDb([{ id: "t1", lakeRetentionDays: 30 }], { update: true });
    const result = await pruneLake(db, store, NOW);
    expect(result).toMatchObject({ failedPartitions: 1 });
    expect(result.errors[0]).toMatch(/could not be completed/);
    expect(deletions[0]).toMatchObject({ completedAt: null, objectCount: 1 });
    expect(store.files.size).toBe(0);
  });

  it("does not claim the prefix is empty when it cannot be listed afterwards", async () => {
    const store = new MemoryStore();
    await store.put(file("t1", "2026-07-01"), new Uint8Array(1));
    store.listThrowsAfterDelete = true;
    const { db, deletions } = fakeDb([{ id: "t1", lakeRetentionDays: 30 }]);
    const result = await pruneLake(db, store, NOW);
    expect(result).toMatchObject({ notEmpty: 1, failedPartitions: 1 });
    expect(deletions[0]).toMatchObject({ verifiedEmpty: false, deletedCount: 1, failedCount: null });
    expect(deletions[0].error).toMatch(/could not list/);
  });

  it("does nothing on an empty lake", async () => {
    const { db } = fakeDb([]);
    expect(await pruneLake(db, new MemoryStore(), NOW)).toMatchObject({ partitionsDeleted: 0, filesDeleted: 0, bytesDeleted: 0 });
  });
});
