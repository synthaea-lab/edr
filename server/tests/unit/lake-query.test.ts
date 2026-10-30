import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { FsLakeStore, type LakeReader } from "@/lib/lake-store";
import { encodeParquet, lakeKey, lakeRow, type LakeRow as WriterRow } from "@/lib/lake-writer";
import { MAX_FILES, MAX_ROWS, MAX_TYPES, queryLake } from "@/lib/lake-query";

const T1 = "tenant-one";
const T2 = "tenant-two";
const HASH = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

let dir: string;
let store: FsLakeStore;
beforeEach(async () => {
  dir = await mkdtemp(path.join(os.tmpdir(), "lake-query-"));
  store = new FsLakeStore(dir);
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

const at = (day: string, hhmmss: string) => new Date(`${day}T${hhmmss}Z`);
function row(agent: string, when: Date, type: string, over: Record<string, unknown> = {}): WriterRow {
  const event = { type, meta: { comm: "bash" }, ...over };
  // The source text carries an integer a JS number cannot hold, as an agent's `timestamp_ns` is.
  const source = JSON.stringify(event).replace('"meta":{', '"meta":{"timestamp_ns":1800000000123456789,');
  return lakeRow(agent, event, when, source);
}
async function put(tenant: string, day: string, type: string, flush: string, rows: WriterRow[]) {
  await store.put(lakeKey(tenant, day, type, flush), encodeParquet(rows));
}

describe("queryLake", () => {
  it("returns the events of a range, oldest first across days and files, with the source text", async () => {
    await put(T1, "2026-10-28", "exec", "b", [row("a1", at("2026-10-28", "12:00:00"), "exec")]);
    await put(T1, "2026-10-28", "exec", "a", [row("a1", at("2026-10-28", "08:00:00"), "exec")]);
    await put(T1, "2026-10-29", "exec", "a", [row("a1", at("2026-10-29", "01:00:00"), "exec")]);
    await put(T1, "2026-10-27", "exec", "a", [row("a1", at("2026-10-27", "23:00:00"), "exec")]);

    const r = await queryLake(store, { tenantId: T1, from: "2026-10-28", to: "2026-10-29" });
    expect(r.rows.map((x) => x.ts.toISOString())).toEqual(["2026-10-28T08:00:00.000Z", "2026-10-28T12:00:00.000Z", "2026-10-29T01:00:00.000Z"]);
    expect(r.rows.map((x) => x.date)).toEqual(["2026-10-28", "2026-10-28", "2026-10-29"]);
    // The integer above 2^53 survives: the column holds the text ingest received.
    expect(r.rows[0].event).toContain("1800000000123456789");
    expect(r).toMatchObject({ truncated: false, filesMatched: 3, filesRead: 3, filesSkipped: 0 });
  });

  it("prunes by event type from the path and filters on typed columns", async () => {
    await put(T1, "2026-10-29", "exec", "a", [
      row("a1", at("2026-10-29", "01:00:00"), "exec", { image_path: "/usr/bin/curl", sha256: HASH.toUpperCase() }),
      row("a2", at("2026-10-29", "02:00:00"), "exec", { image_path: "/usr/bin/ls" }),
    ]);
    await put(T1, "2026-10-29", "connect", "a", [row("a1", at("2026-10-29", "03:00:00"), "connect", { daddr: "203.0.113.9" })]);

    const q = { tenantId: T1, from: "2026-10-29", to: "2026-10-29" };
    expect((await queryLake(store, { ...q, types: ["connect"] })).filesMatched).toBe(1);
    expect((await queryLake(store, { ...q, where: { imagePath: "/usr/bin/curl" } })).rows).toHaveLength(1);
    expect((await queryLake(store, { ...q, where: { agentId: "a2" } })).rows.map((x) => x.imagePath)).toEqual(["/usr/bin/ls"]);
    expect((await queryLake(store, { ...q, where: { daddr: "203.0.113.9" } })).rows[0].type).toBe("connect");
    // sha256 is stored lowercase and compared lowercase, so a query in either case finds it.
    expect((await queryLake(store, { ...q, where: { sha256: HASH.toUpperCase() } })).rows).toHaveLength(1);
    expect((await queryLake(store, { ...q, where: { imagePath: "/usr/bin/curl", agentId: "a2" } })).rows).toEqual([]);
  });

  it("keeps the oldest rows of the range under the limit and says it cut", async () => {
    await put(T1, "2026-10-28", "exec", "a", [row("a", at("2026-10-28", "05:00:00"), "exec"), row("a", at("2026-10-28", "01:00:00"), "exec")]);
    await put(T1, "2026-10-29", "exec", "a", [row("a", at("2026-10-29", "00:30:00"), "exec")]);
    const r = await queryLake(store, { tenantId: T1, from: "2026-10-28", to: "2026-10-29", limit: 2 });
    expect(r.rows.map((x) => x.ts.toISOString())).toEqual(["2026-10-28T01:00:00.000Z", "2026-10-28T05:00:00.000Z"]);
    expect(r.truncated).toBe(true);
    const exact = await queryLake(store, { tenantId: T1, from: "2026-10-28", to: "2026-10-29", limit: 3 });
    expect(exact).toMatchObject({ truncated: false });
    expect(exact.rows).toHaveLength(3);
  });

  it("never reads another tenant, including one whose id starts with this one's", async () => {
    await put(T1, "2026-10-29", "exec", "a", [row("mine", at("2026-10-29", "01:00:00"), "exec")]);
    await put(T2, "2026-10-29", "exec", "a", [row("theirs", at("2026-10-29", "01:00:00"), "exec")]);
    await put(`${T1}x`, "2026-10-29", "exec", "a", [row("prefixed", at("2026-10-29", "01:00:00"), "exec")]);
    const r = await queryLake(store, { tenantId: T1, from: "2026-10-29", to: "2026-10-29" });
    expect(r.rows.map((x) => x.agentId)).toEqual(["mine"]);
  });

  it("refuses a key the store lists that is not this tenant's, even if the store answers a wider prefix", async () => {
    await put(T1, "2026-10-29", "exec", "a", [row("mine", at("2026-10-29", "01:00:00"), "exec")]);
    await put(T2, "2026-10-29", "exec", "a", [row("theirs", at("2026-10-29", "01:00:00"), "exec")]);
    const wide: LakeReader = {
      list: async () => store.list(""), // ignores the prefix it was given
      get: (key) => store.get(key),
    };
    const r = await queryLake(wide, { tenantId: T1, from: "2026-10-29", to: "2026-10-29" });
    expect(r.rows.map((x) => x.agentId)).toEqual(["mine"]);
    expect(r.filesMatched).toBe(1);
  });

  it("lists only the days in range, under the tenant's own prefix, and nothing wider", async () => {
    const asked: string[] = [];
    const spy: LakeReader = { list: async (p) => (asked.push(p), []), get: (key) => store.get(key) };
    await queryLake(spy, { tenantId: T1, from: "2026-10-28", to: "2026-10-30" });
    expect(asked).toEqual([`tenant=${T1}/date=2026-10-28/`, `tenant=${T1}/date=2026-10-29/`, `tenant=${T1}/date=2026-10-30/`]);
    asked.length = 0;
    await queryLake(spy, { tenantId: T1, from: "2026-10-29", to: "2026-10-29", types: ["exec", "connect", "exec"] });
    expect(asked).toEqual([`tenant=${T1}/date=2026-10-29/type=exec/`, `tenant=${T1}/date=2026-10-29/type=connect/`]);
  });

  it("ignores a key of another day returned for a day's prefix", async () => {
    await put(T1, "2026-10-29", "exec", "a", [row("a", at("2026-10-29", "01:00:00"), "exec")]);
    await put(T1, "2026-10-27", "exec", "a", [row("old", at("2026-10-27", "01:00:00"), "exec")]);
    const loose: LakeReader = { list: async () => store.list(""), get: (key) => store.get(key) };
    const r = await queryLake(loose, { tenantId: T1, from: "2026-10-29", to: "2026-10-29" });
    expect(r.rows.map((x) => x.agentId)).toEqual(["a"]);
  });

  it("ignores a key of another type returned for a type's prefix", async () => {
    await put(T1, "2026-10-29", "exec", "a", [row("e", at("2026-10-29", "01:00:00"), "exec")]);
    await put(T1, "2026-10-29", "connect", "a", [row("c", at("2026-10-29", "02:00:00"), "connect")]);
    const loose: LakeReader = { list: async () => store.list(""), get: (key) => store.get(key) };
    const r = await queryLake(loose, { tenantId: T1, from: "2026-10-29", to: "2026-10-29", types: ["connect"] });
    expect(r.rows.map((x) => x.agentId)).toEqual(["c"]);
  });

  it("ignores keys that do not fit the layout", async () => {
    await put(T1, "2026-10-29", "exec", "a", [row("a", at("2026-10-29", "01:00:00"), "exec")]);
    const odd: LakeReader = {
      list: async (p) => [
        ...(await store.list(p)),
        { key: `tenant=${T1}/date=2026-10-29/type=Exec/x.parquet`, size: 1 },
        { key: `tenant=${T1}/date=2026-10-29/type=exec/sub/x.parquet`, size: 1 },
        { key: `tenant=${T1}/date=2026-10-29/type=exec/x.txt`, size: 1 },
        { key: `tenant=${T1}/date=2026-13-45/type=exec/x.parquet`, size: 1 },
      ],
      get: (key) => store.get(key),
    };
    await expect(queryLake(odd, { tenantId: T1, from: "2026-10-29", to: "2026-10-29" })).resolves.toMatchObject({ filesMatched: 1 });
  });

  it("returns nothing for an empty lake or a tenant with no data", async () => {
    expect(await queryLake(store, { tenantId: T1, from: "2026-10-29", to: "2026-10-29" })).toEqual({
      rows: [],
      truncated: false,
      filesMatched: 0,
      filesRead: 0,
      filesSkipped: 0,
      listingTruncated: false,
    });
  });

  it("never lists more than MAX_FILES + 1 files, however many the tenant has, and says the answer is incomplete", async () => {
    const bytes = encodeParquet([row("a", at("2026-10-29", "01:00:00"), "exec")]);
    // A tenant with far more files than the cap, all in one day. The fake honours `limit` like a real store.
    const keys = Array.from({ length: MAX_FILES * 5 }, (_, i) => lakeKey(T1, "2026-10-29", "exec", `f${String(i).padStart(6, "0")}`));
    let handedOut = 0;
    let gets = 0;
    const many: LakeReader = {
      list: async (prefix, opts) => {
        const under = keys.filter((k) => k.startsWith(prefix)).slice(0, opts?.limit);
        handedOut += under.length;
        return under.map((key) => ({ key, size: bytes.length }));
      },
      get: async () => (gets++, bytes),
    };
    const r = await queryLake(many, { tenantId: T1, from: "2026-10-29", to: "2026-10-29", limit: MAX_ROWS });
    expect(handedOut).toBe(MAX_FILES + 1);
    expect(gets).toBe(MAX_FILES);
    expect(r).toMatchObject({ filesMatched: MAX_FILES, filesRead: MAX_FILES, filesSkipped: 1, listingTruncated: true });
  });

  it("spends the file budget across days and stops listing once it is spent", async () => {
    const bytes = encodeParquet([row("a", at("2026-10-28", "01:00:00"), "exec")]);
    const perDay = MAX_FILES - 1; // day 1 leaves room for one file of day 2; day 3 is never listed
    const asked: string[] = [];
    const limits: (number | undefined)[] = [];
    const days: LakeReader = {
      list: async (prefix, opts) => {
        asked.push(prefix);
        limits.push(opts?.limit);
        return Array.from({ length: perDay }, (_, i) => ({ key: `${prefix}type=exec/f${i}.parquet`, size: bytes.length })).slice(0, opts?.limit);
      },
      get: async () => bytes,
    };
    const r = await queryLake(days, { tenantId: T1, from: "2026-10-28", to: "2026-10-30" });
    expect(asked).toEqual([`tenant=${T1}/date=2026-10-28/`, `tenant=${T1}/date=2026-10-29/`]);
    expect(limits).toEqual([MAX_FILES + 1, 2]);
    expect(r.listingTruncated).toBe(true);
    expect(r.filesMatched).toBe(MAX_FILES);
  });

  it("does not report a truncated listing when the files fit exactly", async () => {
    const bytes = encodeParquet([row("a", at("2026-10-29", "01:00:00"), "exec")]);
    const keys = Array.from({ length: MAX_FILES }, (_, i) => lakeKey(T1, "2026-10-29", "exec", `f${String(i).padStart(5, "0")}`));
    const exact: LakeReader = {
      list: async (_p, opts) => keys.slice(0, opts?.limit).map((key) => ({ key, size: bytes.length })),
      get: async () => bytes,
    };
    const r = await queryLake(exact, { tenantId: T1, from: "2026-10-29", to: "2026-10-29", limit: MAX_ROWS });
    expect(r).toMatchObject({ filesMatched: MAX_FILES, filesSkipped: 0, listingTruncated: false });
  });

  it("rejects what it cannot take", async () => {
    const ok = { tenantId: T1, from: "2026-10-29", to: "2026-10-29" };
    for (const bad of [
      { ...ok, tenantId: "" },
      { ...ok, tenantId: "../x" },
      { ...ok, tenantId: "a/b" },
      { ...ok, tenantId: "a=b" },
      { ...ok, from: "2026-10-3" },
      { ...ok, from: "2026-02-30" },
      { ...ok, from: "2026-10-30", to: "2026-10-29" },
      { ...ok, from: "2025-01-01", to: "2026-10-29" },
      { ...ok, types: ["Exec"] },
      { ...ok, types: Array.from({ length: MAX_TYPES + 1 }, (_, i) => `t${i}`) },
      { ...ok, types: ["a/b"] },
      { ...ok, limit: 0 },
      { ...ok, limit: MAX_ROWS + 1 },
      { ...ok, limit: 1.5 },
      { ...ok, where: { event: "x" } as never },
      { ...ok, where: { comm: 5 as never } },
    ]) {
      await expect(queryLake(store, bad)).rejects.toThrow(RangeError);
    }
  });
});

describe("FsLakeStore.list with a limit", () => {
  it("returns the first `limit` keys in key order and rejects a limit that is not a positive integer", async () => {
    for (const name of ["c", "a", "b", "d"]) await put(T1, "2026-10-29", "exec", name, [row("a", at("2026-10-29", "01:00:00"), "exec")]);
    await put(T1, "2026-10-28", "exec", "z", [row("a", at("2026-10-28", "01:00:00"), "exec")]);
    const all = (await store.list(`tenant=${T1}/`)).map((f) => f.key);
    expect(all).toHaveLength(5);
    expect((await store.list(`tenant=${T1}/`, { limit: 3 })).map((f) => f.key)).toEqual(all.slice(0, 3));
    expect((await store.list(`tenant=${T1}/date=2026-10-29/`, { limit: 2 })).map((f) => f.key)).toEqual(all.slice(1, 3));
    expect(await store.list(`tenant=${T1}/`, { limit: 99 })).toHaveLength(5);
    await expect(store.list(`tenant=${T1}/`, { limit: 0 })).rejects.toThrow(RangeError);
    await expect(store.list(`tenant=${T1}/`, { limit: 1.5 })).rejects.toThrow(RangeError);
  });
});
