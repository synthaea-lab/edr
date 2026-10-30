import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { PrismaClient } from "@prisma/client";
import { SEARCH_PAGE_SIZE, searchFailure } from "@/lib/hunt-search";
import { FIELD_MAX, searchEventsWithinLimit } from "@/lib/hunt-events-search";
import { parseEventQuery } from "@/lib/hunt-events";
import { FsLakeStore, type LakeReader } from "@/lib/lake-store";
import { encodeParquet, lakeKey, lakeRow, type LakeRow as WriterRow } from "@/lib/lake-writer";

const T1 = "tenant-one";
const T2 = "tenant-two";
const NOW = new Date("2026-10-30T12:00:00Z");

let dir: string;
let store: FsLakeStore;
beforeEach(async () => {
  dir = await mkdtemp(path.join(os.tmpdir(), "hunt-events-"));
  store = new FsLakeStore(dir);
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

function row(agent: string, when: string, type: string, over: Record<string, unknown> = {}): WriterRow {
  const event = { type, meta: { comm: "bash" }, ...over };
  return lakeRow(agent, event, new Date(when), JSON.stringify(event));
}
async function put(tenant: string, day: string, type: string, flush: string, rows: WriterRow[]) {
  await store.put(lakeKey(tenant, day, type, flush), encodeParquet(rows));
}

/** Prisma with just what the search touches: a transaction, and the advisory lock answering `slotFree`. */
function fakePrisma(slotFree = true) {
  const tx = { $queryRaw: vi.fn(async () => [{ ok: slotFree }]) };
  const prisma = { $transaction: vi.fn(async (fn: (t: typeof tx) => Promise<unknown>) => fn(tx)) } as unknown as PrismaClient;
  return { prisma, tx };
}
const query = (over: Record<string, unknown> = {}) => parseEventQuery({ kind: "events", version: 1, lastDays: 3, ...over });

describe("searchEventsWithinLimit", () => {
  it("answers lake_off, without opening a transaction, when there is no reader", async () => {
    const { prisma } = fakePrisma();
    expect(await searchEventsWithinLimit(prisma, null, T1, query(), NOW)).toEqual({ status: "lake_off" });
    expect(prisma.$transaction).not.toHaveBeenCalled();
  });

  it("answers busy, and reads nothing, when the tenant has no free slot", async () => {
    const list = vi.fn(async () => []);
    const reader: LakeReader = { list, get: async () => new Uint8Array() };
    const { prisma } = fakePrisma(false);
    expect(await searchEventsWithinLimit(prisma, reader, T1, query(), NOW)).toEqual({ status: "busy" });
    expect(list).not.toHaveBeenCalled();
  });

  it("takes the slot before it reads, from the same two locks as the other sources", async () => {
    const { prisma, tx } = fakePrisma();
    await searchEventsWithinLimit(prisma, store, T1, query(), NOW);
    const sql = (tx.$queryRaw.mock.calls[0] as unknown as [{ sql: string; values: unknown[] }])[0];
    expect(sql.sql).toContain("pg_try_advisory_xact_lock");
    expect(sql.values).toEqual([`hunt_search:${T1}:0`]);
  });

  it("returns the newest events of the window, newest first, as rows of typed columns only", async () => {
    await put(T1, "2026-10-29", "exec", "a", [row("a1", "2026-10-29T08:00:00Z", "exec", { image_path: "/usr/bin/curl", args: ["curl", "-H", "Authorization: secret"] })]);
    await put(T1, "2026-10-30", "exec", "a", [row("a2", "2026-10-30T09:00:00Z", "exec", { path: "/tmp/x", sha256: "b".repeat(64) })]);
    await put(T1, "2026-10-20", "exec", "a", [row("a3", "2026-10-20T09:00:00Z", "exec")]); // out of a 3-day window
    const { prisma } = fakePrisma();
    const out = await searchEventsWithinLimit(prisma, store, T1, query(), NOW);
    expect(out.status).toBe("ok");
    if (out.status !== "ok") return;
    expect(out.page).toMatchObject({ source: "events", truncated: false, incomplete: false, from: "2026-10-28", to: "2026-10-30" });
    expect(out.page.rows.map((r) => [r.agentId, r.timestamp])).toEqual([
      ["a2", "2026-10-30T09:00:00.000Z"],
      ["a1", "2026-10-29T08:00:00.000Z"],
    ]);
    expect(out.page.rows[1]).toEqual({
      type: "exec", timestamp: "2026-10-29T08:00:00.000Z", agentId: "a1", comm: "bash", path: null,
      imagePath: "/usr/bin/curl", daddr: null, query: null, sha256: null,
    });
    // A command line lives in the event's text, which is neither read nor returned.
    expect(JSON.stringify(out.page)).not.toContain("Authorization");
    expect(Object.keys(out.page.rows[0])).not.toContain("event");
  });

  it("applies the types and filters of the query", async () => {
    await put(T1, "2026-10-30", "exec", "a", [row("a1", "2026-10-30T01:00:00Z", "exec", { image_path: "/usr/bin/curl" }), row("a2", "2026-10-30T02:00:00Z", "exec", { image_path: "/bin/ls" })]);
    await put(T1, "2026-10-30", "connect", "a", [row("a1", "2026-10-30T03:00:00Z", "connect", { daddr: "203.0.113.9" })]);
    const { prisma } = fakePrisma();
    const rowsOf = async (q: ReturnType<typeof query>) => {
      const out = await searchEventsWithinLimit(prisma, store, T1, q, NOW);
      return out.status === "ok" ? out.page.rows.map((r) => r.agentId + ":" + r.type) : null;
    };
    expect(await rowsOf(query({ types: ["connect"] }))).toEqual(["a1:connect"]);
    expect(await rowsOf(query({ where: { imagePath: "/bin/ls" } }))).toEqual(["a2:exec"]);
    expect(await rowsOf(query({ types: ["exec"], where: { agentId: "a1" } }))).toEqual(["a1:exec"]);
  });

  it("returns one page of SEARCH_PAGE_SIZE rows, the newest, and says there are more", async () => {
    const rows = Array.from({ length: SEARCH_PAGE_SIZE + 10 }, (_, i) => row(`a${i}`, `2026-10-30T${String(Math.floor(i / 60)).padStart(2, "0")}:${String(i % 60).padStart(2, "0")}:00Z`, "exec"));
    await put(T1, "2026-10-30", "exec", "a", rows);
    const { prisma } = fakePrisma();
    const out = await searchEventsWithinLimit(prisma, store, T1, query(), NOW);
    if (out.status !== "ok") throw new Error("expected ok");
    expect(out.page.rows).toHaveLength(SEARCH_PAGE_SIZE);
    expect(out.page.truncated).toBe(true);
    expect(out.page.rows[0].agentId).toBe(`a${SEARCH_PAGE_SIZE + 9}`);
    expect(out.page.rows[SEARCH_PAGE_SIZE - 1].agentId).toBe("a10");
  });

  it("cuts each text field of a row to FIELD_MAX", async () => {
    await put(T1, "2026-10-30", "exec", "a", [row("a1", "2026-10-30T01:00:00Z", "exec", { path: "/x".repeat(FIELD_MAX) })]);
    const { prisma } = fakePrisma();
    const out = await searchEventsWithinLimit(prisma, store, T1, query(), NOW);
    if (out.status !== "ok") throw new Error("expected ok");
    expect(out.page.rows[0].path).toHaveLength(FIELD_MAX);
  });

  it("searches the tenant it was given and no other, whatever the store lists", async () => {
    await put(T1, "2026-10-30", "exec", "a", [row("mine", "2026-10-30T01:00:00Z", "exec")]);
    await put(T2, "2026-10-30", "exec", "a", [row("theirs", "2026-10-30T02:00:00Z", "exec")]);
    const asked: string[] = [];
    const wide: LakeReader = { list: async (p) => (asked.push(p), store.list("")), get: (k) => store.get(k) };
    const { prisma } = fakePrisma();
    const out = await searchEventsWithinLimit(prisma, wide, T1, query(), NOW);
    if (out.status !== "ok") throw new Error("expected ok");
    expect(out.page.rows.map((r) => r.agentId)).toEqual(["mine"]);
    expect(asked).toEqual([`tenant=${T1}/`]);
  });

  it("flags an incomplete answer when the archive had more files than one search reads", async () => {
    const bytes = encodeParquet([row("a", "2026-10-30T01:00:00Z", "exec")]);
    const keys = Array.from({ length: 2005 }, (_, i) => lakeKey(T1, "2026-10-30", "exec", `f${String(i).padStart(5, "0")}`));
    const many: LakeReader = { list: async () => keys.map((key) => ({ key, size: 1 })), get: async () => bytes };
    const { prisma } = fakePrisma();
    const out = await searchEventsWithinLimit(prisma, many, T1, query(), NOW);
    if (out.status !== "ok") throw new Error("expected ok");
    expect(out.page.incomplete).toBe(true);
  });

  it("gives up at its time limit with a TimeoutError that maps to a 504", async () => {
    await put(T1, "2026-10-30", "exec", "a", [row("a1", "2026-10-30T01:00:00Z", "exec")]);
    await put(T1, "2026-10-30", "exec", "b", [row("a2", "2026-10-30T02:00:00Z", "exec")]);
    const slow: LakeReader = {
      list: (p) => store.list(p),
      get: async (k) => {
        await new Promise((r) => setTimeout(r, 60));
        return store.get(k);
      },
    };
    const { prisma } = fakePrisma();
    const failed = await searchEventsWithinLimit(prisma, slow, T1, query(), NOW, { timeoutMs: 30 }).catch((e) => e);
    expect(failed).toMatchObject({ name: "TimeoutError" });
    expect(searchFailure(failed).status).toBe(504);
  });

  it("keeps the slot held until the read is over, then releases it by ending the transaction", async () => {
    await put(T1, "2026-10-30", "exec", "a", [row("a1", "2026-10-30T01:00:00Z", "exec")]);
    const order: string[] = [];
    const { prisma, tx } = fakePrisma();
    tx.$queryRaw.mockImplementation(async () => (order.push("lock"), [{ ok: true }]));
    const reader: LakeReader = { list: (p) => (order.push("list"), store.list(p)), get: (k) => (order.push("get"), store.get(k)) };
    await searchEventsWithinLimit(prisma, reader, T1, query(), NOW);
    expect(order).toEqual(["lock", "list", "get"]);
  });
});
