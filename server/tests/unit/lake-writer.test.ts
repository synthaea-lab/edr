import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { parquetReadObjects } from "hyparquet";
import type { PrismaClient } from "@prisma/client";
import { FsLakeStore, assertSafeKey, type LakeStore } from "@/lib/lake-store";
import { lakeStoreFromEnv } from "@/lib/lake-env";
import {
  OTHER_TYPE,
  dayOf,
  drainLakeQueue,
  encodeParquet,
  enqueueLakeBatch,
  eventSources,
  isPastRetention,
  lakeKey,
  lakeRow,
  typeSegment,
} from "@/lib/lake-writer";

const SHA = "a".repeat(64);
const RECEIVED = new Date(Date.UTC(2026, 9, 29, 10, 0, 0));
const NS = (d: Date) => d.getTime() * 1_000_000;

const exec = (over: Record<string, unknown> = {}) => ({
  type: "exec",
  meta: { pid: 10, comm: "bash", timestamp_ns: NS(RECEIVED) },
  image_path: "/usr/bin/curl",
  sha256: SHA,
  ...over,
});

/** Reads a Parquet file the writer produced, the way a lake consumer would. */
async function readParquet(bytes: Uint8Array): Promise<Record<string, unknown>[]> {
  const file = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
  return (await parquetReadObjects({ file })) as Record<string, unknown>[];
}

describe("typeSegment", () => {
  it("keeps a plain event type", () => {
    expect(typeSegment("file_open")).toBe("file_open");
  });

  it("sends anything that could shape a path to 'other'", () => {
    for (const bad of ["../etc", "a/b", "Exec", "", "x".repeat(65), "exec ", "e\u0000x", 7, null, undefined, "-x", "9x"]) {
      expect(typeSegment(bad)).toBe(OTHER_TYPE);
    }
  });
});

describe("dayOf and lakeKey", () => {
  it("cuts the day in UTC", () => {
    expect(dayOf(new Date("2026-10-29T23:59:59.999Z"))).toBe("2026-10-29");
    expect(dayOf(new Date("2026-10-30T00:00:00.000Z"))).toBe("2026-10-30");
  });

  it("lays out tenant, date, type and file", () => {
    expect(lakeKey("t1", "2026-10-29", "exec", "abc")).toBe("tenant=t1/date=2026-10-29/type=exec/abc.parquet");
  });
});

describe("lakeRow", () => {
  it("takes the typed columns and keeps the whole event", () => {
    const row = lakeRow("agent-1", exec(), RECEIVED);
    expect(row).toMatchObject({ agentId: "agent-1", comm: "bash", imagePath: "/usr/bin/curl", sha256: SHA, path: null, daddr: null, query: null });
    expect(row.at).toEqual(RECEIVED);
    expect(JSON.parse(row.event)).toEqual(exec());
  });

  it("dates a far-future or missing stamp at the time of receipt", () => {
    const future = lakeRow("a", exec({ meta: { timestamp_ns: NS(RECEIVED) + 3 * 86_400_000 * 1_000_000 } }), RECEIVED);
    const missing = lakeRow("a", { type: "exec" }, RECEIVED);
    expect(future.at).toEqual(RECEIVED);
    expect(missing.at).toEqual(RECEIVED);
  });

  it("drops a value that is not a hash from the hash column and bounds a long path", () => {
    expect(lakeRow("a", exec({ sha256: "not-a-hash" }), RECEIVED).sha256).toBeNull();
    expect(lakeRow("a", exec({ path: "/x".repeat(2000) }), RECEIVED).path).toHaveLength(1024);
  });
});

describe("eventSources", () => {
  it("returns each event's text exactly, whitespace between events aside", () => {
    expect(eventSources('{"events":[ {"a":1} , {"b":[1,2]},"s", 3 ]}')).toEqual(['{"a":1}', '{"b":[1,2]}', '"s"', "3"]);
  });

  it("keeps an integer above 2^53 that JSON.parse would round", () => {
    const text = '{"type":"exec","meta":{"timestamp_ns":1793287944852336852}}';
    expect(JSON.stringify(JSON.parse(text))).not.toBe(text);
    expect(eventSources(`{"events":[${text}]}`)).toEqual([text]);
  });

  it("is not fooled by brackets, commas, quotes and escapes inside strings", () => {
    const text = '{"type":"x","query":"a]},[{\\"\\\\"}';
    expect(eventSources(`{"events":[${text},{"type":"y"}]}`)).toEqual([text, '{"type":"y"}']);
  });

  it("ignores an events key that is nested, and takes the last top-level one like JSON.parse", () => {
    expect(eventSources('{"meta":{"events":[1]},"events":[{"a":1}]}')).toEqual(['{"a":1}']);
    expect(eventSources('{"events":[1],"events":[2,3]}')).toEqual(["2", "3"]);
  });

  it("is null without a top-level events array, and empty for an empty one", () => {
    expect(eventSources('{"other":[1]}')).toBeNull();
    expect(eventSources('{"events":{}}')).toBeNull();
    expect(eventSources('{"events":[]}')).toEqual([]);
  });

  it("agrees with JSON.parse on the number and order of the elements", () => {
    const body = JSON.stringify({ x: "[", events: [{ type: "a", n: [1, { m: "}," }] }, "q\"", 5, null, [], {}], z: { events: 1 } });
    expect(eventSources(body)!.map((t) => JSON.parse(t))).toEqual(JSON.parse(body).events);
  });
});

describe("encodeParquet", () => {
  it("writes a file a reader gets the rows back from, nulls included", async () => {
    const rows = [lakeRow("agent-1", exec(), RECEIVED), lakeRow("agent-1", { type: "dns_query", query: "example.com", meta: { comm: "curl", timestamp_ns: NS(RECEIVED) } }, RECEIVED)];
    const back = await readParquet(encodeParquet(rows));
    expect(back).toHaveLength(2);
    expect(back[0]).toMatchObject({ agent_id: "agent-1", comm: "bash", image_path: "/usr/bin/curl", sha256: SHA, query: null });
    expect(back[1]).toMatchObject({ comm: "curl", query: "example.com", sha256: null });
    expect(JSON.parse(back[0].event as string).type).toBe("exec");
    expect(new Date(back[0].ts as Date)).toEqual(RECEIVED);
  });
});

describe("FsLakeStore", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(path.join(os.tmpdir(), "lake-"));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("creates the directories and writes the bytes", async () => {
    await new FsLakeStore(dir).put("tenant=t/date=2026-10-29/type=exec/f.parquet", new Uint8Array([1, 2, 3]));
    expect(Array.from(await readFile(path.join(dir, "tenant=t/date=2026-10-29/type=exec/f.parquet")))).toEqual([1, 2, 3]);
  });

  it("replaces a file written twice and leaves no temporary file", async () => {
    const store = new FsLakeStore(dir);
    await store.put("t/f.parquet", new Uint8Array([1]));
    await store.put("t/f.parquet", new Uint8Array([2]));
    expect(Array.from(await readFile(path.join(dir, "t/f.parquet")))).toEqual([2]);
    expect(await readdir(path.join(dir, "t"))).toEqual(["f.parquet"]);
  });

  it("refuses a key that could leave the root", async () => {
    const store = new FsLakeStore(dir);
    for (const bad of ["../x", "a/../../x", "/abs", "a//b", "a/./b", "", "a b", "a\\b", "a\u0000b"]) {
      await expect(store.put(bad, new Uint8Array([1]))).rejects.toThrow(/Unsafe lake key/);
      expect(() => assertSafeKey(bad)).toThrow();
    }
  });
});

describe("lakeStoreFromEnv", () => {
  it("is off unless LAKE_DIR is set and non-empty", () => {
    expect(lakeStoreFromEnv({})).toBeNull();
    expect(lakeStoreFromEnv({ LAKE_DIR: "" })).toBeNull();
    expect(lakeStoreFromEnv({ LAKE_DIR: "/data/lake" })).toBeInstanceOf(FsLakeStore);
  });
});

describe("enqueueLakeBatch", () => {
  it("stores the batch with its size, and nothing for an empty one", async () => {
    const create = vi.fn().mockResolvedValue({});
    const db = { lakeBatch: { create } } as unknown as Pick<PrismaClient, "lakeBatch">;
    await enqueueLakeBatch(db, { tenantId: "t", agentId: "a", events: [exec(), exec()], receivedAt: RECEIVED });
    expect(create).toHaveBeenCalledWith({ data: { tenantId: "t", agentId: "a", receivedAt: RECEIVED, events: [exec(), exec()], eventCount: 2 } });
    create.mockClear();
    await enqueueLakeBatch(db, { tenantId: "t", agentId: "a", events: [], receivedAt: RECEIVED });
    expect(create).not.toHaveBeenCalled();
  });

  it("lets an insert failure reach the caller, so ingest answers 5xx", async () => {
    const db = { lakeBatch: { create: vi.fn().mockRejectedValue(new Error("db down")) } } as unknown as Pick<PrismaClient, "lakeBatch">;
    await expect(enqueueLakeBatch(db, { tenantId: "t", agentId: "a", events: [exec()], receivedAt: RECEIVED })).rejects.toThrow("db down");
  });
});

type Batch = { id: string; tenantId: string; agentId: string; receivedAt: Date; events: unknown; flushId?: string | null };

/** The slice of Prisma `drainLakeQueue` uses, backed by arrays. */
function fakePrisma(batches: Batch[], tenants: { id: string; lakeRetentionDays: number }[]) {
  const state = { batches: batches.map((b) => ({ ...b, flushId: b.flushId ?? null })), lockedFlushes: new Set<string>() };
  const lakeBatch = {
    findMany: vi.fn(async ({ where }: { where: { flushId?: string | { not: null } } }) => {
      const wanted = where.flushId;
      const rows = state.batches.filter((b) => (typeof wanted === "string" ? b.flushId === wanted : b.flushId !== null));
      // `distinct: ["flushId"]` is only asked for with `select: { flushId }`.
      return typeof wanted === "string" ? rows : rows.filter((b, i) => rows.findIndex((o) => o.flushId === b.flushId) === i);
    }),
    updateMany: vi.fn(async ({ where, data }: { where: { id: { in: string[] } }; data: { flushId: string } }) => {
      for (const b of state.batches) if (where.id.in.includes(b.id)) b.flushId = data.flushId;
    }),
    deleteMany: vi.fn(async ({ where }: { where: { id: { in: string[] } } }) => {
      state.batches = state.batches.filter((b) => !where.id.in.includes(b.id));
    }),
    count: vi.fn(async () => state.batches.length),
  };
  const tx = {
    // The unassigned batches, or the advisory lock on a flush.
    $queryRaw: vi.fn(async (strings: TemplateStringsArray, ...values: unknown[]) => {
      if (strings.join("").includes("pg_try_advisory_xact_lock")) {
        const flush = String(values[0]);
        const ok = !state.lockedFlushes.has(flush);
        return [{ ok }];
      }
      return state.batches.filter((b) => b.flushId === null).map((b) => ({ id: b.id }));
    }),
    lakeBatch,
    tenant: { findMany: vi.fn(async ({ where }: { where: { id: { in: string[] } } }) => tenants.filter((t) => where.id.in.includes(t.id))) },
  };
  const prisma = {
    lakeBatch,
    // A real transaction rolls back when the callback throws; the fake restores the rows and their flush ids.
    $transaction: vi.fn(async (fn: (t: typeof tx) => Promise<unknown>) => {
      const before = state.batches.map((b) => ({ ...b }));
      try {
        return await fn(tx);
      } catch (e) {
        state.batches = before;
        throw e;
      }
    }),
  } as unknown as PrismaClient;
  return { prisma, state, tx };
}

class MemoryStore implements Pick<LakeStore, "put"> {
  files = new Map<string, Uint8Array>();
  async put(key: string, body: Uint8Array) {
    this.files.set(key, body);
  }
}

describe("isPastRetention", () => {
  const now = new Date("2026-10-30T15:00:00Z");
  it("is true from the day that is `retentionDays` old, as the retention job counts it", () => {
    expect(isPastRetention("2026-07-31", 90, now)).toBe(true); // 91 days
    expect(isPastRetention("2026-08-01", 90, now)).toBe(true); // 90 days: deleted at the next run
    expect(isPastRetention("2026-08-02", 90, now)).toBe(false); // 89 days
    expect(isPastRetention("2026-10-30", 0, now)).toBe(true);
  });
  it("is false for today, a future day and an unparseable day", () => {
    expect(isPastRetention("2026-10-30", 1, now)).toBe(false);
    expect(isPastRetention("2026-11-02", 90, now)).toBe(false);
    expect(isPastRetention("not-a-day", 0, now)).toBe(false);
  });
});

describe("drainLakeQueue", () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(RECEIVED);
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("drops, and counts, an event dated past its tenant's retention, and keeps the rest of the batch", async () => {
    const old = RECEIVED.getTime() - 91 * 86_400_000;
    const { prisma, state } = fakePrisma(
      [{ id: "b1", tenantId: "t1", agentId: "a1", receivedAt: RECEIVED, events: [exec(), exec({ meta: { comm: "old", timestamp_ns: NS(new Date(old)) } })] }],
      [{ id: "t1", lakeRetentionDays: 90 }]
    );
    const store = new MemoryStore();
    expect(await drainLakeQueue(prisma, store)).toMatchObject({ events: 1, files: 1, droppedPastRetention: 1, remaining: 0 });
    expect(Array.from(store.files.keys())).toEqual([expect.stringContaining("/date=2026-10-29/")]);
    expect(state.batches).toHaveLength(0);
  });

  it("applies each tenant's own retention", async () => {
    const tenDaysAgo = new Date(RECEIVED.getTime() - 10 * 86_400_000);
    const event = exec({ meta: { comm: "x", timestamp_ns: NS(tenDaysAgo) } });
    const { prisma } = fakePrisma(
      [
        { id: "b1", tenantId: "short", agentId: "a1", receivedAt: RECEIVED, events: [event] },
        { id: "b2", tenantId: "long", agentId: "a2", receivedAt: RECEIVED, events: [event] },
      ],
      [{ id: "short", lakeRetentionDays: 7 }, { id: "long", lakeRetentionDays: 90 }]
    );
    const store = new MemoryStore();
    expect(await drainLakeQueue(prisma, store)).toMatchObject({ events: 1, droppedPastRetention: 1 });
    expect(Array.from(store.files.keys()).every((k) => k.startsWith("tenant=long/"))).toBe(true);
  });
  it("does nothing on an empty queue", async () => {
    const { prisma } = fakePrisma([], []);
    const store = new MemoryStore();
    expect(await drainLakeQueue(prisma, store)).toEqual({ batches: 0, events: 0, files: 0, droppedNoRetention: 0, droppedPastRetention: 0, skippedMalformed: 0, remaining: 0 });
    expect(store.files.size).toBe(0);
  });

  it("writes one file per tenant, day and type, and empties the queue", async () => {
    const nextDay = new Date(RECEIVED.getTime() + 86_400_000);
    const { prisma, state } = fakePrisma(
      [
        { id: "b1", tenantId: "t1", agentId: "a1", receivedAt: RECEIVED, events: [exec(), { type: "dns_query", query: "x.test", meta: { timestamp_ns: NS(RECEIVED) } }] },
        { id: "b2", tenantId: "t1", agentId: "a2", receivedAt: nextDay, events: [exec({ meta: { comm: "sh", timestamp_ns: NS(nextDay) } })] },
        { id: "b3", tenantId: "t2", agentId: "a3", receivedAt: RECEIVED, events: [exec()] },
      ],
      [{ id: "t1", lakeRetentionDays: 90 }, { id: "t2", lakeRetentionDays: 90 }]
    );
    const store = new MemoryStore();
    const result = await drainLakeQueue(prisma, store);
    expect(result).toEqual({ batches: 3, events: 4, files: 4, droppedNoRetention: 0, droppedPastRetention: 0, skippedMalformed: 0, remaining: 0 });
    expect(state.batches).toHaveLength(0);
    const keys = Array.from(store.files.keys()).map((k) => k.replace(/\/[0-9a-f]{32}\.parquet$/, ""));
    expect(keys.sort()).toEqual([
      "tenant=t1/date=2026-10-29/type=dns_query",
      "tenant=t1/date=2026-10-29/type=exec",
      "tenant=t1/date=2026-10-30/type=exec",
      "tenant=t2/date=2026-10-29/type=exec",
    ]);
  });

  it("keeps a tenant's events out of another tenant's files", async () => {
    const { prisma } = fakePrisma(
      [
        { id: "b1", tenantId: "t1", agentId: "a1", receivedAt: RECEIVED, events: [exec({ image_path: "/only/t1" })] },
        { id: "b2", tenantId: "t2", agentId: "a2", receivedAt: RECEIVED, events: [exec({ image_path: "/only/t2" })] },
      ],
      [{ id: "t1", lakeRetentionDays: 90 }, { id: "t2", lakeRetentionDays: 90 }]
    );
    const store = new MemoryStore();
    await drainLakeQueue(prisma, store);
    for (const [key, bytes] of Array.from(store.files)) {
      const rows = await readParquet(bytes);
      const owner = key.startsWith("tenant=t1/") ? "/only/t1" : "/only/t2";
      expect(rows.map((r) => r.image_path)).toEqual([owner]);
    }
  });

  it("routes an event type that is not a safe path segment to 'other' and keeps the real type in the event", async () => {
    const { prisma } = fakePrisma(
      [{ id: "b1", tenantId: "t1", agentId: "a1", receivedAt: RECEIVED, events: [{ type: "../../etc/passwd", meta: { timestamp_ns: NS(RECEIVED) } }] }],
      [{ id: "t1", lakeRetentionDays: 90 }]
    );
    const store = new MemoryStore();
    await drainLakeQueue(prisma, store);
    const [[key, bytes]] = Array.from(store.files);
    expect(key).toMatch(/^tenant=t1\/date=2026-10-29\/type=other\/[0-9a-f]{32}\.parquet$/);
    expect(JSON.parse((await readParquet(bytes))[0].event as string).type).toBe("../../etc/passwd");
  });

  it("drops what a tenant with no retention would keep, and says how many", async () => {
    const { prisma, state } = fakePrisma(
      [
        { id: "b1", tenantId: "none", agentId: "a1", receivedAt: RECEIVED, events: [exec(), exec()] },
        { id: "b2", tenantId: "t1", agentId: "a2", receivedAt: RECEIVED, events: [exec()] },
      ],
      [{ id: "none", lakeRetentionDays: 0 }, { id: "t1", lakeRetentionDays: 90 }]
    );
    const store = new MemoryStore();
    const result = await drainLakeQueue(prisma, store);
    expect(result).toMatchObject({ events: 1, files: 1, droppedNoRetention: 2, remaining: 0 });
    expect(Array.from(store.files.keys()).every((k) => k.startsWith("tenant=t1/"))).toBe(true);
    expect(state.batches).toHaveLength(0);
  });

  it("writes a queued event's source text into the file, so a timestamp above 2^53 is not rounded", async () => {
    const text = `{"type":"exec","meta":{"comm":"bash","timestamp_ns":${NS(RECEIVED)}852}}`;
    const { prisma } = fakePrisma(
      [{ id: "b1", tenantId: "t1", agentId: "a1", receivedAt: RECEIVED, events: [text] }],
      [{ id: "t1", lakeRetentionDays: 90 }]
    );
    const store = new MemoryStore();
    expect(await drainLakeQueue(prisma, store)).toMatchObject({ events: 1, skippedMalformed: 0 });
    const rows = await readParquet(Array.from(store.files.values())[0]);
    expect(rows[0].event).toBe(text);
    expect(rows[0]).toMatchObject({ comm: "bash" });
    expect(new Date(rows[0].ts as Date)).toEqual(RECEIVED);
  });

  it("still reads a row queued as parsed objects, and skips a source text that is not JSON", async () => {
    const { prisma } = fakePrisma(
      [{ id: "b1", tenantId: "t1", agentId: "a1", receivedAt: RECEIVED, events: [exec(), "{not json", '"just a string"'] }],
      [{ id: "t1", lakeRetentionDays: 90 }]
    );
    expect(await drainLakeQueue(prisma, new MemoryStore())).toMatchObject({ events: 1, skippedMalformed: 2 });
  });

  it("skips a malformed queued event without losing the good ones", async () => {
    const { prisma } = fakePrisma(
      [{ id: "b1", tenantId: "t1", agentId: "a1", receivedAt: RECEIVED, events: [exec(), 7, null, [], { nope: true }] }],
      [{ id: "t1", lakeRetentionDays: 90 }]
    );
    const store = new MemoryStore();
    expect(await drainLakeQueue(prisma, store)).toMatchObject({ events: 1, skippedMalformed: 4 });
  });

  it("leaves the rows queued when a file cannot be written, so the next drain retries them", async () => {
    const { prisma, state } = fakePrisma(
      [{ id: "b1", tenantId: "t1", agentId: "a1", receivedAt: RECEIVED, events: [exec()] }],
      [{ id: "t1", lakeRetentionDays: 90 }]
    );
    const failing: Pick<LakeStore, "put"> = { put: vi.fn().mockRejectedValue(new Error("disk full")) };
    await expect(drainLakeQueue(prisma, failing)).rejects.toThrow("disk full");
    expect(state.batches).toHaveLength(1);
  });

  it("keeps a failed flush's batches and id, and the retry writes the same file under the same name (#1093)", async () => {
    const { prisma, state } = fakePrisma(
      [{ id: "b1", tenantId: "t1", agentId: "a1", receivedAt: RECEIVED, events: [exec({ image_path: "/e/1" })] }],
      [{ id: "t1", lakeRetentionDays: 90 }]
    );
    await expect(drainLakeQueue(prisma, { put: async () => Promise.reject(new Error("disk full")) })).rejects.toThrow("disk full");
    // The assignment committed before the write; the failed write left the batch queued under it.
    expect(state.batches).toHaveLength(1);
    const flushId = state.batches[0].flushId;
    expect(flushId).not.toBeNull();
    const store = new MemoryStore();
    await drainLakeQueue(prisma, store);
    expect(Array.from(store.files.keys())).toEqual([expect.stringContaining(`/${flushId!.replace(/-/g, "")}.parquet`)]);
    expect(state.batches).toHaveLength(0);
  });

  it("does not let a batch that arrives between a failed drain and its retry change what the failed flush holds (#1093)", async () => {
    const { prisma, state } = fakePrisma(
      [{ id: "b1", tenantId: "t1", agentId: "a1", receivedAt: RECEIVED, events: [exec({ image_path: "/e/1" })] }],
      [{ id: "t1", lakeRetentionDays: 90 }]
    );
    // The first file reaches the store, then the drain dies: the file stays, the batch stays queued.
    const survivor = new MemoryStore();
    let puts = 0;
    await expect(
      drainLakeQueue(prisma, {
        put: async (key: string, body: Uint8Array) => {
          await survivor.put(key, body);
          if (++puts === 1) throw new Error("crash");
        },
      })
    ).rejects.toThrow("crash");
    state.batches.push({ id: "b2", tenantId: "t1", agentId: "a1", receivedAt: new Date(RECEIVED.getTime() + 1000), events: [exec({ image_path: "/e/2" })], flushId: null });
    await drainLakeQueue(prisma, survivor);

    const seen: unknown[] = [];
    for (const bytes of Array.from(survivor.files.values())) seen.push(...(await readParquet(bytes)).map((r) => r.image_path));
    expect(seen.sort()).toEqual(["/e/1", "/e/2"]);
    // The retried flush replaced its own file; the new batch got a different flush and its own file.
    expect(survivor.files.size).toBe(2);
    expect(new Set(survivor.files.keys()).size).toBe(2);
  });

  it("assigns a new flush to batches that arrive after another flush was assigned", async () => {
    const { prisma, state } = fakePrisma(
      [{ id: "b1", tenantId: "t1", agentId: "a1", receivedAt: RECEIVED, events: [exec()] }],
      [{ id: "t1", lakeRetentionDays: 90 }]
    );
    await expect(drainLakeQueue(prisma, { put: async () => Promise.reject(new Error("down")) })).rejects.toThrow("down");
    state.batches.push({ id: "b2", tenantId: "t1", agentId: "a1", receivedAt: RECEIVED, events: [exec()], flushId: null });
    await expect(drainLakeQueue(prisma, { put: async () => Promise.reject(new Error("down")) })).rejects.toThrow("down");
    const [a, b] = state.batches;
    expect(a.flushId).not.toBeNull();
    expect(b.flushId).not.toBeNull();
    expect(a.flushId).not.toBe(b.flushId);
  });

  it("skips a flush another drain holds, and writes nothing for it", async () => {
    const { prisma, state } = fakePrisma(
      [{ id: "b1", tenantId: "t1", agentId: "a1", receivedAt: RECEIVED, events: [exec()], flushId: "held" }],
      [{ id: "t1", lakeRetentionDays: 90 }]
    );
    state.lockedFlushes.add("held");
    const store = new MemoryStore();
    expect(await drainLakeQueue(prisma, store)).toMatchObject({ batches: 0, files: 0, remaining: 1 });
    expect(store.files.size).toBe(0);
    expect(state.batches).toHaveLength(1);
  });

  it("takes at most the requested number of batches", async () => {
    const { prisma, tx } = fakePrisma([], []);
    await drainLakeQueue(prisma, new MemoryStore(), { maxBatches: 7 });
    const call = tx.$queryRaw.mock.calls[0] as unknown as [TemplateStringsArray, ...unknown[]];
    expect(call.slice(1)).toContain(7);
  });
});
