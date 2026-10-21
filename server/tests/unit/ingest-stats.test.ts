import { describe, expect, it, vi } from "vitest";
import {
  acceptedOutcome,
  foldRows,
  hourBucket,
  pruneIngestStats,
  recordIngest,
  refusedOutcome,
  windowStart,
  lagOf,
} from "@/lib/ingest-stats";

const LAG = { sumMs: 900, count: 3, maxMs: 500 };
const at = (h: number, m = 0, s = 0) => new Date(Date.UTC(2026, 9, 20, h, m, s));

describe("hourBucket / windowStart", () => {
  it("floors to the start of the hour", () => {
    expect(hourBucket(at(12, 59, 59))).toEqual(at(12));
    expect(hourBucket(at(12))).toEqual(at(12));
  });

  it("starts the window at the bucket the instant one hour ago falls in", () => {
    expect(windowStart(at(12, 30))).toEqual(at(11));
    expect(windowStart(at(12))).toEqual(at(11));
  });
});

describe("lagOf", () => {
  it("sums, counts and keeps the worst age, and is null for no events", () => {
    expect(lagOf([at(11, 59), at(11, 58, 30), at(12)], at(12))).toEqual({ sumMs: 150_000, count: 3, maxMs: 90_000 });
    expect(lagOf([], at(12))).toBeNull();
  });

  it("never goes negative for an event stamped ahead of the server", () => {
    expect(lagOf([at(12, 5)], at(12))).toEqual({ sumMs: 0, count: 1, maxMs: 0 });
  });
});

describe("outcomes", () => {
  it("derives accepted from received and skipped", () => {
    expect(acceptedOutcome(10, 3, LAG)).toEqual({ received: 10, accepted: 7, skipped: 3, refusedStatus: null, lag: LAG });
  });

  it("carries the status of a refusal and takes nothing", () => {
    expect(refusedOutcome(413, 1001)).toEqual({ received: 1001, accepted: 0, skipped: 0, refusedStatus: 413, lag: null });
  });
});

describe("recordIngest", () => {
  const run = async (outcome: ReturnType<typeof acceptedOutcome>) => {
    const db = { $executeRaw: vi.fn().mockResolvedValue(1) };
    await recordIngest(db, "t1", "a1", "events", outcome, at(12, 30));
    return db.$executeRaw.mock.calls[0][0];
  };

  it("adds to the hour bucket, keeping the worst lag and the latest acceptance", async () => {
    const q = await run(acceptedOutcome(5, 1, { sumMs: 2000, count: 4, maxMs: 1200 }));
    expect(q.values).toEqual([
      "t1", "a1", "events", at(12), 5, 4, 1, 0, 0, 2000, 4, 1200, at(12, 30),
    ]);
    expect(q.sql).toContain("ON CONFLICT (tenant_id, agent_id, kind, bucket)");
    expect(q.sql).toContain("GREATEST(ingest_stats.lag_max_ms");
    expect(q.sql).toContain("GREATEST(ingest_stats.last_accepted_at");
  });

  it("sorts a refusal into its status class and leaves last_accepted_at null", async () => {
    expect((await run(refusedOutcome(400))).values.slice(7, 13)).toEqual([1, 0, 0, 0, null, null]);
    expect((await run(refusedOutcome(503))).values.slice(7, 13)).toEqual([0, 1, 0, 0, null, null]);
  });

  it("never throws: a stats failure must not fail an ingest", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    const db = { $executeRaw: vi.fn().mockRejectedValue(new Error("db down")) };
    await expect(recordIngest(db, "t1", "a1", "events", acceptedOutcome(1, 0, null), at(12))).resolves.toBeUndefined();
    spy.mockRestore();
  });
});

describe("foldRows", () => {
  const row = (over: Record<string, unknown>) => ({
    agent_id: "a1", kind: "events", last_accepted_at: null,
    refused_4xx: null, refused_5xx: null, skipped: null,
    lag_sum_ms: null, lag_count: null, lag_max_ms: null, ...over,
  });

  it("gives one entry per agent: last time per kind, sums, and the worst lag", () => {
    const m = foldRows([
      row({ kind: "events", last_accepted_at: at(12), refused_4xx: 2, skipped: 3, lag_sum_ms: 6000, lag_count: 3, lag_max_ms: 4000 }),
      row({ kind: "detection", last_accepted_at: at(11), refused_5xx: 1, lag_sum_ms: 10000, lag_count: 1, lag_max_ms: 9000 }),
      row({ agent_id: "a2", kind: "beacon" }),
    ]);
    expect(m.get("a1")).toEqual({
      agentId: "a1",
      lastAccepted: { events: at(12).toISOString(), detection: at(11).toISOString(), beacon: null },
      refused4xx: 2, refused5xx: 1, skipped: 3, lagMeanMs: 4000, lagMaxMs: 9000,
    });
    expect(m.get("a2")?.lastAccepted).toEqual({ events: null, detection: null, beacon: null });
    expect(m.get("a2")?.lagMaxMs).toBeNull();
    expect(m.get("a2")?.lagMeanMs).toBeNull();
  });

  it("ignores a kind it does not know rather than failing the page", () => {
    expect(foldRows([row({ kind: "future", last_accepted_at: at(12) })]).get("a1")?.lastAccepted.events).toBeNull();
  });
});

describe("pruneIngestStats", () => {
  it("drops buckets older than the retention and reports how many", async () => {
    const db = { ingestStat: { deleteMany: vi.fn().mockResolvedValue({ count: 7 }) } };
    expect(await pruneIngestStats(db as never, at(12), 14)).toBe(7);
    expect(db.ingestStat.deleteMany).toHaveBeenCalledWith({
      where: { bucket: { lt: new Date(Date.UTC(2026, 9, 6, 12)) } },
    });
  });
});
