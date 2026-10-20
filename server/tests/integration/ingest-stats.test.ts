import { beforeEach, afterAll, describe, expect, it } from "vitest";
import { cleanDatabase, createTestAgent, createTestTenant, prisma } from "../helpers/db";
import {
  acceptedOutcome,
  loadIngestHealth,
  pruneIngestStats,
  recordIngest,
  refusedOutcome,
} from "@/lib/ingest-stats";

/** A lag of `maxMs` over `count` events (all at the max, for a simple sum). */
const lag = (maxMs: number, count: number) => ({ sumMs: maxMs * count, count, maxMs });
const at = (h: number, m = 0) => new Date(Date.UTC(2026, 9, 20, h, m));

describe("ingest stats (real database)", () => {
  beforeEach(async () => {
    await cleanDatabase();
  });
  afterAll(async () => {
    await prisma.$disconnect();
  });

  it("accumulates one row per agent, kind and hour", async () => {
    const t = await createTestTenant();
    const a = await createTestAgent(t.id);
    await recordIngest(prisma, t.id, a.id, "events", acceptedOutcome(10, 2, lag(3000, 2)), at(12, 5));
    await recordIngest(prisma, t.id, a.id, "events", acceptedOutcome(5, 0, lag(8000, 1)), at(12, 40));
    await recordIngest(prisma, t.id, a.id, "events", refusedOutcome(413, 2000), at(12, 50));
    await recordIngest(prisma, t.id, a.id, "events", acceptedOutcome(1, 0, lag(100, 1)), at(13, 1));

    const rows = await prisma.ingestStat.findMany({ orderBy: { bucket: "asc" } });
    expect(rows).toHaveLength(2);
    expect(rows[0]).toMatchObject({
      received: 2015, accepted: 13, skipped: 2, refused4xx: 1, refused5xx: 0,
      lagSumMs: BigInt(14000), lagCount: 3, lagMaxMs: BigInt(8000), lastAcceptedAt: at(12, 40),
    });
    expect(rows[1]).toMatchObject({ received: 1, accepted: 1, lagMaxMs: BigInt(100) });
  });

  it("keeps the latest acceptance when a late request arrives out of order", async () => {
    const t = await createTestTenant();
    const a = await createTestAgent(t.id);
    await recordIngest(prisma, t.id, a.id, "detection", acceptedOutcome(1, 0, null), at(12, 50));
    await recordIngest(prisma, t.id, a.id, "detection", acceptedOutcome(1, 0, null), at(12, 10));
    expect((await prisma.ingestStat.findFirstOrThrow()).lastAcceptedAt).toEqual(at(12, 50));
  });

  it("shows a refused batch and skipped entries for that agent, not for its neighbour", async () => {
    const t = await createTestTenant();
    const a = await createTestAgent(t.id);
    const b = await createTestAgent(t.id);
    await recordIngest(prisma, t.id, a.id, "events", acceptedOutcome(4, 1, lag(2000, 1)), at(12, 10));
    await recordIngest(prisma, t.id, a.id, "events", refusedOutcome(400), at(12, 20));
    await recordIngest(prisma, t.id, a.id, "events", refusedOutcome(500), at(12, 21));
    await recordIngest(prisma, t.id, b.id, "events", acceptedOutcome(4, 0, lag(10, 1)), at(12, 10));

    const h = await loadIngestHealth(prisma, t.id, at(12, 30));
    expect(h.get(a.id)).toMatchObject({ refused4xx: 1, refused5xx: 1, skipped: 1, lagMeanMs: 2000, lagMaxMs: 2000 });
    expect(h.get(b.id)).toMatchObject({ refused4xx: 0, refused5xx: 0, skipped: 0, lagMeanMs: 10, lagMaxMs: 10 });
  });

  it("makes an agent whose events stopped while its beacons continue visible", async () => {
    const t = await createTestTenant();
    const a = await createTestAgent(t.id);
    await recordIngest(prisma, t.id, a.id, "events", acceptedOutcome(3, 0, lag(0, 1)), at(8, 0));
    await recordIngest(prisma, t.id, a.id, "beacon", acceptedOutcome(1, 0, null), at(12, 25));

    const last = (await loadIngestHealth(prisma, t.id, at(12, 30))).get(a.id)?.lastAccepted;
    expect(last?.events).toEqual(at(8, 0).toISOString());
    expect(last?.beacon).toEqual(at(12, 25).toISOString());
    expect(last?.detection).toBeNull();
  });

  it("counts refusals only over the window, but keeps the last acceptance beyond it", async () => {
    const t = await createTestTenant();
    const a = await createTestAgent(t.id);
    await recordIngest(prisma, t.id, a.id, "events", refusedOutcome(400), at(8, 0));
    await recordIngest(prisma, t.id, a.id, "events", acceptedOutcome(1, 0, lag(0, 1)), at(8, 5));
    const h = (await loadIngestHealth(prisma, t.id, at(12, 30))).get(a.id);
    expect(h?.refused4xx).toBe(0);
    expect(h?.lastAccepted.events).toEqual(at(8, 5).toISOString());
  });

  it("holds a lag of weeks, as an agent reconnecting after an outage uploads", async () => {
    const t = await createTestTenant();
    const a = await createTestAgent(t.id);
    const month = 30 * 24 * 60 * 60 * 1000;
    await recordIngest(prisma, t.id, a.id, "events", acceptedOutcome(2, 0, lag(month, 2)), at(12, 10));
    const h = (await loadIngestHealth(prisma, t.id, at(12, 30))).get(a.id);
    expect(h).toMatchObject({ lagMeanMs: month, lagMaxMs: month });
  });

  it("keeps tenants apart", async () => {
    const t1 = await createTestTenant();
    const t2 = await createTestTenant();
    const a = await createTestAgent(t1.id);
    await recordIngest(prisma, t1.id, a.id, "events", refusedOutcome(400), at(12, 10));
    expect((await loadIngestHealth(prisma, t2.id, at(12, 30))).size).toBe(0);
  });

  it("prunes old buckets and nothing else", async () => {
    const t = await createTestTenant();
    const a = await createTestAgent(t.id);
    await recordIngest(prisma, t.id, a.id, "events", acceptedOutcome(1, 0, lag(0, 1)), new Date(Date.UTC(2026, 8, 1, 12)));
    await recordIngest(prisma, t.id, a.id, "events", acceptedOutcome(1, 0, lag(0, 1)), at(12));
    expect(await pruneIngestStats(prisma, at(12), 14)).toBe(1);
    expect(await prisma.ingestStat.count()).toBe(1);
  });
});
