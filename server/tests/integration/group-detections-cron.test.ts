import { describe, it, expect, beforeEach, afterAll, afterEach, vi } from "vitest";
import { NextRequest } from "next/server";
import {
  cleanDatabase,
  createTestTenant,
  createTestAgent,
  createTestDetection,
  prisma,
} from "../helpers/db";
import { GROUPING_BATCH_SIZE } from "@/lib/case-grouping";
import { GET } from "@/app/api/cron/group-detections/route";
// The route imports its own `prisma` singleton from "@/lib/prisma" — a
// different PrismaClient instance than the one `../helpers/db` constructs
// for test setup/assertions (review, Jihair54: spying on the wrong instance
// meant the mock below was never actually hit). Aliased so it's obvious at
// each call site which one a given line means.
import { prisma as routePrisma } from "@/lib/prisma";

function cronRequest() {
  return new NextRequest("http://localhost/api/cron/group-detections", {
    headers: { Authorization: `Bearer ${process.env.CRON_SECRET}` },
  });
}

describe("GET /api/cron/group-detections", () => {
  beforeEach(async () => {
    await cleanDatabase();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  afterAll(async () => {
    await cleanDatabase();
    await prisma.$disconnect();
  });

  it("attaches related detections from the same agent to one case", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    const t0 = new Date();
    await createTestDetection(tenant.id, agent.id, {
      technique: "T1059.001",
      timestamp: t0,
    });
    await createTestDetection(tenant.id, agent.id, {
      technique: "T1059.003",
      timestamp: new Date(t0.getTime() + 5 * 60 * 1000),
    });

    const res = await GET(cronRequest());
    const body = await res.json();

    expect(body.casesCreated).toBe(1);
    expect(body.detectionsGrouped).toBe(2);

    const cases = await prisma.case.findMany({ where: { tenantId: tenant.id } });
    expect(cases).toHaveLength(1);
    const grouped = await prisma.detection.findMany({ where: { tenantId: tenant.id } });
    expect(grouped.every((d) => d.caseId === cases[0].id)).toBe(true);
  });

  it("creates separate cases for unrelated techniques", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    const t0 = new Date();
    await createTestDetection(tenant.id, agent.id, { technique: "T1059.001", timestamp: t0 });
    await createTestDetection(tenant.id, agent.id, { technique: "T1105", timestamp: t0 });

    const res = await GET(cronRequest());
    const body = await res.json();

    expect(body.casesCreated).toBe(2);
  });

  it("does not group detections from different agents", async () => {
    const tenant = await createTestTenant();
    const agentA = await createTestAgent(tenant.id, "agent-a");
    const agentB = await createTestAgent(tenant.id, "agent-b");
    const t0 = new Date();
    await createTestDetection(tenant.id, agentA.id, { technique: "T1059.001", timestamp: t0 });
    await createTestDetection(tenant.id, agentB.id, { technique: "T1059.001", timestamp: t0 });

    const res = await GET(cronRequest());
    const body = await res.json();

    expect(body.casesCreated).toBe(2);
  });

  it("bumps the case severity to the worst evidence it contains", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    const t0 = new Date();
    await createTestDetection(tenant.id, agent.id, {
      technique: "T1059.001",
      severity: "medium",
      timestamp: t0,
    });
    await createTestDetection(tenant.id, agent.id, {
      technique: "T1059.001",
      severity: "critical",
      timestamp: new Date(t0.getTime() + 60_000),
    });

    await GET(cronRequest());

    const cases = await prisma.case.findMany({ where: { tenantId: tenant.id } });
    expect(cases[0].severity).toBe("critical");
  });

  it("does not let the grouping window drift past the case's first detection", async () => {
    // Regression test: matching used to be evaluated against whichever
    // detection was added to the case most recently, letting a chain of
    // detections each 20 minutes apart merge into one case spanning far
    // more than the 30 minute window. The window must be anchored to the
    // case's earliest detection instead.
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    const t0 = new Date();
    const STEP_MS = 20 * 60 * 1000;
    for (let i = 0; i < 4; i++) {
      await createTestDetection(tenant.id, agent.id, {
        technique: "T1059.001",
        timestamp: new Date(t0.getTime() + i * STEP_MS),
      });
    }

    const res = await GET(cronRequest());
    const body = await res.json();

    // t0, t0+20m join case 1 (both within 30m of t0). t0+40m is 40m from
    // t0 -> starts case 2; t0+60m is 20m from case 2's start -> joins it.
    expect(body.casesCreated).toBe(2);
    const cases = await prisma.case.findMany({
      where: { tenantId: tenant.id },
      include: { detections: true },
      orderBy: { createdAt: "asc" },
    });
    expect(cases).toHaveLength(2);
    expect(cases[0].detections).toHaveLength(2);
    expect(cases[1].detections).toHaveLength(2);
  });

  it("does not double-group detections under concurrent invocations", async () => {
    // Regression test: without a lock serializing the sweep, two overlapping
    // invocations (retry, duplicated trigger) could each independently
    // group the same ungrouped detections into their own separate case.
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    const t0 = new Date();
    await createTestDetection(tenant.id, agent.id, { technique: "T1059.001", timestamp: t0 });
    await createTestDetection(tenant.id, agent.id, {
      technique: "T1059.003",
      timestamp: new Date(t0.getTime() + 5 * 60 * 1000),
    });

    const [res1, res2] = await Promise.all([GET(cronRequest()), GET(cronRequest())]);
    const [body1, body2] = await Promise.all([res1.json(), res2.json()]);

    const cases = await prisma.case.findMany({ where: { tenantId: tenant.id } });
    expect(cases).toHaveLength(1);

    const totalGrouped = (body1.detectionsGrouped ?? 0) + (body2.detectionsGrouped ?? 0);
    expect(totalGrouped).toBe(2);

    const grouped = await prisma.detection.findMany({ where: { tenantId: tenant.id } });
    expect(grouped.every((d) => d.caseId === cases[0].id)).toBe(true);
  });

  it("is idempotent across repeated runs", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    await createTestDetection(tenant.id, agent.id, { technique: "T1059.001" });

    await GET(cronRequest());
    const secondRun = await GET(cronRequest());
    const body = await secondRun.json();

    expect(body.detectionsGrouped).toBe(0);
    const cases = await prisma.case.findMany({ where: { tenantId: tenant.id } });
    expect(cases).toHaveLength(1);
  });

  it("drains a backlog larger than one batch over successive ticks instead of stalling", async () => {
    // Regression (review, Jihair54/Sollykhan): before batching, a backlog
    // larger than the transaction could handle in 30s never made progress —
    // every retry redid the same doomed work. GROUPING_BATCH_SIZE + 50 forces
    // this run to actually span two ticks.
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    const total = GROUPING_BATCH_SIZE + 50;
    const t0 = new Date();
    await prisma.detection.createMany({
      data: Array.from({ length: total }, (_, i) => ({
        tenantId: tenant.id,
        agentId: agent.id,
        technique: "T1059.001",
        severity: "high",
        timestamp: new Date(t0.getTime() + i * 1000),
        event: { test: "data" },
        meta: { test: "meta" },
      })),
    });

    const first = await (await GET(cronRequest())).json();
    expect(first.detectionsGrouped).toBe(GROUPING_BATCH_SIZE);
    expect(first.moreWorkLikely).toBe(true);

    const stillUngrouped = await prisma.detection.count({
      where: { tenantId: tenant.id, caseId: null },
    });
    expect(stillUngrouped).toBe(50);

    const second = await (await GET(cronRequest())).json();
    expect(second.detectionsGrouped).toBe(50);
    expect(second.moreWorkLikely).toBe(false);

    const cases = await prisma.case.findMany({ where: { tenantId: tenant.id } });
    expect(cases).toHaveLength(1);
    const grouped = await prisma.detection.findMany({ where: { tenantId: tenant.id } });
    expect(grouped.every((d) => d.caseId === cases[0].id)).toBe(true);
  });

  it("caps and drains each tenant independently of how many other tenants exist", async () => {
    // Regression, turned multi-tenant per review (Jihair54): the previous fix
    // capped each tenant's read at GROUPING_BATCH_SIZE, but ran every tenant
    // inside ONE shared transaction — so the real per-invocation budget was
    // `tenants × GROUPING_BATCH_SIZE`, not GROUPING_BATCH_SIZE, and enough
    // tenants could still blow the transaction timeout and roll back
    // everyone, including tenants with a tiny backlog. Two tenants, each with
    // a backlog larger than one batch, must each independently cap at
    // GROUPING_BATCH_SIZE per tick and drain over the same number of ticks a
    // single tenant would need — neither tenant's batch size depends on how
    // many other tenants exist.
    const tenantA = await createTestTenant();
    const tenantB = await createTestTenant();
    const agentA = await createTestAgent(tenantA.id);
    const agentB = await createTestAgent(tenantB.id);
    const total = GROUPING_BATCH_SIZE + 50;
    const t0 = new Date();

    for (const [tenant, agent] of [
      [tenantA, agentA],
      [tenantB, agentB],
    ] as const) {
      await prisma.detection.createMany({
        data: Array.from({ length: total }, (_, i) => ({
          tenantId: tenant.id,
          agentId: agent.id,
          technique: "T1059.001",
          severity: "high",
          timestamp: new Date(t0.getTime() + i * 1000),
          event: { test: "data" },
          meta: { test: "meta" },
        })),
      });
    }

    const first = await (await GET(cronRequest())).json();
    expect(first.detectionsGrouped).toBe(GROUPING_BATCH_SIZE * 2);
    expect(first.moreWorkLikely).toBe(true);

    const ungroupedA = await prisma.detection.count({
      where: { tenantId: tenantA.id, caseId: null },
    });
    const ungroupedB = await prisma.detection.count({
      where: { tenantId: tenantB.id, caseId: null },
    });
    expect(ungroupedA).toBe(50);
    expect(ungroupedB).toBe(50);

    const second = await (await GET(cronRequest())).json();
    expect(second.detectionsGrouped).toBe(100);
    expect(second.moreWorkLikely).toBe(false);
  });

  it("continues to the remaining tenants when one tenant's transaction throws", async () => {
    // Regression (review, Jihair54): a per-tenant transaction fixes
    // cross-TICK isolation, but without a try/catch around each one, a
    // single tenant's transaction throwing (a real timeout, a serialization
    // failure) would still abort the whole loop and skip every tenant after
    // it in THIS SAME invocation — the same "one slow tenant blocks
    // everyone" failure mode, just narrowed from every tick to the rest of
    // this one.
    const tenantA = await createTestTenant();
    const tenantB = await createTestTenant();
    const agentA = await createTestAgent(tenantA.id);
    const agentB = await createTestAgent(tenantB.id);
    await createTestDetection(tenantA.id, agentA.id, { technique: "T1059.001" });
    await createTestDetection(tenantB.id, agentB.id, { technique: "T1059.001" });

    const realTransaction = routePrisma.$transaction.bind(routePrisma);
    vi.spyOn(routePrisma, "$transaction")
      .mockImplementationOnce(() => {
        throw new Error("simulated transaction failure (e.g. a real timeout)");
      })
      // Every call after the first (one-time) override goes through untouched.
      .mockImplementation(realTransaction as typeof routePrisma.$transaction);

    const res = await GET(cronRequest());
    const body = await res.json();

    // One of two tenants failed: a partial failure, not a total outage —
    // 207, not 200 (a caller checking only for 2xx must still see this).
    expect(res.status).toBe(207);
    expect(body.tenantsChecked).toBe(2);
    expect(body.tenantsFailed).toBe(1);

    const groupedA = await prisma.detection.count({
      where: { tenantId: tenantA.id, caseId: { not: null } },
    });
    const groupedB = await prisma.detection.count({
      where: { tenantId: tenantB.id, caseId: { not: null } },
    });
    // Exactly one tenant's detection got grouped: the other tenant's
    // transaction threw and was caught, but the loop still reached and
    // completed the remaining tenant instead of aborting the whole request.
    expect(groupedA + groupedB).toBe(1);
  });

  it("answers a non-2xx when every tenant fails, instead of a silent 200", async () => {
    // Regression (review, Jihair54): the lock-cast bug made every tenant's
    // transaction throw on every tick, and this route still answered 200
    // with detectionsGrouped: 0 -- indistinguishable from "nothing to do",
    // so nothing a scheduler or monitor would ever notice. A total failure
    // must surface as a non-2xx.
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    await createTestDetection(tenant.id, agent.id, { technique: "T1059.001" });

    vi.spyOn(routePrisma, "$transaction").mockImplementation(() => {
      throw new Error("simulated total outage (e.g. the lock-cast bug)");
    });

    const res = await GET(cronRequest());
    const body = await res.json();

    expect(res.status).toBe(502);
    expect(body.tenantsChecked).toBe(1);
    expect(body.tenantsFailed).toBe(1);
    expect(body.detectionsGrouped).toBe(0);

    const grouped = await prisma.detection.count({
      where: { tenantId: tenant.id, caseId: { not: null } },
    });
    expect(grouped).toBe(0);
  });

  it("rejects the call when CRON_SECRET is unset", async () => {
    const saved = process.env.CRON_SECRET;
    delete process.env.CRON_SECRET;
    try {
      const res = await GET(cronRequest());
      expect(res.status).toBe(500);
    } finally {
      process.env.CRON_SECRET = saved;
    }
  });
});
