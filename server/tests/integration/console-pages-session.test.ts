import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { cleanDatabase, createTestAgent, createTestTenant, prisma } from "../helpers/db";

// Every console page reads its tenant from the session. Like the real one, `getSession` refuses a
// call without the request's headers; the pages called it bare, so once a user could sign in
// every console page answered 500 "Headers is required" (#810).
// Vitest compiles the pages with the classic JSX transform, which needs `React` in scope.
(globalThis as { React?: typeof React }).React = React;

let activeOrganizationId: string | null = null;
vi.mock("@/lib/auth", () => ({
  auth: {
    api: {
      getSession: async (opts?: { headers?: Headers }) => {
        if (!opts?.headers) throw new Error("APIError: Headers is required");
        return { session: { activeOrganizationId }, user: { id: "u" } };
      },
    },
  },
}));
vi.mock("next/headers", () => ({ headers: async () => new Headers({ cookie: "a=b" }) }));
vi.mock("@/components/GenerateNarrativeButton", () => ({ GenerateNarrativeButton: () => null }));
vi.mock("@/components/RunHuntButton", () => ({ RunHuntButton: () => null }));
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: () => undefined, refresh: () => undefined }),
  redirect: (to: string) => {
    throw new Error(`redirect ${to}`);
  },
  notFound: () => {
    throw new Error("not found");
  },
}));

async function render(page: string, props: unknown = {}): Promise<string> {
  const mod = await import(/* @vite-ignore */ `@/app/console/${page}`);
  return renderToStaticMarkup(await mod.default(props));
}

describe("console pages read the session with the request's headers (real database)", () => {
  beforeEach(async () => {
    await cleanDatabase();
  });
  afterAll(async () => {
    await prisma.$disconnect();
  });

  it("renders the case list, the fleet page and a case for a tenant's session", async () => {
    const tenant = await createTestTenant();
    const case_ = await prisma.case.create({
      data: { tenantId: tenant.id, title: "T1059 activity", severity: "high", status: "open" },
    });
    activeOrganizationId = tenant.id;

    expect(await render("cases/page")).toContain("T1059 activity");
    expect(await render("ops/page")).toContain("No agents enrolled yet.");
    expect(await render("cases/[id]/page", { params: { id: case_.id } })).toContain("T1059 activity");
  });

  it("shows a host that lost telemetry recently as degraded, with the reason, on the ops page (#83)", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id, "agent-ops-loss", { hostname: "lossy-host", lastSeen: new Date() });
    await prisma.agentHealth.create({
      data: {
        agentId: agent.id,
        tenantId: tenant.id,
        beaconAt: new Date(),
        receivedAt: new Date(),
        agentVersion: "0.1.0",
        spoolBytes: BigInt(0),
        spoolDropped: BigInt(4096),
        enrichDropped: BigInt(7560),
        lossObservedAt: new Date(Date.now() - 60_000),
        sensors: [{ name: "linux-ebpf", pulse_count: 3, silent: false }],
      },
    });
    activeOrganizationId = tenant.id;

    const html = await render("ops/page");

    expect(html).toContain("lossy-host");
    expect(html).toContain("Degraded");
    expect(html).toMatch(/lost telemetry in the last 10 min/i);
  });

  it("shows the watchdog restarts, tamper events and parent-image evictions of a host on the ops page (#863)", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id, "agent-ops-self", { hostname: "selfprotect-host", lastSeen: new Date() });
    await prisma.agentHealth.create({
      data: {
        agentId: agent.id,
        tenantId: tenant.id,
        beaconAt: new Date(),
        receivedAt: new Date(),
        agentVersion: "0.1.0",
        spoolBytes: BigInt(0),
        spoolDropped: BigInt(0),
        enrichDropped: BigInt(0),
        watchdogRestarts: BigInt(3),
        tamperEvents: BigInt(5),
        parentImageEvictedLive: BigInt(13),
        parentImageEvictedDead: BigInt(209000),
        sensors: [{ name: "linux-ebpf", pulse_count: 3, silent: false }],
      },
    });
    activeOrganizationId = tenant.id;

    const html = await render("ops/page");

    expect(html).toContain("selfprotect-host");
    expect(html).toMatch(/Watchdog restarts/);
    expect(html).toMatch(/Tamper events/);
    expect(html).toMatch(/Parent images evicted/);
    expect(html).toMatch(/<td[^>]*>3<\/td>/);
    expect(html).toMatch(/<td[^>]*>5<\/td>/);
    expect(html).toContain("13 live, 209000 exited");
  });

  it("tells a session without an organization to contact the administrator, on every page", async () => {
    activeOrganizationId = null;
    for (const [page, props] of [
      ["cases/page", {}],
      ["ops/page", {}],
      ["hunts/page", {}],
      ["hunts/[id]/page", { params: { id: "x" } }],
      ["hunts/new/page", {}],
      ["hunts/[id]/edit/page", { params: { id: "x" } }],
      ["cases/[id]/page", { params: { id: "x" } }],
    ] as const) {
      expect(await render(page, props), page).toContain("No organization selected");
    }
  });

  describe("hunts (#61)", () => {
    const query = { version: 1, lastHours: 168, techniques: ["T1059"], severities: ["high"] };
    const minutesAgo = (m: number) => new Date(Date.now() - m * 60_000);

    async function hunt(tenantId: string, name: string, extra: Record<string, unknown> = {}) {
      return prisma.hunt.create({ data: { tenantId, ownerId: "analyst-1", name, query, ...extra } });
    }
    const run = (h: { id: string; tenantId: string }, extra: Record<string, unknown>) =>
      prisma.huntRun.create({
        data: {
          huntId: h.id, tenantId: h.tenantId, queryVersion: 1, query, sampleDetectionIds: [], trigger: "manual", ...extra,
        },
      });

    it("lists a tenant's hunts with their query, schedule and last result, and never another tenant's", async () => {
      const mine = await createTestTenant();
      const other = await createTestTenant();
      const done = await hunt(mine.id, "PowerShell from Office", { scheduleMinutes: 60 });
      await run(done, { startedAt: minutesAgo(5), finishedAt: minutesAgo(5), matchCount: 7, newMatchCount: 2 });
      await hunt(mine.id, "never ran");
      await hunt(other.id, "someone else's hunt");
      activeOrganizationId = mine.id;

      const html = await render("hunts/page");

      expect(html).toContain("PowerShell from Office");
      expect(html).toContain("last 7 d · T1059 · high");
      expect(html).toContain("every 1 h");
      expect(html).toContain("Done");
      expect(html).toMatch(/<td[^>]*>7<\/td>/);
      expect(html).toMatch(/<td[^>]*>2<\/td>/);
      expect(html).toContain("never ran");
      expect(html).toContain("Never run");
      expect(html).not.toContain("someone else's hunt");
    });

    it("shows a run in flight as running and keeps the numbers of the run before it, a failed one as failed", async () => {
      const tenant = await createTestTenant();
      const going = await hunt(tenant.id, "going");
      await run(going, { startedAt: minutesAgo(30), finishedAt: minutesAgo(30), matchCount: 11, newMatchCount: 4 });
      await run(going, { startedAt: new Date(), finishedAt: null });
      const broken = await hunt(tenant.id, "broken");
      await run(broken, {
        startedAt: minutesAgo(1), finishedAt: minutesAgo(1), error: "the search exceeded its time limit and was cancelled",
      });
      activeOrganizationId = tenant.id;

      const html = await render("hunts/page");

      expect(html).toContain("Running");
      expect(html).toMatch(/<td[^>]*>11<span[^>]*>from /);
      expect(html).toContain("Failed");
    });

    it("shows a hunt's history: results, a failed run with its message, a run that never finished", async () => {
      const tenant = await createTestTenant();
      const h = await hunt(tenant.id, "history", { description: "watching Office children", scheduleMinutes: 30 });
      await run(h, { startedAt: minutesAgo(90), finishedAt: minutesAgo(90), matchCount: 5, newMatchCount: 5, trigger: "schedule" });
      await run(h, {
        startedAt: minutesAgo(60), finishedAt: minutesAgo(60), error: "the search exceeded its time limit and was cancelled",
      });
      await run(h, { startedAt: minutesAgo(10), finishedAt: null });
      activeOrganizationId = tenant.id;

      const html = await render("hunts/[id]/page", { params: { id: h.id } });

      expect(html).toContain("history");
      expect(html).toContain("watching Office children");
      expect(html).toContain("every 30 min");
      expect(html).toContain("schedule");
      expect(html).toContain("Failed");
      expect(html).toContain("the search exceeded its time limit and was cancelled");
      expect(html).toContain("Did not finish");
      expect(html).toMatch(/<td[^>]*>5<\/td>/);
    });

    it("offers to draft a Sigma rule from the hunt, for each platform", async () => {
      const tenant = await createTestTenant();
      const h = await hunt(tenant.id, "graduating");
      activeOrganizationId = tenant.id;

      const html = await render("hunts/[id]/page", { params: { id: h.id } });

      expect(html).toContain("Draft Sigma rule");
      for (const platform of ["linux", "windows", "macos"]) expect(html).toContain(`value="${platform}"`);
    });

    it("answers not found for another tenant's hunt, without any of its contents", async () => {
      const mine = await createTestTenant();
      const other = await createTestTenant();
      const theirs = await hunt(other.id, "secret hunt name");
      activeOrganizationId = mine.id;

      await expect(render("hunts/[id]/page", { params: { id: theirs.id } })).rejects.toThrow("not found");
    });

    it("shows the numbers of the newest run that has a result, and says which run they are from", async () => {
      const tenant = await createTestTenant();
      const h = await hunt(tenant.id, "two failures after a result");
      await run(h, { startedAt: minutesAgo(180), finishedAt: minutesAgo(180), matchCount: 42, newMatchCount: 9 });
      await run(h, { startedAt: minutesAgo(120), finishedAt: minutesAgo(120), error: "the search exceeded its time limit" });
      await run(h, { startedAt: minutesAgo(60), finishedAt: minutesAgo(60), error: "the search exceeded its time limit" });
      const current = await hunt(tenant.id, "current result");
      await run(current, { startedAt: minutesAgo(5), finishedAt: minutesAgo(5), matchCount: 3, newMatchCount: 1 });
      activeOrganizationId = tenant.id;

      const html = await render("hunts/page");

      expect(html).toMatch(/<td[^>]*>42<span[^>]*>from /);
      expect(html).toMatch(/<td[^>]*>9<\/td>/);
      expect(html).toMatch(/<td[^>]*>3<\/td>/);
      expect(html.match(/from \d{4}-/g)).toHaveLength(1);
    });

    describe("the create and edit pages", () => {
      it("renders an empty form on the new page", async () => {
        const tenant = await createTestTenant();
        activeOrganizationId = tenant.id;
        const html = await render("hunts/new/page");
        expect(html).toContain("hunt-name");
        expect(html).not.toContain("no longer parses");
      });

      it("fills the edit form with the hunt's name and query", async () => {
        const tenant = await createTestTenant();
        const h = await hunt(tenant.id, "Office children", { description: "watching Office" });
        activeOrganizationId = tenant.id;

        const html = await render("hunts/[id]/edit/page", { params: { id: h.id } });

        expect(html).toContain("Office children");
        expect(html).toContain("watching Office");
        expect(html).toContain("T1059");
        expect(html).toContain('value="168"');
        expect(html).not.toContain("no longer parses");
      });

      it("answers not found for another tenant's hunt on the edit page, without its contents", async () => {
        const mine = await createTestTenant();
        const other = await createTestTenant();
        const theirs = await hunt(other.id, "secret hunt name");
        activeOrganizationId = mine.id;

        await expect(render("hunts/[id]/edit/page", { params: { id: theirs.id } })).rejects.toThrow("not found");
      });

      it("warns that saving replaces a stored query that no longer parses", async () => {
        const tenant = await createTestTenant();
        const h = await prisma.hunt.create({
          data: { tenantId: tenant.id, ownerId: "analyst-1", name: "narrow hunt", query: { version: 99, lastHours: 2 } },
        });
        activeOrganizationId = tenant.id;

        const html = await render("hunts/[id]/edit/page", { params: { id: h.id } });

        expect(html).toContain("no longer parses");
        expect(html).toContain("Saving replaces the stored query");
      });
    });

    it("escapes what an analyst typed in a hunt's name, description and text", async () => {
      const tenant = await createTestTenant();
      const h = await prisma.hunt.create({
        data: {
          tenantId: tenant.id, ownerId: "analyst-1", name: "<script>alert(1)</script>", description: "<img src=x onerror=alert(2)>",
          query: { version: 1, lastHours: 24, text: "<b>bold</b>" },
        },
      });
      activeOrganizationId = tenant.id;

      for (const html of [await render("hunts/page"), await render("hunts/[id]/page", { params: { id: h.id } })]) {
        expect(html).not.toContain("<script>alert(1)");
        expect(html).not.toContain("<img src=x");
        expect(html).not.toContain("<b>bold</b>");
        expect(html).toContain("&lt;script&gt;");
      }
    });
  });
});
