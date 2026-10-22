import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { NextRequest } from "next/server";
import { renderToStaticMarkup } from "react-dom/server";
import { cleanDatabase, createTestAgent, createTestDetection, createTestTenant, prisma } from "../helpers/db";
import { createTenantHeaders } from "../helpers/http";
import { GET as listApi } from "@/app/api/fleet-cases/route";
import { GET as detailApi } from "@/app/api/fleet-cases/[id]/route";

// Same setup as console-pages-session.test.ts: the pages read their tenant from the session.
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
vi.mock("next/navigation", () => ({
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

const SHA = "72c31946".padEnd(64, "0");
const T0 = Date.now() - 3_600_000;
const at = (m: number) => new Date(T0 + m * 60_000);

/** A fleet case over two hosts and one hash, with a detection on each host. */
async function fleetCase(tenantId: string, over: Partial<{ severity: string; hostA: string; hostB: string; key: string }> = {}) {
  const a = await createTestAgent(tenantId, undefined, { hostname: over.hostA ?? "host-a" });
  const b = await createTestAgent(tenantId, undefined, { hostname: over.hostB ?? "host-b" });
  const row = await prisma.fleetCase.create({
    data: {
      tenantId,
      severity: over.severity ?? "high",
      agentCount: 2,
      firstAt: at(0),
      lastAt: at(5),
      entities: { create: [{ tenantId, kind: "sha256", key: over.key ?? SHA }] },
    },
  });
  const hostCase = await prisma.case.create({ data: { tenantId, title: "host case", severity: "high", status: "open" } });
  await createTestDetection(tenantId, a.id, { technique: "T1059", severity: "medium", timestamp: at(0), caseId: hostCase.id });
  await createTestDetection(tenantId, b.id, { technique: "T1505.003", severity: "high", timestamp: at(5) });
  await prisma.detection.updateMany({ where: { tenantId, agentId: { in: [a.id, b.id] } }, data: { fleetCaseId: row.id } });
  return { row, a, b, hostCase };
}

const req = (url: string, tenantId: string) =>
  new NextRequest(`http://localhost${url}`, { headers: createTenantHeaders(tenantId) });

describe("fleet cases in the console and the API (#62)", () => {
  beforeEach(async () => {
    await cleanDatabase();
    activeOrganizationId = null;
  });
  afterAll(async () => {
    await cleanDatabase();
    await prisma.$disconnect();
  });

  describe("the list page", () => {
    it("says so when there are none, and tells a session with no organization to ask an administrator", async () => {
      const tenant = await createTestTenant();
      activeOrganizationId = tenant.id;
      expect(await render("fleet-cases/page")).toContain("No fleet cases yet");
      activeOrganizationId = null;
      expect(await render("fleet-cases/page")).toContain("contact your administrator");
    });

    it("lists a tenant's fleet cases with severity, status, hosts, entity and detections, and never another tenant's", async () => {
      const mine = await createTestTenant();
      const other = await createTestTenant();
      const { row } = await fleetCase(mine.id);
      await fleetCase(other.id, { key: "ff".repeat(32), hostA: "foreign-host" });
      activeOrganizationId = mine.id;

      const html = await render("fleet-cases/page");

      expect(html).toContain(`href="/console/fleet-cases/${row.id}"`);
      expect(html).toContain("high");
      expect(html).toContain("open");
      expect(html).toContain("file 72c319460000…");
      expect(html).toMatch(/<td[^>]*>2<\/td>/); // hosts, and detections
      expect(html).not.toContain("foreign-host");
      expect(html).not.toContain("ffffffffffff");
    });

    it("lists the newest-active case first", async () => {
      const tenant = await createTestTenant();
      const older = await prisma.fleetCase.create({
        data: { tenantId: tenant.id, severity: "low", agentCount: 2, firstAt: at(-600), lastAt: at(-590) },
      });
      const newer = await prisma.fleetCase.create({
        data: { tenantId: tenant.id, severity: "low", agentCount: 2, firstAt: at(-10), lastAt: at(-1) },
      });
      activeOrganizationId = tenant.id;
      const html = await render("fleet-cases/page");
      expect(html.indexOf(newer.id)).toBeGreaterThan(-1);
      expect(html.indexOf(newer.id)).toBeLessThan(html.indexOf(older.id));
    });

    it("says when the list is cut at its limit", async () => {
      const tenant = await createTestTenant();
      await prisma.fleetCase.createMany({
        data: Array.from({ length: 201 }, (_, i) => ({
          tenantId: tenant.id, severity: "low", agentCount: 2, firstAt: at(-i), lastAt: at(-i),
        })),
      });
      activeOrganizationId = tenant.id;
      const html = await render("fleet-cases/page");
      expect(html).toContain("Only the 200 most recent");
      expect(html.match(/href="\/console\/fleet-cases\//g)).toHaveLength(200);
    });
  });

  describe("the detail page", () => {
    it("shows the entities, the hosts and each detection with its host, technique and host case", async () => {
      const tenant = await createTestTenant();
      const { row, hostCase } = await fleetCase(tenant.id);
      activeOrganizationId = tenant.id;

      const html = await render("fleet-cases/[id]/page", { params: { id: row.id } });

      expect(html).toContain(SHA);
      expect(html).toContain("host-a");
      expect(html).toContain("host-b");
      expect(html).toContain("T1059");
      expect(html).toContain("T1505.003");
      expect(html).toContain(`href="/console/cases/${hostCase.id}"`);
      expect(html.indexOf("T1059")).toBeLessThan(html.indexOf("T1505.003")); // oldest first
    });

    it("escapes a hostname and an entity that carry markup", async () => {
      const tenant = await createTestTenant();
      const { row } = await fleetCase(tenant.id, { hostA: "<img src=x onerror=alert(1)>" });
      await prisma.fleetCaseEntity.create({ data: { tenantId: tenant.id, fleetCaseId: row.id, kind: "identity", key: "<b>eve</b>" } });
      activeOrganizationId = tenant.id;

      const html = await render("fleet-cases/[id]/page", { params: { id: row.id } });

      expect(html).not.toContain("<img src=x");
      expect(html).not.toContain("<b>eve</b>");
      expect(html).toContain("&lt;b&gt;eve&lt;/b&gt;");
    });

    it("answers not found for another tenant's fleet case, without any of its contents", async () => {
      const mine = await createTestTenant();
      const other = await createTestTenant();
      const { row } = await fleetCase(other.id, { hostA: "secret-host" });
      activeOrganizationId = mine.id;
      await expect(render("fleet-cases/[id]/page", { params: { id: row.id } })).rejects.toThrow("not found");
    });
  });

  describe("the API", () => {
    it("lists the tenant's fleet cases and cuts nothing off a small list", async () => {
      const mine = await createTestTenant();
      const other = await createTestTenant();
      const { row } = await fleetCase(mine.id);
      await fleetCase(other.id);
      const body = await (await listApi(req("/api/fleet-cases", mine.id))).json();
      expect(body.truncated).toBe(false);
      expect(body.cases.map((c: { id: string }) => c.id)).toEqual([row.id]);
      expect(body.cases[0]).toMatchObject({ severity: "high", status: "open", agentCount: 2, detectionCount: 2 });
      expect(body.cases[0].entities).toEqual([{ kind: "sha256", key: SHA }]);
    });

    it("returns one fleet case with its hosts and detections, 404 for another tenant's or an unknown id", async () => {
      const mine = await createTestTenant();
      const other = await createTestTenant();
      const { row } = await fleetCase(mine.id);
      const theirs = await fleetCase(other.id);

      const res = await detailApi(req(`/api/fleet-cases/${row.id}`, mine.id), { params: { id: row.id } });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.agents.map((a: { hostname: string }) => a.hostname).sort()).toEqual(["host-a", "host-b"]);
      expect(body.detections.map((d: { technique: string }) => d.technique)).toEqual(["T1059", "T1505.003"]);

      expect((await detailApi(req(`/api/fleet-cases/${theirs.row.id}`, mine.id), { params: { id: theirs.row.id } })).status).toBe(404);
      expect((await detailApi(req("/api/fleet-cases/nope", mine.id), { params: { id: "nope" } })).status).toBe(404);
    });
  });
});
