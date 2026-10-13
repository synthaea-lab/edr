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

  it("tells a session without an organization to contact the administrator, on every page", async () => {
    activeOrganizationId = null;
    for (const [page, props] of [
      ["cases/page", {}],
      ["ops/page", {}],
      ["cases/[id]/page", { params: { id: "x" } }],
    ] as const) {
      expect(await render(page, props), page).toContain("No organization selected");
    }
  });
});
