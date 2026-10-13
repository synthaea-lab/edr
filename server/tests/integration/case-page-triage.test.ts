import { beforeEach, afterAll, describe, expect, it, vi } from "vitest";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { cleanDatabase, createTestAgent, createTestTenant, prisma } from "../helpers/db";
import { extractObservations, recordObservations } from "@/lib/prevalence";

// The page is a server component: it asks better-auth for the session and renders the case with
// the fleet triage lines (issue #76). Only the session and the client-side button are replaced;
// the database, the page and `triageLines` are the real ones.
// Vitest compiles the page with the classic JSX transform, which needs `React` in scope; the
// Next build uses the automatic runtime and does not.
(globalThis as { React?: typeof React }).React = React;

let activeOrganizationId: string | null = null;
// Like the real one, `getSession` refuses a call without the request's headers (#810): the
// pages pass `await headers()`, which needs a request scope this test does not have, so
// `next/headers` is replaced too. Without that, this test failed once #811 landed.
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

const execEvent = (image: string, parent: string) => ({
  type: "exec",
  image_path: image,
  parent_image_path: parent,
  meta: { pid: 10, ppid: 1, comm: "sh", timestamp_ns: 1_791_849_600_000_000_000 },
});

async function renderCase(caseId: string): Promise<string> {
  const { default: CaseDetailPage } = await import("@/app/console/cases/[id]/page");
  return renderToStaticMarkup(await CaseDetailPage({ params: { id: caseId } }));
}

describe("case page, fleet triage lines (real database, server-rendered)", () => {
  beforeEach(async () => {
    await cleanDatabase();
  });
  afterAll(async () => {
    await prisma.$disconnect();
  });

  it("shows how many hosts ran the transition and the first-seen date under the detection", async () => {
    const tenant = await createTestTenant();
    const [a, b] = [await createTestAgent(tenant.id), await createTestAgent(tenant.id)];
    const shared = execEvent("/bin/sh", "/tmp/prevalence-shared/nginx");
    const rare = execEvent("/bin/sh", "/tmp/prevalence-only-a/nginx");
    const day = new Date(Date.UTC(2026, 9, 13));
    await recordObservations(prisma, tenant.id, a.id, day, [
      ...extractObservations(shared),
      ...extractObservations(rare),
    ]);
    await recordObservations(prisma, tenant.id, b.id, day, extractObservations(shared));
    const case_ = await prisma.case.create({
      data: { tenantId: tenant.id, title: "T1059 activity", severity: "high", status: "open" },
    });
    await prisma.detection.create({
      data: {
        tenantId: tenant.id,
        agentId: a.id,
        caseId: case_.id,
        timestamp: day,
        technique: "T1059",
        severity: "high",
        event: rare,
        meta: {},
      },
    });
    activeOrganizationId = tenant.id;

    const html = await renderCase(case_.id);

    expect(html).toContain('aria-label="Fleet prevalence"');
    expect(html).toContain("seen on 1 host, first 2026-10-13");
    expect(html).toContain("/tmp/prevalence-only-a/nginx -&gt; /bin/sh");
    // The shared transition belongs to the other host's event, not to this detection.
    expect(html).not.toContain("/tmp/prevalence-shared/nginx");
  });

  it("renders no prevalence list for a detection that touched nothing countable", async () => {
    const tenant = await createTestTenant();
    const a = await createTestAgent(tenant.id);
    const case_ = await prisma.case.create({
      data: { tenantId: tenant.id, title: "T1070 activity", severity: "high", status: "open" },
    });
    await prisma.detection.create({
      data: {
        tenantId: tenant.id,
        agentId: a.id,
        caseId: case_.id,
        timestamp: new Date(),
        technique: "T1070",
        severity: "high",
        event: { type: "file_delete", path: "/var/log/x", meta: {} },
        meta: {},
      },
    });
    activeOrganizationId = tenant.id;

    expect(await renderCase(case_.id)).not.toContain("Fleet prevalence");
  });

  it("does not render another tenant's case", async () => {
    const mine = await createTestTenant();
    const theirs = await createTestTenant();
    const case_ = await prisma.case.create({
      data: { tenantId: theirs.id, title: "secret", severity: "high", status: "open" },
    });
    activeOrganizationId = mine.id;

    await expect(renderCase(case_.id)).rejects.toThrow("not found");
  });
});
