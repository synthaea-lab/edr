import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { randomUUID } from "node:crypto";
import { NextRequest } from "next/server";
import { renderToStaticMarkup } from "react-dom/server";
import { cleanDatabase, createTestTenant, prisma } from "../helpers/db";
import { POST as halt } from "@/app/api/content/halt/route";
import { POST as rollback } from "@/app/api/content/rollback/route";

(globalThis as { React?: typeof React }).React = React;

let activeOrganizationId: string | null = null;
let userId = "u";
vi.mock("@/lib/auth", () => ({
  auth: { api: { getSession: async () => ({ session: { activeOrganizationId }, user: { id: userId } }) } },
}));
vi.mock("next/headers", () => ({ headers: async () => new Headers({ cookie: "a=b" }) }));
vi.mock("next/navigation", () => ({
  redirect: (to: string) => {
    throw new Error(`redirect ${to}`);
  },
  useRouter: () => ({ refresh() {} }),
}));

const renderOps = async () => {
  const mod = await import("@/app/console/ops/page");
  return renderToStaticMarkup(await mod.default());
};

async function actor(role: string) {
  const user = await prisma.user.create({ data: { id: randomUUID(), email: `${randomUUID()}@example.com`, name: "U" } });
  const tenant = await createTestTenant(undefined, { userId: user.id });
  await prisma.member.updateMany({ where: { organizationId: tenant.id, userId: user.id }, data: { role } });
  activeOrganizationId = tenant.id;
  userId = user.id;
  return { tenantId: tenant.id, userId: user.id };
}

const release = (tenantId: string, ring: string, releaseVersion: number, status: string) =>
  prisma.contentRelease.create({
    data: { tenantId, ring, releaseVersion, manifestUrl: `m/${ring}/${releaseVersion}`, manifestSha256: "0".repeat(64), status, releasedAt: new Date() },
  });

const post = (url: string, tenantId: string, uid: string, body: unknown) =>
  new NextRequest(`http://localhost${url}`, {
    method: "POST",
    headers: { "x-tenant-id": tenantId, "x-user-id": uid, "content-type": "application/json" },
    body: JSON.stringify(body),
  });

describe("ring controls on /console/ops (#898)", () => {
  beforeEach(cleanDatabase);
  afterAll(async () => {
    await cleanDatabase();
    await prisma.$disconnect();
  });

  it("an admin sees halt and roll back on a serving ring, only roll back on a halted one, nothing on the others", async () => {
    const { tenantId } = await actor("admin");
    await release(tenantId, "canary_0", 1, "rolled_back");
    await release(tenantId, "canary_1", 1, "active");
    await release(tenantId, "canary_2", 1, "halted");
    // `prod` has no release.
    const html = await renderOps();
    const buttons = (ring: string) => {
      // each ring card is introduced by its name; read until the next card
      const start = html.indexOf(`>${ring}<`);
      const next = ["canary_0", "canary_1", "canary_2", "prod"].map((r) => html.indexOf(`>${r}<`, start + 1)).filter((i) => i > start);
      const end = next.length ? Math.min(...next) : html.length;
      const card = html.slice(start, end);
      return { halt: card.includes("Halt…"), rollback: card.includes("Roll back…") };
    };
    expect(buttons("canary_0")).toEqual({ halt: false, rollback: false });
    expect(buttons("canary_1")).toEqual({ halt: true, rollback: true });
    expect(buttons("canary_2")).toEqual({ halt: false, rollback: true });
    expect(buttons("prod")).toEqual({ halt: false, rollback: false });
    expect(html).not.toContain("Only an organization owner or admin");
  });

  it("an owner sees the controls too; a plain member sees the state and is told who can act", async () => {
    const { tenantId } = await actor("owner");
    await release(tenantId, "prod", 1, "active");
    expect(await renderOps()).toContain("Halt…");

    const member = await actor("member");
    await release(member.tenantId, "prod", 1, "active");
    const html = await renderOps();
    expect(html).toContain("v1");
    expect(html).not.toContain("Halt…");
    expect(html).not.toContain("Roll back…");
    expect(html).toContain("Only an organization owner or admin can halt or roll back a ring.");
  });

  it("the routes the buttons call refuse a plain member and change nothing", async () => {
    const m = await actor("member");
    const rel = await release(m.tenantId, "prod", 1, "active");
    expect((await halt(post("/api/content/halt", m.tenantId, m.userId, { ring: "prod" }))).status).toBe(403);
    expect((await rollback(post("/api/content/rollback", m.tenantId, m.userId, { ring: "prod" }))).status).toBe(403);
    expect((await prisma.contentRelease.findUniqueOrThrow({ where: { id: rel.id } })).status).toBe("active");
    expect(await prisma.auditLog.count({ where: { action: { startsWith: "content.release" } } })).toBe(0);
  });

  it("a halt by an admin halts the ring and writes the audit row with the reason and the actor", async () => {
    const a = await actor("admin");
    await release(a.tenantId, "prod", 1, "active");
    const res = await halt(post("/api/content/halt", a.tenantId, a.userId, { ring: "prod", reason: "bad rule in v1" }));
    expect(res.status).toBe(200);
    expect((await prisma.contentRelease.findFirstOrThrow({ where: { ring: "prod" } })).status).toBe("halted");
    const audit = await prisma.auditLog.findFirstOrThrow({ where: { action: "content.release.halt" } });
    expect(audit.userId).toBe(a.userId);
    expect(audit.details).toMatchObject({ ring: "prod", releaseVersion: 1, reason: "bad rule in v1" });
  });

  it("a rollback of a halted ring works, names the corrective release, and is audited", async () => {
    const a = await actor("admin");
    await release(a.tenantId, "prod", 1, "active");
    await release(a.tenantId, "prod", 2, "halted");
    const res = await rollback(post("/api/content/rollback", a.tenantId, a.userId, { ring: "prod", reason: "back to v1" }));
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.status).toBe("rolled_back");
    expect(body.correctiveRelease).toMatchObject({ releaseVersion: 3, restoreVersion: 1 });
    expect(body.correctiveRelease.note).toContain("never goes to a lower release number");
    const audit = await prisma.auditLog.findFirstOrThrow({ where: { action: "content.release.rollback" } });
    expect(audit.userId).toBe(a.userId);
    expect(audit.details).toMatchObject({ ring: "prod", fromVersion: 2, toVersion: 1, reason: "back to v1" });
  });

  it("a rollback with no earlier release answers 404 and changes nothing", async () => {
    const a = await actor("admin");
    const rel = await release(a.tenantId, "prod", 1, "active");
    const res = await rollback(post("/api/content/rollback", a.tenantId, a.userId, { ring: "prod" }));
    expect(res.status).toBe(404);
    expect((await prisma.contentRelease.findUniqueOrThrow({ where: { id: rel.id } })).status).toBe("active");
  });
});
