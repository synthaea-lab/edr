import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { randomUUID } from "node:crypto";
import { renderToStaticMarkup } from "react-dom/server";
import { cleanDatabase, createTestTenant, prisma } from "../helpers/db";
import { sealSecret } from "@/lib/notify/secret";

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

const KEY = "k1:" + "11".repeat(32);
const render = async () => {
  const mod = await import("@/app/console/notifications/page");
  return renderToStaticMarkup(await mod.default());
};

async function member(role: string) {
  const user = await prisma.user.create({ data: { id: randomUUID(), email: `${randomUUID()}@example.com`, name: "U" } });
  const tenant = await createTestTenant(undefined, { userId: user.id });
  await prisma.member.updateMany({ where: { organizationId: tenant.id, userId: user.id }, data: { role } });
  activeOrganizationId = tenant.id;
  userId = user.id;
  return tenant.id;
}

async function channel(tenantId: string, over: Record<string, unknown> = {}) {
  const id = randomUUID();
  const sealed = sealSecret("whsec_x", id, { NOTIFY_SECRET_KEY: KEY })!;
  return prisma.notificationChannel.create({
    data: { id, tenantId, url: "https://hooks.example.com/very/secret/path", secretKeyId: "k1", secretSealed: sealed.sealed, events: ["host.degraded"], createdBy: "u", ...over },
  });
}

describe("console notifications page (real database)", () => {
  beforeEach(async () => {
    process.env.NOTIFY_SECRET_KEY = KEY;
    await cleanDatabase();
  });
  afterAll(async () => {
    await cleanDatabase();
    await prisma.$disconnect();
  });

  it("an admin sees the host (never the path or the secret), a paused channel's explanation, and the controls", async () => {
    const tenantId = await member("admin");
    const c = await channel(tenantId, { status: "paused", lastError: "http_status", lastStatusCode: 500 });
    await prisma.notification.create({
      data: { tenantId, channelId: c.id, event: "host.degraded", subject: "a", seq: 1, payload: {}, failedAt: new Date(), attempts: 6 },
    });
    const html = await render();
    expect(html).toContain("hooks.example.com");
    expect(html).not.toContain("very/secret/path");
    expect(html).not.toContain("secretSealed");
    expect(html).toContain("Paused after five failed deliveries");
    expect(html).toContain("http_status (HTTP 500)");
    expect(html).toContain("1 failed");
    expect(html).toContain("Send test");
    expect(html).toContain("Add a webhook");
  });

  it("a plain member sees the channels but no control", async () => {
    const tenantId = await member("member");
    await channel(tenantId);
    const html = await render();
    expect(html).toContain("hooks.example.com");
    expect(html).not.toContain("Send test");
    expect(html).not.toContain("Add a webhook");
    expect(html).toContain("Only an organization owner or admin");
  });

  it("says when the outbox is backed up, and when notifications are not configured", async () => {
    const tenantId = await member("owner");
    const c = await channel(tenantId);
    await prisma.notification.create({
      data: { tenantId, channelId: c.id, event: "host.degraded", subject: "a", seq: 1, payload: {}, createdAt: new Date(Date.now() - 20 * 60_000) },
    });
    delete process.env.NOTIFY_SECRET_KEY;
    const html = await render();
    expect(html).toContain("1 notification waiting");
    expect(html).toContain("the outbox is backed up");
    expect(html).toContain("NOTIFY_SECRET_KEY is unset");
  });

  it("shows the empty state", async () => {
    await member("owner");
    expect(await render()).toContain("No webhook registered.");
  });
});
