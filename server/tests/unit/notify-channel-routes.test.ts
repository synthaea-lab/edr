import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

const db = vi.hoisted(() => ({
  notificationChannel: { findMany: vi.fn(), findFirst: vi.fn(), count: vi.fn(), create: vi.fn(), update: vi.fn(), delete: vi.fn() },
  notification: { count: vi.fn(), updateMany: vi.fn() },
  hunt: { count: vi.fn() },
  auditLog: { create: vi.fn() },
  member: { findFirst: vi.fn() },
}));
vi.mock("@/lib/prisma", () => ({ prisma: db }));
vi.mock("@/lib/notify/guard", async (orig) => {
  const real = await orig<typeof import("@/lib/notify/guard")>();
  return { ...real, resolvePublicTarget: (url: string, o?: object) => real.resolvePublicTarget(url, { ...o, resolve: async () => ["93.184.216.34"] }) };
});

import { GET, POST } from "@/app/api/notify/channels/route";
import { PATCH, DELETE } from "@/app/api/notify/channels/[id]/route";
import { POST as testSend } from "@/app/api/notify/channels/[id]/test/route";

const KEY = "k1:" + "11".repeat(32);
const headers = { "x-tenant-id": "t1", "x-user-id": "u1", "content-type": "application/json" };
const r = (method: string, body?: unknown, h: Record<string, string> = headers) =>
  new NextRequest("http://localhost/api/notify/channels", { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) });
const ctx = { params: { id: "c1" } };
const row = { id: "c1", tenantId: "t1", kind: "webhook", url: "https://hooks.example.com/secret/path", secretKeyId: "k1", secretSealed: "xx", events: ["host.degraded"], huntIds: [], status: "active", cooldownSeconds: 1800, lastStatusCode: null, lastError: null, lastDeliveredAt: null, createdAt: new Date() };

beforeEach(() => {
  vi.clearAllMocks();
  process.env.NOTIFY_SECRET_KEY = KEY;
  db.member.findFirst.mockResolvedValue({ role: "owner" });
  db.auditLog.create.mockResolvedValue({});
  db.notificationChannel.count.mockResolvedValue(0);
  db.notificationChannel.create.mockImplementation(async ({ data }) => ({ ...row, ...data }));
  db.notificationChannel.findFirst.mockResolvedValue(row);
  db.notificationChannel.update.mockImplementation(async ({ data }) => ({ ...row, ...data }));
});

describe("notification channel routes", () => {
  it("every write refuses a plain member", async () => {
    db.member.findFirst.mockResolvedValue({ role: "member" });
    expect((await POST(r("POST", { url: "https://hooks.example.com/" }))).status).toBe(403);
    expect((await PATCH(r("PATCH", { action: "disable" }), ctx)).status).toBe(403);
    expect((await DELETE(r("DELETE"), ctx)).status).toBe(403);
    expect((await testSend(r("POST"), ctx)).status).toBe(403);
    expect(db.notificationChannel.create).not.toHaveBeenCalled();
  });

  it("a member can list, and sees the host only: no path, no secret", async () => {
    db.member.findFirst.mockResolvedValue({ role: "member" });
    db.notificationChannel.findMany.mockResolvedValue([row]);
    db.notification.count.mockResolvedValue(3);
    const res = await GET(r("GET"));
    const text = JSON.stringify(await res.json());
    expect(res.status).toBe(200);
    expect(text).toContain("hooks.example.com");
    expect(text).not.toContain("/secret/path");
    expect(text).not.toContain("secretSealed");
    expect(text).toContain('"backlog":3');
  });

  it("creates a channel, returns the secret once, audits without it", async () => {
    const res = await POST(r("POST", { url: "https://hooks.example.com/x" }));
    const body = await res.json();
    expect(res.status).toBe(201);
    expect(body.secret).toMatch(/^whsec_[0-9a-f]{48}$/);
    expect(JSON.stringify(body.channel)).not.toContain(body.secret);
    const stored = db.notificationChannel.create.mock.calls[0][0].data;
    expect(JSON.stringify(stored)).not.toContain(body.secret);
    expect(stored.secretKeyId).toBe("k1");
    expect(JSON.stringify(db.auditLog.create.mock.calls[0][0])).not.toContain(body.secret);
    expect(db.auditLog.create.mock.calls[0][0].data.action).toBe("notify.channel.create");
  });

  it("is disabled when no key is configured, and refuses private or non-443 URLs", async () => {
    delete process.env.NOTIFY_SECRET_KEY;
    expect((await POST(r("POST", { url: "https://hooks.example.com/" }))).status).toBe(503);
    process.env.NOTIFY_SECRET_KEY = KEY;
    expect((await POST(r("POST", { url: "http://hooks.example.com/" }))).status).toBe(400);
    expect((await POST(r("POST", { url: "https://hooks.example.com:8443/" }))).status).toBe(400);
    expect((await POST(r("POST", { url: "https://127.0.0.1/" }))).status).toBe(400);
    expect(db.notificationChannel.create).not.toHaveBeenCalled();
  });

  it("caps channels per tenant and refuses another tenant's hunt", async () => {
    db.notificationChannel.count.mockResolvedValue(5);
    expect((await POST(r("POST", { url: "https://hooks.example.com/" }))).status).toBe(409);
    db.notificationChannel.count.mockResolvedValue(0);
    db.hunt.count.mockResolvedValue(0);
    const huntId = "0b7f3a52-1b0e-4a53-9f65-2f4d3c1e9a10";
    expect((await POST(r("POST", { url: "https://hooks.example.com/", huntIds: [huntId] }))).status).toBe(400);
  });

  it("rotate returns a new secret once; disable and enable are audited", async () => {
    const rot = await (await PATCH(r("PATCH", { action: "rotate_secret" }), ctx)).json();
    expect(rot.secret).toMatch(/^whsec_/);
    expect(JSON.stringify(db.auditLog.create.mock.calls[0][0])).not.toContain(rot.secret);
    await PATCH(r("PATCH", { action: "disable" }), ctx);
    await PATCH(r("PATCH", { action: "enable" }), ctx);
    expect(db.auditLog.create.mock.calls.map((c) => c[0].data.action)).toEqual([
      "notify.channel.rotate_secret", "notify.channel.disable", "notify.channel.enable",
    ]);
  });

  it("resend_failed requeues only this channel's failed rows and is audited", async () => {
    db.notification.updateMany.mockResolvedValue({ count: 2 });
    expect((await PATCH(r("PATCH", { action: "resend_failed" }), ctx)).status).toBe(200);
    const call = db.notification.updateMany.mock.calls[0][0];
    expect(call.where).toEqual({ channelId: "c1", failedAt: { not: null } });
    expect(call.data).toMatchObject({ failedAt: null, attempts: 0 });
    expect(db.auditLog.create.mock.calls[0][0].data.action).toBe("notify.channel.resend_failed");
  });

  it("looks a channel up inside the caller's tenant only", async () => {
    db.notificationChannel.findFirst.mockResolvedValue(null);
    expect((await PATCH(r("PATCH", { action: "disable" }), ctx)).status).toBe(404);
    expect(db.notificationChannel.findFirst.mock.calls[0][0].where).toEqual({ id: "c1", tenantId: "t1" });
  });
});
