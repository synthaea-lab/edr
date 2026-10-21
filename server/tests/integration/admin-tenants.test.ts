import { randomUUID } from "crypto";
import { NextRequest } from "next/server";
import { afterAll, afterEach, beforeEach, describe, expect, it } from "vitest";
import { POST } from "@/app/api/admin/tenants/route";
import { cleanDatabase, prisma } from "../helpers/db";

// #821: this is the route a human now calls instead of setting `active_organization_id`
// by hand (`server/README.md`). `x-user-id` is set directly here, the same thing
// `middleware.ts` does for every protected route once a session exists — this route
// itself has no session of its own to establish one from.

function request(body: unknown, userId: string | null): NextRequest {
  const headers = new Headers({ "Content-Type": "application/json" });
  if (userId) headers.set("x-user-id", userId);
  return new NextRequest("http://localhost/api/admin/tenants", {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
}

function rawBodyRequest(body: string, userId: string): NextRequest {
  const headers = new Headers({ "Content-Type": "application/json", "x-user-id": userId });
  return new NextRequest("http://localhost/api/admin/tenants", { method: "POST", headers, body });
}

describe("POST /api/admin/tenants (real database)", () => {
  const originalAllowList = process.env.PLATFORM_OPERATOR_USER_IDS;

  beforeEach(async () => {
    await cleanDatabase();
  });
  afterEach(() => {
    if (originalAllowList === undefined) {
      delete process.env.PLATFORM_OPERATOR_USER_IDS;
    } else {
      process.env.PLATFORM_OPERATOR_USER_IDS = originalAllowList;
    }
  });
  afterAll(async () => {
    await prisma.$disconnect();
  });

  it("creates a tenant and its paired organization, with the caller as owner", async () => {
    const admin = await prisma.user.create({
      data: { id: randomUUID(), email: "admin@example.com", name: "Admin" },
    });
    process.env.PLATFORM_OPERATOR_USER_IDS = admin.id;

    const res = await POST(request({ name: "Acme" }, admin.id));
    expect(res.status).toBe(201);
    const { tenant } = await res.json();
    expect(tenant.name).toBe("Acme");

    const org = await prisma.organization.findUnique({ where: { id: tenant.id } });
    expect(org).not.toBeNull();
    const member = await prisma.member.findFirst({ where: { organizationId: tenant.id } });
    expect(member?.userId).toBe(admin.id);
  });

  it("writes an audit log entry for the new tenant (review of #829)", async () => {
    const admin = await prisma.user.create({
      data: { id: randomUUID(), email: "admin2@example.com", name: "Admin" },
    });
    process.env.PLATFORM_OPERATOR_USER_IDS = admin.id;

    const res = await POST(request({ name: "Acme" }, admin.id));
    const { tenant } = await res.json();

    const entry = await prisma.auditLog.findFirst({ where: { tenantId: tenant.id } });
    expect(entry?.action).toBe("tenant.create");
    expect(entry?.userId).toBe(admin.id);
  });

  it("refuses a missing name", async () => {
    process.env.PLATFORM_OPERATOR_USER_IDS = "admin-user-1";
    const res = await POST(request({}, "admin-user-1"));
    expect(res.status).toBe(400);
  });

  it("refuses a body that is not valid JSON, with 400 not 500 (review of #829)", async () => {
    process.env.PLATFORM_OPERATOR_USER_IDS = "admin-user-1";
    const res = await POST(rawBodyRequest("{not json", "admin-user-1"));
    expect(res.status).toBe(400);
  });

  it("refuses a request with no session identity", async () => {
    process.env.PLATFORM_OPERATOR_USER_IDS = "admin-user-1";
    const res = await POST(request({ name: "Acme" }, null));
    expect(res.status).toBe(500);
  });

  it("refuses a self-registered user who is not on the operator allow-list (review of #829, blocking)", async () => {
    // Before this fix, any signed-up user could provision a tenant and become its
    // owner — self-service organization creation, which lib/auth.ts's
    // allowUserToCreateOrganization: false and the PR's own body both said was not
    // allowed, but this route never checked anything beyond "a session exists".
    const stranger = await prisma.user.create({
      data: { id: randomUUID(), email: "stranger@example.com", name: "Stranger" },
    });
    process.env.PLATFORM_OPERATOR_USER_IDS = "some-other-operator-id";

    const res = await POST(request({ name: "Acme" }, stranger.id));
    expect(res.status).toBe(403);

    const tenants = await prisma.tenant.findMany();
    expect(tenants).toHaveLength(0);
  });

  it("refuses everyone when the allow-list is unset, not left open (review of #829)", async () => {
    delete process.env.PLATFORM_OPERATOR_USER_IDS;
    const res = await POST(request({ name: "Acme" }, "anyone"));
    expect(res.status).toBe(403);
  });

  it("accepts any id on the comma-separated allow-list, not only the first", async () => {
    const admin = await prisma.user.create({
      data: { id: randomUUID(), email: "admin3@example.com", name: "Admin" },
    });
    process.env.PLATFORM_OPERATOR_USER_IDS = ` other-id , ${admin.id} ,third-id`;

    const res = await POST(request({ name: "Acme" }, admin.id));
    expect(res.status).toBe(201);
  });
});
