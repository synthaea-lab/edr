import { randomUUID } from "crypto";
import { NextRequest } from "next/server";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
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

describe("POST /api/admin/tenants (real database)", () => {
  beforeEach(async () => {
    await cleanDatabase();
  });
  afterAll(async () => {
    await prisma.$disconnect();
  });

  it("creates a tenant and its paired organization, with the caller as owner", async () => {
    const admin = await prisma.user.create({
      data: { id: randomUUID(), email: "admin@example.com", name: "Admin" },
    });

    const res = await POST(request({ name: "Acme" }, admin.id));
    expect(res.status).toBe(201);
    const { tenant } = await res.json();
    expect(tenant.name).toBe("Acme");

    const org = await prisma.organization.findUnique({ where: { id: tenant.id } });
    expect(org).not.toBeNull();
    const member = await prisma.member.findFirst({ where: { organizationId: tenant.id } });
    expect(member?.userId).toBe(admin.id);
  });

  it("refuses a missing name", async () => {
    const res = await POST(request({}, "admin-user-1"));
    expect(res.status).toBe(400);
  });

  it("refuses a request with no session identity", async () => {
    const res = await POST(request({ name: "Acme" }, null));
    expect(res.status).toBe(500);
  });
});
