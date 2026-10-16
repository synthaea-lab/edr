import { randomUUID } from "crypto";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { provisionTenant } from "@/lib/tenant-provisioning";
import { cleanDatabase, createTestTenant, prisma } from "../helpers/db";

// #821: a Tenant with no matching Organization/Member is exactly the state "set
// active_organization_id by hand" used to leave behind. These assert the pair (and the
// owner) actually exists, against a real database — `console-auth.test.ts` separately
// proves better-auth's own API accepts the result.

describe("tenant provisioning (real database)", () => {
  beforeEach(async () => {
    await cleanDatabase();
  });
  afterAll(async () => {
    await prisma.$disconnect();
  });

  it("creates a tenant and an organization sharing one id", async () => {
    const tenant = await provisionTenant(prisma, "Acme");

    const org = await prisma.organization.findUnique({ where: { id: tenant.id } });
    expect(org).not.toBeNull();
    expect(org?.name).toBe("Acme");
  });

  it("adds the given owner as a member of the organization", async () => {
    const user = await prisma.user.create({
      data: { id: randomUUID(), email: "owner@example.com", name: "Owner", emailVerified: true },
    });

    const tenant = await provisionTenant(prisma, "Acme", { userId: user.id });

    const member = await prisma.member.findFirst({ where: { organizationId: tenant.id } });
    expect(member?.userId).toBe(user.id);
    expect(member?.role).toBe("owner");
  });

  it("creates no member when no owner is given", async () => {
    const tenant = await provisionTenant(prisma, "Acme");

    const members = await prisma.member.findMany({ where: { organizationId: tenant.id } });
    expect(members).toHaveLength(0);
  });

  it("gives two tenants of the same name distinct organization slugs", async () => {
    const first = await provisionTenant(prisma, "Acme");
    const second = await provisionTenant(prisma, "Acme");

    const [firstOrg, secondOrg] = await Promise.all([
      prisma.organization.findUniqueOrThrow({ where: { id: first.id } }),
      prisma.organization.findUniqueOrThrow({ where: { id: second.id } }),
    ]);
    expect(firstOrg.slug).not.toBe(secondOrg.slug);
  });

  it("createTestTenant (the test helper) goes through the same pairing", async () => {
    const tenant = await createTestTenant("Helper Tenant");

    const org = await prisma.organization.findUnique({ where: { id: tenant.id } });
    expect(org).not.toBeNull();
  });

  it("rolls back the tenant and organization when the member write fails (review of #829)", async () => {
    // A non-existent owner userId fails the Member→User foreign key. Without the
    // $transaction wrapping all three writes, this would leave a Tenant and an
    // Organization behind with no member able to make it their active session —
    // exactly the orphaned state #821 exists to stop happening by hand.
    await expect(
      provisionTenant(prisma, "Acme", { userId: randomUUID() })
    ).rejects.toThrow();

    expect(await prisma.tenant.count()).toBe(0);
    expect(await prisma.organization.count()).toBe(0);
  });
});
