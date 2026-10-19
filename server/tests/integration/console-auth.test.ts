import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { auth } from "@/lib/auth";
import { cleanDatabase, createTestTenant, prisma } from "../helpers/db";

// Console authentication against the real database (#810). Every other test calls a handler
// with an `x-tenant-id` header or mocks `@/lib/auth`, so the session lookup the middleware
// depends on had never run: better-auth could not even initialize its database adapter.

/** The cookies a response sets, as the `Cookie` header a browser would send back. */
function cookieHeader(setCookie: string | null): string {
  return (setCookie ?? "")
    .split(/,(?=\s*[\w.-]+=)/)
    .map((c) => c.split(";")[0].trim())
    .filter(Boolean)
    .join("; ");
}

async function signUp(email: string) {
  const res = await auth.api.signUpEmail({
    body: { email, password: "console-test-password-1", name: "Console Test" },
    returnHeaders: true,
  });
  return { token: res.response.token, cookie: cookieHeader(res.headers.get("set-cookie")) };
}

describe("console authentication (real database)", () => {
  beforeEach(async () => {
    await cleanDatabase();
  });
  afterAll(async () => {
    await prisma.$disconnect();
  });

  it("signs a user up and reads the session back from the cookie it was given", async () => {
    const { cookie } = await signUp("sign-up@example.com");

    const session = await auth.api.getSession({ headers: new Headers({ cookie }) });

    expect(session?.user.email).toBe("sign-up@example.com");
    expect(session?.session.activeOrganizationId ?? null).toBeNull();
  });

  it("carries the active organization on the session: the middleware turns it into the tenant", async () => {
    const tenant = await createTestTenant();
    const { token, cookie } = await signUp("tenant@example.com");
    await prisma.session.update({
      where: { token: token! },
      data: { activeOrganizationId: tenant.id },
    });

    const session = await auth.api.getSession({ headers: new Headers({ cookie }) });

    expect(session?.session.activeOrganizationId).toBe(tenant.id);
  });

  it("a provisioned tenant's owner can make it their session's active organization through better-auth's own API", async () => {
    // #821: unlike the test above (a raw `prisma.session.update`, which never checks
    // `Organization`/`Member` at all), `setActiveOrganization` does — it is better-auth's own
    // real code path, the one a signed-in user's own console session actually calls. It
    // refused every id before a tenant's provisioning also made the paired `Organization` and
    // `Member` rows a real sign-in needs.
    const { cookie } = await signUp("owner@example.com");
    const signedUp = await auth.api.getSession({ headers: new Headers({ cookie }) });
    const tenant = await createTestTenant(undefined, { userId: signedUp!.user.id });

    await auth.api.setActiveOrganization({
      headers: new Headers({ cookie }),
      body: { organizationId: tenant.id },
    });

    const session = await auth.api.getSession({ headers: new Headers({ cookie }) });
    expect(session?.session.activeOrganizationId).toBe(tenant.id);
  });

  it("refuses to delete a tenant's paired organization, rather than orphan the tenant (review of #829)", async () => {
    // better-auth's own delete API has no notion of the Tenant/Organization pairing
    // (#821) and would otherwise remove the Organization/Member rows while leaving
    // the Tenant and all its data behind, reachable by no one — disableOrganizationDeletion
    // (lib/auth.ts) refuses the call outright instead.
    const { cookie } = await signUp("owner-delete@example.com");
    const signedUp = await auth.api.getSession({ headers: new Headers({ cookie }) });
    const tenant = await createTestTenant(undefined, { userId: signedUp!.user.id });
    await auth.api.setActiveOrganization({
      headers: new Headers({ cookie }),
      body: { organizationId: tenant.id },
    });

    await expect(
      auth.api.deleteOrganization({
        headers: new Headers({ cookie }),
        body: { organizationId: tenant.id },
      })
    ).rejects.toThrow();

    expect(await prisma.organization.findUnique({ where: { id: tenant.id } })).not.toBeNull();
    expect(await prisma.tenant.findUnique({ where: { id: tenant.id } })).not.toBeNull();
  });

  it("signs in with the right password and refuses the wrong one", async () => {
    await signUp("sign-in@example.com");

    const ok = await auth.api.signInEmail({
      body: { email: "sign-in@example.com", password: "console-test-password-1" },
    });
    expect(ok.user.email).toBe("sign-in@example.com");
    await expect(
      auth.api.signInEmail({ body: { email: "sign-in@example.com", password: "wrong-password" } })
    ).rejects.toThrow();
  });

  it("returns no session without a cookie, or with a forged one", async () => {
    expect(await auth.api.getSession({ headers: new Headers() })).toBeNull();
    const forged = new Headers({ cookie: "better-auth.session_token=forged.value" });
    expect(await auth.api.getSession({ headers: forged })).toBeNull();
  });
});
