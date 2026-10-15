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
