import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { config, middleware } from "@/middleware";

// vi.mock is hoisted above the imports, so the mock fn must be hoisted with it.
const { getSession } = vi.hoisted(() => ({ getSession: vi.fn() }));
vi.mock("@/lib/auth", () => ({ auth: { api: { getSession } } }));

/**
 * The request headers `NextResponse.next({ request: { headers } })` forwards
 * to the route: Next encodes each one as `x-middleware-request-<name>`.
 */
function forwarded(res: Response, name: string): string | null {
  return res.headers.get(`x-middleware-request-${name}`);
}

/**
 * Names of the request headers the route will see, or `null` when the
 * middleware passed the client's request through unmodified. A bare
 * `NextResponse.next()` forwards the original headers without listing them,
 * so a "header absent" check alone would pass vacuously on exactly the bug
 * under test.
 */
function forwardedNames(res: Response): string[] | null {
  const list = res.headers.get("x-middleware-override-headers");
  return list === null ? null : list.split(",").map((h) => h.trim().toLowerCase());
}

function spoofedRequest(path: string): NextRequest {
  return new NextRequest(`http://localhost${path}`, {
    headers: { "x-tenant-id": "victim-tenant", "x-user-id": "victim-user" },
  });
}

describe("middleware identity headers", () => {
  beforeEach(() => {
    getSession.mockReset();
  });

  it("strips client identity headers on public routes too", async () => {
    // Regression (#470 review): the public branch returned NextResponse.next()
    // with the client's headers untouched, so a public route calling
    // getTenantId would have trusted a client-chosen tenant.
    for (const path of ["/api/ingest/events", "/api/auth/session", "/api/health"]) {
      const res = await middleware(spoofedRequest(path));
      const names = forwardedNames(res);
      expect(names, `${path}: request passed through unmodified`).not.toBeNull();
      expect(names, path).not.toContain("x-tenant-id");
      expect(names, path).not.toContain("x-user-id");
    }
    expect(getSession).not.toHaveBeenCalled();
  });

  it("injects the session identity on protected routes", async () => {
    getSession.mockResolvedValue({
      session: { activeOrganizationId: "own-tenant" },
      user: { id: "u1" },
    });
    const res = await middleware(spoofedRequest("/api/cases"));
    expect(forwarded(res, "x-tenant-id")).toBe("own-tenant");
    expect(forwarded(res, "x-user-id")).toBe("u1");
  });

  it("forwards no tenant for a session without an active organization", async () => {
    getSession.mockResolvedValue({
      session: { activeOrganizationId: null },
      user: { id: "u1" },
    });
    const res = await middleware(spoofedRequest("/api/cases"));
    const names = forwardedNames(res);
    expect(names).not.toBeNull();
    expect(names).not.toContain("x-tenant-id");
    expect(forwarded(res, "x-user-id")).toBe("u1");
  });

  it("runs on every API route, public ones included", () => {
    // The old matcher excluded ingest/auth/health, so the public branch never
    // ran for them and nothing stripped their headers.
    expect(config.matcher).toContain("/api/:path*");
  });
});
