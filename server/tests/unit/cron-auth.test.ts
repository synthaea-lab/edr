import { describe, it, expect } from "vitest";
import { NextRequest } from "next/server";
import { checkCronAuth, verifyCronRequest } from "@/lib/cron-auth";

describe("checkCronAuth", () => {
  it("accepts the exact bearer token", () => {
    expect(checkCronAuth("Bearer s3cret", "s3cret")).toBe("ok");
  });

  it("rejects a wrong or missing token", () => {
    expect(checkCronAuth("Bearer wrong!", "s3cret")).toBe("unauthorized");
    expect(checkCronAuth("Bearer s3cre", "s3cret")).toBe("unauthorized");
    expect(checkCronAuth("s3cret", "s3cret")).toBe("unauthorized");
    expect(checkCronAuth(null, "s3cret")).toBe("unauthorized");
  });

  it("fails closed when the secret is unset or empty", () => {
    // The pre-fix check compared against `Bearer ${undefined}`, so this
    // exact header was accepted whenever CRON_SECRET was missing.
    expect(checkCronAuth("Bearer undefined", undefined)).toBe("unconfigured");
    expect(checkCronAuth("Bearer ", "")).toBe("unconfigured");
    expect(checkCronAuth(null, undefined)).toBe("unconfigured");
  });

  it("handles multi-byte headers without throwing", () => {
    expect(checkCronAuth("Bearer é", "e")).toBe("unauthorized");
  });
});

describe("verifyCronRequest", () => {
  const request = (auth?: string) =>
    new NextRequest("http://localhost/api/cron/detect-silent-agents", {
      headers: auth ? { Authorization: auth } : {},
    });

  it("returns null for an authorized call", async () => {
    expect(await verifyCronRequest(request(`Bearer ${process.env.CRON_SECRET}`))).toBeNull();
  });

  it("returns 401 for a bad token", async () => {
    expect((await verifyCronRequest(request("Bearer nope")))?.status).toBe(401);
  });

  it("returns 500 and rejects 'Bearer undefined' when CRON_SECRET is unset", async () => {
    const saved = process.env.CRON_SECRET;
    delete process.env.CRON_SECRET;
    try {
      expect((await verifyCronRequest(request("Bearer undefined")))?.status).toBe(500);
    } finally {
      process.env.CRON_SECRET = saved;
    }
  });
});
