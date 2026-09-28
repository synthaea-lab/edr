import { describe, it, expect } from "vitest";
import { NextRequest } from "next/server";
import { buildIdentityHeaders, extractEnrollmentId, getTenantId } from "@/lib/tenant";

describe("tenant helpers", () => {
  describe("extractEnrollmentId", () => {
    it("should extract enrollment ID from certificate subject", () => {
      const subject = "CN=agent-test-001,O=synthaea";
      const result = extractEnrollmentId(subject);
      expect(result).toBe("agent-test-001");
    });

    it("should handle subject with multiple fields", () => {
      const subject =
        "C=US,ST=CA,L=SF,O=synthaea,OU=Agents,CN=agent-prod-123";
      const result = extractEnrollmentId(subject);
      expect(result).toBe("agent-prod-123");
    });

    it("should return empty string for invalid subject", () => {
      const subject = "O=synthaea";
      const result = extractEnrollmentId(subject);
      expect(result).toBe("");
    });

    it("should return empty string for empty subject", () => {
      const subject = "";
      const result = extractEnrollmentId(subject);
      expect(result).toBe("");
    });

    it("should handle subject with CN containing special characters", () => {
      const subject = "CN=agent-test-001.example.com,O=synthaea";
      const result = extractEnrollmentId(subject);
      expect(result).toBe("agent-test-001.example.com");
    });
  });

  describe("buildIdentityHeaders", () => {
    const spoofed = () =>
      new Headers({
        "x-tenant-id": "victim-tenant",
        "x-user-id": "victim-user",
        cookie: "session=abc",
      });

    it("drops a client-supplied tenant id when the session has no active organization", () => {
      // Regression (#468): the header was only overwritten when the session had
      // an organization, so the client's own value reached the route.
      for (const tenantId of [null, undefined, ""]) {
        const headers = buildIdentityHeaders(spoofed(), { tenantId, userId: "u1" });
        expect(headers.get("x-tenant-id")).toBeNull();
      }
    });

    it("replaces a client-supplied tenant id with the session's", () => {
      const headers = buildIdentityHeaders(spoofed(), { tenantId: "own-tenant", userId: "u1" });
      expect(headers.get("x-tenant-id")).toBe("own-tenant");
    });

    it("always sets the user id from the session", () => {
      const headers = buildIdentityHeaders(spoofed(), { tenantId: null, userId: "u1" });
      expect(headers.get("x-user-id")).toBe("u1");
    });

    it("matches identity headers case-insensitively", () => {
      const incoming = new Headers();
      incoming.set("X-Tenant-ID", "victim-tenant");
      const headers = buildIdentityHeaders(incoming, { tenantId: null, userId: "u1" });
      expect(headers.get("x-tenant-id")).toBeNull();
    });

    it("keeps the client's other headers and leaves the input untouched", () => {
      const incoming = spoofed();
      const headers = buildIdentityHeaders(incoming, { tenantId: "own-tenant", userId: "u1" });
      expect(headers.get("cookie")).toBe("session=abc");
      expect(incoming.get("x-tenant-id")).toBe("victim-tenant");
    });
  });

  describe("getTenantId after buildIdentityHeaders", () => {
    it("rejects a spoofed tenant id end to end when the session has no organization", async () => {
      const forwarded = buildIdentityHeaders(
        new Headers({ "x-tenant-id": "victim-tenant" }),
        { tenantId: null, userId: "u1" }
      );
      const req = new NextRequest("http://localhost/api/cases", { headers: forwarded });
      await expect(getTenantId(req)).rejects.toThrow("No tenant context");
    });
  });
});
