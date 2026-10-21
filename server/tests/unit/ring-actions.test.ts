import { describe, expect, it } from "vitest";
import { availableActions, confirmation, confirmationMatches, NON_ADMIN_NOTE } from "@/lib/ring-actions";
import { endedSession } from "@/lib/session-redirect";

describe("availableActions", () => {
  it("offers halt and rollback on a serving ring, rollback only on a halted one, nothing otherwise", () => {
    expect(availableActions("serving", true)).toEqual(["halt", "rollback"]);
    expect(availableActions("halted", true)).toEqual(["rollback"]);
    expect(availableActions("rolled_back", true)).toEqual([]);
    expect(availableActions("no_release", true)).toEqual([]);
  });
  it("does not offer a rollback that has no earlier release to go to: it could only answer 404", () => {
    expect(availableActions("serving", false)).toEqual(["halt"]);
    expect(availableActions("halted", false)).toEqual([]);
  });
  it("never offers a release: who may publish is undecided (#898)", () => {
    for (const s of ["serving", "halted", "rolled_back", "no_release"] as const) {
      expect(availableActions(s, true)).not.toContain("release" as never);
    }
  });
});

describe("confirmation", () => {
  it("a halt says what stops, that applied content stays, and that it is audited; it asks for no typing", () => {
    const c = confirmation("halt", "prod", 7);
    expect(c.title).toBe("Halt prod");
    expect(c.body).toContain("stop being offered content (now v7)");
    expect(c.body).toContain("stays applied");
    expect(c.body).toContain("audit log");
    expect(c.mustType).toBeNull();
  });

  it("a rollback says it does not reach agents that already applied the release, names the corrective release, and asks for the ring's name", () => {
    const c = confirmation("rollback", "canary_0", null);
    expect(c.body).toContain("does not reach an agent that has already applied");
    expect(c.body).toContain("stays on it");
    expect(c.body).toContain("corrective release");
    expect(c.body).toContain("audit log");
    expect(c.mustType).toBe("canary_0");
    expect(c.confirmLabel).toBe("Roll back canary_0");
  });

  it("a halt of a ring with no known served version does not invent one", () => {
    expect(confirmation("halt", "prod", null).body).not.toMatch(/\(now v/);
  });
});

describe("confirmationMatches", () => {
  it("needs the ring's name when one is required, ignoring case and surrounding spaces", () => {
    expect(confirmationMatches("prod", "prod")).toBe(true);
    expect(confirmationMatches("  PROD ", "prod")).toBe(true);
    expect(confirmationMatches("prd", "prod")).toBe(false);
    expect(confirmationMatches("", "prod")).toBe(false);
    expect(confirmationMatches("", null)).toBe(true);
  });
});

describe("endedSession and the non-admin note", () => {
  it("takes a redirect to the sign-in page for an ended session, and nothing else", () => {
    expect(endedSession({ redirected: true, url: "https://c.example/login" })).toBe(true);
    expect(endedSession({ redirected: true, url: "/login/?next=%2Fconsole" })).toBe(true);
    expect(endedSession({ redirected: false, url: "https://c.example/login" })).toBe(false);
    expect(endedSession({ redirected: true, url: "https://c.example/api/content/halt" })).toBe(false);
  });
  it("tells a member who may do it", () => {
    expect(NON_ADMIN_NOTE).toMatch(/owner or admin/);
  });
});
