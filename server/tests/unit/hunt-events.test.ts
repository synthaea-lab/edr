import { describe, expect, it } from "vitest";
import { HuntValidationError } from "@/lib/hunt";
import { MAX_EVENT_TYPES, MAX_EVENT_WINDOW_DAYS, MAX_FILTER_LENGTH, eventWindow, parseEventQuery } from "@/lib/hunt-events";

const base = { kind: "events", version: 1, lastDays: 7 };
const HASH = "a".repeat(64);

describe("parseEventQuery", () => {
  it("accepts a window alone, and with types and filters, normalizing duplicates and the hash's case", () => {
    expect(parseEventQuery(base)).toEqual(base);
    expect(
      parseEventQuery({
        ...base,
        types: ["exec", "connect", "exec"],
        where: { imagePath: "/usr/bin/curl", sha256: HASH.toUpperCase(), comm: "curl" },
      })
    ).toEqual({
      ...base,
      types: ["exec", "connect"],
      where: { imagePath: "/usr/bin/curl", sha256: HASH, comm: "curl" },
    });
  });

  it("drops an empty where object", () => {
    expect(parseEventQuery({ ...base, where: {} })).toEqual(base);
  });

  it("refuses what is not an event query, with a message that names the field", () => {
    const bad: [unknown, RegExp][] = [
      [null, /must be an object/],
      [[], /must be an object/],
      [{ ...base, kind: "cases" }, /kind/],
      [{ ...base, version: 2 }, /version/],
      [{ ...base, lastDays: 0 }, /lastDays/],
      [{ ...base, lastDays: MAX_EVENT_WINDOW_DAYS + 1 }, /lastDays/],
      [{ ...base, lastDays: 1.5 }, /lastDays/],
      [{ ...base, lastDays: "7" }, /lastDays/],
      [{ kind: "events", version: 1 }, /lastDays/],
      [{ ...base, types: [] }, /types/],
      [{ ...base, types: Array.from({ length: MAX_EVENT_TYPES + 1 }, (_, i) => `t${i}`) }, /types/],
      [{ ...base, types: ["../etc"] }, /not an event type/],
      [{ ...base, types: ["Exec"] }, /not an event type/],
      [{ ...base, types: [7] }, /only strings/],
      [{ ...base, where: [] }, /where must be an object/],
      [{ ...base, where: { path: "" } }, /where\.path/],
      [{ ...base, where: { path: 7 } }, /where\.path/],
      [{ ...base, where: { path: "x".repeat(MAX_FILTER_LENGTH + 1) } }, /where\.path/],
      [{ ...base, where: { event: "x" } }, /unknown filter "event"/],
      [{ ...base, where: { sha256: "abc" } }, /sha256/],
      [{ ...base, text: "powershell" }, /unknown query field "text"/],
      [{ ...base, tenantId: "someone-else" }, /unknown query field "tenantId"/],
      [{ ...base, from: "2026-01-01" }, /unknown query field "from"/],
    ];
    for (const [input, message] of bad) {
      expect(() => parseEventQuery(input), JSON.stringify(input)).toThrow(HuntValidationError);
      expect(() => parseEventQuery(input), JSON.stringify(input)).toThrow(message);
    }
  });
});

describe("eventWindow", () => {
  const q = (lastDays: number) => parseEventQuery({ ...base, lastDays });
  it("is today alone for one day, and counts back whole UTC days including today", () => {
    const now = new Date("2026-10-30T23:59:59.999Z");
    expect(eventWindow(q(1), now)).toEqual({ from: "2026-10-30", to: "2026-10-30" });
    expect(eventWindow(q(3), now)).toEqual({ from: "2026-10-28", to: "2026-10-30" });
    expect(eventWindow(q(1), new Date("2026-10-31T00:00:00.000Z"))).toEqual({ from: "2026-10-31", to: "2026-10-31" });
  });

  it("crosses a month and a year, and fits the lake's longest range", () => {
    expect(eventWindow(q(3), new Date("2027-01-01T10:00:00Z"))).toEqual({ from: "2026-12-30", to: "2027-01-01" });
    const { from, to } = eventWindow(q(MAX_EVENT_WINDOW_DAYS), new Date("2026-10-30T00:00:00Z"));
    expect(from).toBe("2026-08-02");
    expect(to).toBe("2026-10-30");
  });
});
