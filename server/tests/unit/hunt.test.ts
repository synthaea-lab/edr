import { describe, expect, it } from "vitest";
import {
  HuntValidationError,
  MAX_TEXT_LENGTH,
  MAX_WINDOW_HOURS,
  escapeLike,
  huntConditions,
  parseHuntQuery,
} from "@/lib/hunt";
import { parseHuntInput, sameQuery } from "@/lib/hunt-input";

const AGENT = "123e4567-e89b-12d3-a456-426614174000";
const base = { version: 1, lastHours: 24 };

describe("parseHuntQuery", () => {
  it("accepts a minimal query and a full one", () => {
    expect(parseHuntQuery(base)).toEqual(base);
    const full = parseHuntQuery({
      ...base,
      techniques: ["T1059", "T1059.001", "T1059"],
      severities: ["high", "critical"],
      agentIds: [AGENT],
      text: "  curl  ",
    });
    expect(full.techniques).toEqual(["T1059", "T1059.001"]);
    expect(full.text).toBe("curl");
  });

  it.each([
    ["not an object", "x"],
    ["an array", []],
    ["wrong version", { ...base, version: 2 }],
    ["no window", { version: 1 }],
    ["window too long", { ...base, lastHours: MAX_WINDOW_HOURS + 1 }],
    ["fractional window", { ...base, lastHours: 1.5 }],
    ["unknown field (a column or a table name)", { ...base, table: "users" }],
    ["bad technique", { ...base, techniques: ["T1059; DROP TABLE detections"] }],
    ["empty technique list", { ...base, techniques: [] }],
    ["bad severity", { ...base, severities: ["urgent"] }],
    ["bad agent id", { ...base, agentIds: ["1 OR 1=1"] }],
    ["text too short", { ...base, text: "ab" }],
    ["text too long", { ...base, text: "x".repeat(MAX_TEXT_LENGTH + 1) }],
    ["text not a string", { ...base, text: 5 }],
  ])("rejects %s", (_name, input) => {
    expect(() => parseHuntQuery(input)).toThrow(HuntValidationError);
  });
});

describe("huntConditions", () => {
  const now = new Date("2026-10-06T12:00:00Z");

  it("always scopes to the tenant and the window, and binds every value as a parameter", () => {
    const [tenant, window, ...rest] = huntConditions("tenant-1", { version: 1, lastHours: 2 }, now);
    expect(rest).toEqual([]);
    expect(tenant.values).toEqual(["tenant-1"]);
    expect(window.values).toEqual([new Date("2026-10-06T10:00:00Z")]);
  });

  it("never puts query text into the SQL itself", () => {
    const hostile = "'; DROP TABLE detections; --";
    const conditions = huntConditions("t", parseHuntQuery({ ...base, text: hostile }), now);
    for (const c of conditions) expect(c.sql).not.toContain("DROP");
    expect(conditions[2].values[0]).toContain("DROP");
  });

  it("matches a technique and its sub-techniques, or only a sub-technique", () => {
    const [, , parent] = huntConditions("t", parseHuntQuery({ ...base, techniques: ["T1059"] }), now);
    expect(parent.values).toEqual(["T1059", "T1059.%"]);
    const [, , exact] = huntConditions("t", parseHuntQuery({ ...base, techniques: ["T1059.001"] }), now);
    expect(exact.values).toEqual(["T1059.001"]);
  });
});

describe("escapeLike", () => {
  it("makes %, _ and the escape character literal", () => {
    expect(escapeLike("100%_done\\")).toBe("100\\%\\_done\\\\");
  });
});

describe("parseHuntInput", () => {
  const ok = { name: " Beaconing ", query: base };

  it("requires a name and a query on create but not on update", () => {
    expect(parseHuntInput(ok, false).name).toBe("Beaconing");
    expect(() => parseHuntInput({ query: base }, false)).toThrow(HuntValidationError);
    expect(() => parseHuntInput({ name: "x" }, false)).toThrow(HuntValidationError);
    expect(parseHuntInput({ active: false }, true)).toEqual({ active: false });
  });

  it("bounds the schedule and lets null clear it", () => {
    expect(parseHuntInput({ ...ok, scheduleMinutes: 60 }, false).scheduleMinutes).toBe(60);
    expect(parseHuntInput({ scheduleMinutes: null }, true).scheduleMinutes).toBeNull();
    expect(() => parseHuntInput({ ...ok, scheduleMinutes: 1 }, false)).toThrow(HuntValidationError);
    expect(() => parseHuntInput({ ...ok, scheduleMinutes: 99999 }, false)).toThrow(HuntValidationError);
  });

  it("refuses fields it does not know", () => {
    expect(() => parseHuntInput({ ...ok, tenantId: "someone-else" }, false)).toThrow(HuntValidationError);
  });
});

describe("sameQuery", () => {
  it("ignores the order of lists", () => {
    const a = parseHuntQuery({ ...base, techniques: ["T1059", "T1105"] });
    const b = parseHuntQuery({ ...base, techniques: ["T1105", "T1059"] });
    expect(sameQuery(a, b)).toBe(true);
    expect(sameQuery(a, parseHuntQuery({ ...base, lastHours: 25, techniques: ["T1059", "T1105"] }))).toBe(false);
  });
});
