import { describe, expect, it } from "vitest";
import { Prisma } from "@prisma/client";
import { HuntValidationError } from "@/lib/hunt";
import {
  caseConditions,
  decodeCursor,
  encodeCursor,
  parseCaseQuery,
  parseSearchRequest,
  searchFailure,
} from "@/lib/hunt-search";

const caseQuery = { kind: "cases", version: 1, lastHours: 48 };
const huntQuery = { version: 1, lastHours: 24 };

describe("parseCaseQuery", () => {
  it("accepts a window and every optional filter, and normalizes duplicates", () => {
    expect(
      parseCaseQuery({
        ...caseQuery,
        severities: ["high", "high", "critical"],
        statuses: ["open", "investigating"],
        techniques: ["T1059", "T1059", "T1003.001"],
        text: "  ransomware ",
      })
    ).toEqual({
      kind: "cases",
      version: 1,
      lastHours: 48,
      severities: ["high", "critical"],
      statuses: ["open", "investigating"],
      techniques: ["T1059", "T1003.001"],
      text: "ransomware",
    });
  });

  it("refuses what is not a case query, with a message that names the field", () => {
    const bad: [unknown, RegExp][] = [
      [null, /must be an object/],
      [{ ...caseQuery, kind: "detections" }, /kind/],
      [{ ...caseQuery, version: 2 }, /version/],
      [{ ...caseQuery, lastHours: 0 }, /lastHours/],
      [{ ...caseQuery, lastHours: 24 * 90 + 1 }, /lastHours/],
      [{ ...caseQuery, severities: ["urgent"] }, /not a severity/],
      [{ ...caseQuery, statuses: ["closed"] }, /not a case status/],
      [{ ...caseQuery, techniques: ["1059"] }, /not an ATT&CK technique/],
      [{ ...caseQuery, text: "ab" }, /query.text/],
      [{ ...caseQuery, agentIds: ["x"] }, /unknown query field "agentIds"/],
      [{ ...caseQuery, tenantId: "someone-else" }, /unknown query field "tenantId"/],
    ];
    for (const [input, message] of bad) {
      expect(() => parseCaseQuery(input), JSON.stringify(input)).toThrow(HuntValidationError);
      expect(() => parseCaseQuery(input)).toThrow(message);
    }
  });
});

describe("parseSearchRequest", () => {
  it("defaults to detections and validates the query as a saved hunt's", () => {
    expect(parseSearchRequest({ query: huntQuery })).toEqual({ source: "detections", query: huntQuery, cursor: undefined });
    expect(() => parseSearchRequest({ query: { ...huntQuery, lastHours: 0 } })).toThrow(/lastHours/);
  });

  it("takes a case query only for the cases source", () => {
    expect(parseSearchRequest({ source: "cases", query: caseQuery }).source).toBe("cases");
    expect(() => parseSearchRequest({ source: "cases", query: huntQuery })).toThrow(/kind/);
    expect(() => parseSearchRequest({ source: "detections", query: caseQuery })).toThrow(/unknown query field "kind"/);
  });

  it("refuses unknown fields, an unknown source and a cursor it did not make", () => {
    expect(() => parseSearchRequest(null)).toThrow(/body must be an object/);
    expect(() => parseSearchRequest({ query: huntQuery, tenantId: "x" })).toThrow(/unknown field "tenantId"/);
    expect(() => parseSearchRequest({ source: "events", query: huntQuery })).toThrow(/source must be/);
    expect(() => parseSearchRequest({ query: huntQuery, cursor: "not a cursor" })).toThrow(/cursor is not valid/);
    expect(() => parseSearchRequest({ query: huntQuery, cursor: 5 })).toThrow(/cursor must be a string/);
  });
});

describe("cursor", () => {
  const id = "3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b";

  it("round-trips a time and an id", () => {
    const at = new Date("2026-10-19T08:30:15.123Z");
    expect(decodeCursor(encodeCursor(at, id))).toEqual({ at, id });
  });

  it("refuses anything encodeCursor could not have produced", () => {
    const enc = (s: string) => Buffer.from(s, "utf8").toString("base64url");
    for (const bad of [
      "",
      "%%%",
      enc("2026-10-19T08:30:15.123Z"),
      enc(`2026-10-19T08:30:15.123Z|${id}|extra`),
      enc(`2026-10-19 08:30:15|${id}`),
      enc(`2026-10-19T08:30:15.123Z|'; DROP TABLE detections; --`),
      enc(`2026-13-45T99:99:99.123Z|${id}`),
    ]) {
      expect(() => decodeCursor(bad), bad).toThrow(HuntValidationError);
    }
  });
});

describe("caseConditions", () => {
  it("is always scoped to the tenant and the window, and binds every value", () => {
    const now = new Date("2026-10-19T12:00:00Z");
    const sql = Prisma.join(
      caseConditions(
        "tenant-1",
        parseCaseQuery({ ...caseQuery, severities: ["high"], statuses: ["open"], techniques: ["T1059"], text: "100%_sure" }),
        now
      ),
      " AND "
    );
    expect(sql.text).toContain("c.tenant_id = $1");
    expect(sql.text).toContain("c.created_at >= $2");
    expect(sql.text).toContain("d.tenant_id =");
    // Nothing the analyst typed is in the SQL text: it is all parameters.
    expect(sql.text).not.toContain("100%");
    expect(sql.text).not.toContain("T1059");
    expect(sql.values).toContain("tenant-1");
    expect(sql.values).toContain("%100\\%\\_sure%");
    expect(sql.values).toContain("T1059.%");
  });
});

describe("searchFailure", () => {
  it("maps a validation error to 400, a statement timeout to 504 and anything else to a generic 500", () => {
    expect(searchFailure(new HuntValidationError("bad"))).toEqual({ status: 400, message: "bad" });
    expect(searchFailure(new Error("canceling statement due to statement timeout")).status).toBe(504);
    const other = searchFailure(new Error('relation "detections" does not exist at host db:5432'));
    expect(other).toEqual({ status: 500, message: "Internal server error" });
  });
});
