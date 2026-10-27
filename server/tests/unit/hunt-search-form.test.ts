import { describe, expect, it } from "vitest";
import { searchFormFromParams, searchHref, searchRequestFromParams } from "@/lib/hunt-search-form";

describe("searchRequestFromParams", () => {
  it("is none until the form has been submitted", () => {
    expect(searchRequestFromParams({})).toEqual({ kind: "none" });
    expect(searchRequestFromParams({ cursor: "abc" })).toEqual({ kind: "none" });
  });

  it("turns a submitted detections form into a hunt query, leaving empty fields out", () => {
    const asked = searchRequestFromParams({
      source: "detections",
      hours: "72",
      techniques: "T1059, T1003.001",
      severity: ["high", "critical"],
      hosts: "3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b",
      text: "",
    });
    expect(asked).toEqual({
      kind: "request",
      request: {
        source: "detections",
        query: {
          version: 1,
          lastHours: 72,
          techniques: ["T1059", "T1003.001"],
          severities: ["high", "critical"],
          agentIds: ["3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b"],
        },
        cursor: undefined,
      },
    });
  });

  it("turns a submitted cases form into a case query, with a single checked box as a single value", () => {
    const asked = searchRequestFromParams({ source: "cases", hours: "24", status: "open", severity: "high", text: "ransom" });
    expect(asked).toMatchObject({
      kind: "request",
      request: {
        source: "cases",
        query: { kind: "cases", version: 1, lastHours: 24, statuses: ["open"], severities: ["high"], text: "ransom" },
      },
    });
  });

  it("carries the cursor, and says why a form is not a query in the validator's words", () => {
    expect(searchRequestFromParams({ source: "cases", hours: "24", cursor: "abc" })).toMatchObject({
      request: { cursor: "abc" },
    });
    expect(searchRequestFromParams({ source: "detections", hours: "0" })).toEqual({
      kind: "invalid",
      error: "query.lastHours must be an integer from 1 to 2160",
    });
    expect(searchRequestFromParams({ source: "detections", hours: "soon" })).toMatchObject({ kind: "invalid" });
    expect(searchRequestFromParams({ source: "detections", hours: "24", techniques: "powershell" })).toMatchObject({
      kind: "invalid",
      error: expect.stringContaining("not an ATT&CK technique"),
    });
    expect(searchRequestFromParams({ source: "detections", hours: "24", text: "ab" })).toMatchObject({ kind: "invalid" });
  });
});

describe("searchFormFromParams", () => {
  it("refills the form from the query string, with defaults for a first visit", () => {
    expect(searchFormFromParams({})).toMatchObject({ source: "detections", hours: "24", severities: [], statuses: [] });
    expect(searchFormFromParams({ source: "cases", status: ["open", "resolved"], text: "x" })).toMatchObject({
      source: "cases",
      statuses: ["open", "resolved"],
      text: "x",
    });
    // Anything but "cases" is detections.
    expect(searchFormFromParams({ source: "events" }).source).toBe("detections");
  });
});

describe("searchHref", () => {
  it("keeps the search and swaps the cursor", () => {
    expect(searchHref({ source: "cases", hours: "24", status: ["open", "resolved"], cursor: "old" }, "next")).toBe(
      "?source=cases&hours=24&status=open&status=resolved&cursor=next"
    );
    expect(searchHref({ source: "cases", cursor: "old" }, null)).toBe("?source=cases");
  });
});
