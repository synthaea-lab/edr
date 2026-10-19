import { describe, expect, it } from "vitest";
import { EMPTY_HUNT_FORM, huntFormToBody, huntQueryIsValid, huntToFormValues, saveResponseMessage } from "@/lib/hunt-form";

const valid = { ...EMPTY_HUNT_FORM, name: "  Powershell spikes " };

describe("huntFormToBody", () => {
  it("leaves empty fields out of the query and sends null for no schedule and no description", () => {
    const result = huntFormToBody(valid);
    expect(result).toEqual({
      ok: true,
      body: {
        name: "  Powershell spikes ",
        description: null,
        query: { version: 1, lastHours: 168 },
        scheduleMinutes: null,
        active: true,
      },
    });
  });

  it("splits lists on commas, spaces and new lines, and upper-cases technique ids", () => {
    const result = huntFormToBody({
      ...valid,
      techniques: "t1059, T1003.001\nt1055",
      agentIds: "0b9e7a8e-1111-4222-8333-444455556666\n1b9e7a8e-1111-4222-8333-444455556666",
      severities: ["high", "critical"],
      text: "mimikatz",
      scheduleMinutes: "60",
      description: "weekly",
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.body.query).toEqual({
        version: 1,
        lastHours: 168,
        techniques: ["T1059", "T1003.001", "T1055"],
        severities: ["high", "critical"],
        agentIds: ["0b9e7a8e-1111-4222-8333-444455556666", "1b9e7a8e-1111-4222-8333-444455556666"],
        text: "mimikatz",
      });
      expect(result.body.scheduleMinutes).toBe(60);
      expect(result.body.description).toBe("weekly");
    }
  });

  it("says why a field is refused, with the API's own wording", () => {
    expect(huntFormToBody({ ...valid, name: "   " })).toEqual({ ok: false, error: "name must be 1 to 120 characters" });
    expect(huntFormToBody({ ...valid, lastHours: "7 days" })).toEqual({
      ok: false,
      error: "The window (hours) must be a whole number",
    });
    expect(huntFormToBody({ ...valid, lastHours: "0" })).toMatchObject({ ok: false });
    expect(huntFormToBody({ ...valid, techniques: "powershell" })).toMatchObject({
      ok: false,
      error: expect.stringContaining("not an ATT&CK technique id"),
    });
    expect(huntFormToBody({ ...valid, agentIds: "host-1" })).toMatchObject({
      ok: false,
      error: expect.stringContaining("not an agent id"),
    });
    expect(huntFormToBody({ ...valid, text: "ab" })).toMatchObject({ ok: false });
    expect(huntFormToBody({ ...valid, scheduleMinutes: "1" })).toMatchObject({ ok: false });
    expect(huntFormToBody({ ...valid, scheduleMinutes: "often" })).toEqual({
      ok: false,
      error: "The schedule (minutes) must be a whole number",
    });
  });
});

describe("huntToFormValues", () => {
  it("round-trips a stored hunt through the form", () => {
    const hunt = {
      name: "Credential access",
      description: "T1003 on servers",
      query: { version: 1, lastHours: 48, techniques: ["T1003"], severities: ["critical", "high"], text: "lsass" },
      scheduleMinutes: 15,
      active: false,
    };
    const values = huntToFormValues(hunt);
    expect(values.severities).toEqual(["high", "critical"]);
    expect(huntFormToBody(values)).toEqual({
      ok: true,
      body: {
        name: "Credential access",
        description: "T1003 on servers",
        query: { version: 1, lastHours: 48, techniques: ["T1003"], severities: ["high", "critical"], text: "lsass" },
        scheduleMinutes: 15,
        active: false,
      },
    });
  });

  it("opens a hunt whose stored query no longer parses with an empty query, so saving repairs it", () => {
    const values = huntToFormValues({
      name: "Old",
      description: null,
      query: { version: 0, sql: "select 1" },
      scheduleMinutes: null,
      active: true,
    });
    expect(values).toEqual({ ...EMPTY_HUNT_FORM, name: "Old" });
    expect(huntFormToBody(values).ok).toBe(true);
  });
});

describe("saveResponseMessage", () => {
  it("shows the API's message, or the status when it gave none", () => {
    expect(saveResponseMessage(400, { error: "query.text must be 3 to 256 characters" })).toBe(
      "query.text must be 3 to 256 characters"
    );
    expect(saveResponseMessage(500, {})).toBe("Request failed with status 500");
    expect(saveResponseMessage(502, null)).toBe("Request failed with status 502");
  });
});

describe("huntQueryIsValid", () => {
  it("is false for a stored query that no longer parses, which the form would replace with the default", () => {
    expect(huntQueryIsValid({ version: 1, lastHours: 24 })).toBe(true);
    expect(huntQueryIsValid({ version: 99, lastHours: 24 })).toBe(false);
    expect(huntQueryIsValid("not a query")).toBe(false);
    expect(huntQueryIsValid(null)).toBe(false);
  });
});
