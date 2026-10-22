import { describe, expect, it } from "vitest";
import { describeEntity, formatWhen, severityStyle, STATUS_LABEL } from "@/lib/fleet-case-view";

const SHA = "72c31946".padEnd(64, "0");

describe("describeEntity", () => {
  it("shows a hash as its first 12 characters and keeps the whole value for a tooltip", () => {
    expect(describeEntity({ kind: "sha256", key: SHA })).toEqual({
      label: "file 72c319460000…",
      title: SHA,
    });
  });

  it("shows an identity as the account", () => {
    expect(describeEntity({ kind: "identity", key: "alice" })).toEqual({ label: "account alice", title: "alice" });
  });

  it("does not trust a kind it does not know: the key alone, never as markup", () => {
    expect(describeEntity({ kind: "ip", key: "10.0.0.1" })).toEqual({ label: "ip 10.0.0.1", title: "10.0.0.1" });
  });
});

describe("severityStyle", () => {
  it("gives each known severity its own style and an unknown one the neutral style", () => {
    const known = ["low", "medium", "high", "critical"].map(severityStyle);
    expect(new Set(known).size).toBe(4);
    expect(severityStyle("weird")).toBe(severityStyle("something-else"));
    expect(known).not.toContain(severityStyle("weird"));
  });
});

describe("formatWhen", () => {
  it("is a stable UTC string, whatever the machine's locale", () => {
    expect(formatWhen(new Date("2026-10-20T14:05:09.123Z"))).toBe("2026-10-20 14:05 UTC");
  });
});

describe("STATUS_LABEL", () => {
  it("names the four statuses of a fleet case", () => {
    expect(Object.keys(STATUS_LABEL).sort()).toEqual(["false_positive", "investigating", "open", "resolved"]);
  });
});
