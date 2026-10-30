import { describe, it, expect } from "vitest";
import {
  baseTechniques,
  isRelatedTechnique,
  outranksSeverity,
  withinTimeWindow,
} from "@/lib/case-grouping";

describe("isRelatedTechnique", () => {
  it("groups detections with the exact same technique", () => {
    expect(isRelatedTechnique("T1059.001", "T1059.001")).toBe(true);
  });

  it("groups sub-techniques under the same base technique", () => {
    expect(isRelatedTechnique("T1059.001", "T1059.003")).toBe(true);
    expect(isRelatedTechnique("T1059", "T1059.001")).toBe(true);
  });

  it("does not group unrelated techniques", () => {
    expect(isRelatedTechnique("T1059.001", "T1105")).toBe(false);
  });

  it("groups a compound technique with each single technique it names", () => {
    expect(isRelatedTechnique("T1566.001/T1204.002", "T1204.002")).toBe(true);
    expect(isRelatedTechnique("T1204.002", "T1566.001/T1204.002")).toBe(true);
    expect(isRelatedTechnique("T1566.001/T1204.002", "T1566.001")).toBe(true);
    expect(isRelatedTechnique("T1560/T1041", "T1041")).toBe(true);
    expect(isRelatedTechnique("T1204/T1059", "T1059.004")).toBe(true);
  });

  it("groups two compound techniques that share one base technique", () => {
    expect(isRelatedTechnique("T1566.001/T1204.002", "T1204/T1059")).toBe(true);
  });

  it("does not group compound techniques that share no base technique", () => {
    expect(isRelatedTechnique("T1566.001/T1204.002", "T1560/T1041")).toBe(false);
    expect(isRelatedTechnique("T1560/T1041", "T1105")).toBe(false);
  });
});

describe("baseTechniques", () => {
  it("splits compound ids before dropping sub-techniques", () => {
    expect(baseTechniques("T1566.001/T1204.002")).toEqual(new Set(["T1566", "T1204"]));
    expect(baseTechniques("T1059.001")).toEqual(new Set(["T1059"]));
    expect(baseTechniques("T1105")).toEqual(new Set(["T1105"]));
  });
});

describe("withinTimeWindow", () => {
  const t0 = new Date("2026-09-25T10:00:00Z");

  it("does not group detections outside the time window", () => {
    const outside = new Date(t0.getTime() + 31 * 60 * 1000);
    expect(withinTimeWindow(t0, outside)).toBe(false);
  });

  it("groups detections inside the time window, order-independent", () => {
    const inside = new Date(t0.getTime() + 29 * 60 * 1000);
    expect(withinTimeWindow(t0, inside)).toBe(true);
    expect(withinTimeWindow(inside, t0)).toBe(true);
  });
});

describe("outranksSeverity", () => {
  it("ranks critical above high above medium above low", () => {
    expect(outranksSeverity("critical", "high")).toBe(true);
    expect(outranksSeverity("high", "medium")).toBe(true);
    expect(outranksSeverity("medium", "low")).toBe(true);
  });

  it("does not outrank an equal or higher severity", () => {
    expect(outranksSeverity("medium", "high")).toBe(false);
    expect(outranksSeverity("high", "high")).toBe(false);
  });
});
