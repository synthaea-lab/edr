import { describe, it, expect } from "vitest";
import { projectEvidenceItem } from "@/assistant/evidence-graph";

const baseDetection = {
  id: "det-1",
  timestamp: new Date("2026-09-25T10:00:00Z"),
  technique: "T1059.001",
  severity: "high",
};

describe("projectEvidenceItem", () => {
  it("includes only allowlisted event/meta fields in the evidence summary", () => {
    const item = projectEvidenceItem({
      ...baseDetection,
      event: {
        process_name: "powershell.exe",
        parent_process_name: "explorer.exe",
        cmdline: "powershell -enc AAA",
        raw_bytes: "should never appear",
        env_dump: { SECRET: "value" },
      },
      meta: {
        rule_id: "beacon-001",
        model_id: "cmdline-iforest-linux",
        internal_debug: "should never appear",
      },
    });

    expect(item).toEqual({
      detectionId: "det-1",
      timestamp: "2026-09-25T10:00:00.000Z",
      technique: "T1059.001",
      severity: "high",
      processName: "powershell.exe",
      parentProcessName: "explorer.exe",
      cmdline: "powershell -enc AAA",
      ruleId: "beacon-001",
      modelId: "cmdline-iforest-linux",
      attributions: undefined,
    });
  });

  it("omits raw event/meta fields not on the allowlist", () => {
    const item = projectEvidenceItem({
      ...baseDetection,
      event: { raw_bytes: "leak", socket_payload: "leak" },
      meta: { internal_debug: "leak" },
    });

    expect(JSON.stringify(item)).not.toContain("leak");
  });

  it("truncates long cmdline values", () => {
    const longCmdline = "a".repeat(500);

    const item = projectEvidenceItem({
      ...baseDetection,
      event: { cmdline: longCmdline },
      meta: {},
    });

    expect(item.cmdline?.length).toBeLessThan(longCmdline.length);
    expect(item.cmdline).toMatch(/\[truncated\]$/);
  });

  it("tolerates missing event/meta fields", () => {
    const item = projectEvidenceItem({ ...baseDetection, event: {}, meta: {} });

    expect(item.processName).toBeUndefined();
    expect(item.attributions).toBeUndefined();
  });

  it("carries well-formed attributions through", () => {
    const item = projectEvidenceItem({
      ...baseDetection,
      event: {},
      meta: {
        attributions: [
          { feature: "entropy_arg3", value: 4.2, contribution: 0.31 },
          { feature: "not_an_attribution" }, // dropped: missing value/contribution
        ],
      },
    });

    expect(item.attributions).toEqual([
      { feature: "entropy_arg3", value: 4.2, contribution: 0.31 },
    ]);
  });
});
